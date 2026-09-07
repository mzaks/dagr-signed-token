# dagr-signed-token — Mojo example (see ../../CONTRACT.md).
#
# Codec is the generated gen/mojo modules; crypto is native Mojo in the sibling `crypto`
# module (SHA-256 on the target's own hardware intrinsics + a streaming HMAC); native file
# I/O — zero deps. Builds on macOS-arm64 and Linux-x86_64.
#
#   mojo run -I gen/mojo main.mojo             → showcase
#   mojo run -I gen/mojo main.mojo emit  PATH  → write a valid token
#   mojo run -I gen/mojo main.mojo verify PATH → verify+decode a token minted by any language
from std.sys import argv, exit
from std.time import perf_counter_ns
from std.reflection import reflect
from dagr_writer import Builder, NodeStoreRef, node_offset, resolved_ref, leb_length
from token_arena import TokenArena
from token_serde import Jws, JwsAccessor, serialize_claims_graph, serialize_claims_graph_with_header, _store_jws
from token_direct import DirectClaims, DirectJson, DirectJsonMember, _Box, serialize_claims_graph_direct, serialize_claims_graph_with_header_direct
from token_reader import ClaimsAccessor, JsonPackedView, read_claims_root_with_header
from dagr_reader import read_leb
from crypto import Sha256, hmac_sha256_preimage   # sibling module: native HMAC-SHA256

comptime SECRET = "dagr-signed-token-demo-secret-2026"
comptime KID = "hmac-key-2026"
comptime NOW = UInt64(1_760_000_000)
comptime EXP = NOW + 3600

def _read_file(path: String) raises -> List[UInt8]:
    return open(path, "r").read_bytes()

def _write_file(path: String, b: List[UInt8]) raises:
    var f = open(path, "w")
    f.write_bytes(Span(b))

def _tail(buf: List[UInt8], start: Int) raises -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(start, len(buf)):
        out.append(buf[i])
    return out^

# ── Mint ───────────────────────────────────────────────────────────────────────
def _build_arena(exp: UInt64) raises -> TokenArena:
    var a = TokenArena()
    var c = a.new_claims(String("user-42"), String("https://issuer.dagr.one"),
                         String("dagr-api"), NOW, exp)
    c.set_scopes([String("read:profile"), String("write:posts")])
    # custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }
    var roles = a.new_json_array([
        Optional(a.new_json_string(String("admin"))),
        Optional(a.new_json_string(String("billing")))])
    var m_tenant = a.new_json_member(String("tenant")); m_tenant.set_value(a.new_json_string(String("acme")))
    var m_roles = a.new_json_member(String("roles"));   m_roles.set_value(roles)
    var m_mfa = a.new_json_member(String("mfa"));       m_mfa.set_value(a.new_json_bool(True))
    var m_fp = a.new_json_member(String("fp"));         m_fp.set_value(a.new_json_data([UInt8(0xDE), UInt8(0xAD), UInt8(0xBE), UInt8(0xEF)]))
    c.set_custom(a.new_json_object([m_tenant, m_roles, m_mfa, m_fp]))
    a.set_root(c)
    return a^

def mint(alg: String, exp: UInt64) raises -> List[UInt8]:
    var a = _build_arena(exp)
    # Body + original root offset are header-independent: get them from the no-header form.
    var buf0 = serialize_claims_graph(a)
    var fr = read_leb(Span(buf0), 0)
    var root_off = Int(fr[0] >> 2)
    var body = _tail(buf0, fr[1])
    var sig = hmac_sha256_preimage(SECRET, root_off, Span(body))
    return serialize_claims_graph_with_header(a, Jws(alg, Optional[String](String(KID)), sig^))

# ── Verify ───────────────────────────────────────────────────────────────────────
# Returns "" on success, else a "STAGE|REASON" rejection string.
def verify(buf: List[UInt8], secret: String, now: UInt64) raises -> String:
    # The generated `read_claims_root_with_header` decodes framing + packed header,
    # runs this gate, and only THEN hands back a lazy ClaimsAccessor — no hand-rolled
    # offset math, and it validates the framing bits we used to skip.
    @parameter
    def gate(hdr: JwsAccessor[ImmutAnyOrigin], root_off: Int, body: Span[UInt8, ImmutAnyOrigin]) raises:
        # Gate (verify-before-parse): pin algorithm, recompute HMAC. `hdr` is a lazy view —
        # only the fields we read are decoded (key_id is never touched).
        if hdr.algorithm_view() != "HS256":               # zero-alloc: compares a slice, no String
            raise Error("GATE (verify-before-parse)|BadAlg")
        var expected = hmac_sha256_preimage(secret, root_off, body)
        var sig = hdr.signature_view()                    # zero-alloc: a Span into the buffer, no List
        var ok = len(sig) == len(expected)
        if ok:
            var diff = 0
            for i in range(len(expected)):
                diff |= Int(sig[i] ^ expected[i])
            ok = diff == 0
        if not ok:
            raise Error("GATE (verify-before-parse)|BadSignature")
    try:
        var c = read_claims_root_with_header[gate](Span(buf))
        # Post-decode over the now-trusted body — ZERO-ALLOC LAZY ACCESSOR, no restore.
        if now >= c.expires_at():
            return String("post-decode claim check|Expired")
        var aud = c.audience()
        if not aud or aud.value() != String("dagr-api"):
            return String("post-decode claim check|WrongAudience")
        return String("")
    except e:
        # Gate rejections carry a "STAGE|REASON" message; wrap any structural error.
        var m = String(e)
        return m if m.find("|") >= 0 else String("GATE (verify-before-parse)|Malformed")

# Two lowercase hex digits for a byte (Json.data renders as 0x<hex>, JSON's superset).
def _hex2(b: UInt8) -> String:
    comptime H = String("0123456789abcdef")
    return String(H[byte=Int(b >> 4)]) + String(H[byte=Int(b & 15)])

# Lazy render of the packed-JSON `custom` claim — walks the buffer, no owned graph.
# Writes straight into a Writer: one growing buffer, no per-node String allocation.
def _json_write_lazy[o: ImmOrigin](j: JsonPackedView[o], mut w: Some[Writer]) raises:
    if j.is_string():
        w.write('"', j.string(), '"')
    elif j.is_number():
        w.write(j.number())
    elif j.is_bool():
        w.write("true") if j.bool() else w.write("false")
    elif j.is_data():
        w.write("0x")
        var d = j.data()
        for i in range(len(d)):
            w.write(_hex2(d[i]))
    elif j.is_array():
        w.write("[")
        var arr = j.array()
        for i in range(len(arr)):
            if i > 0: w.write(",")
            var e = arr.get(i)
            if e: _json_write_lazy(e.value(), w)
            else: w.write("null")
        w.write("]")
    elif j.is_object():
        w.write("{")
        var obj = j.object()
        for i in range(len(obj)):
            if i > 0: w.write(",")
            var m = obj.get(i)
            var v = m.value()
            w.write('"', m.key(), '":')
            if v: _json_write_lazy(v.value(), w)
            else: w.write("null")
        w.write("}")
    else:
        w.write("?")

# Thin materializing wrapper for callers that want an owned String.
def _json_str_lazy[o: ImmOrigin](j: JsonPackedView[o]) raises -> String:
    var s = String()
    _json_write_lazy(j, s)
    return s^

def _report(label: String, buf: List[UInt8]) raises:
    var r = verify(buf, SECRET, NOW)
    if r == String(""):
        var fr = read_leb(Span(buf), 0)
        var c = ClaimsAccessor(Span(buf), fr[1] + Int(fr[0] >> 2))
        var sub = c.subject()
        var subs = sub.value() if sub else String("-")
        var cus = c.custom()
        var cs = _json_str_lazy(cus.value()) if cus else String("-")
        print("  " + label + "  ACCEPT  sub=\"" + subs + "\" custom=" + cs)
    else:
        var parts = r.split("|")
        print("  " + label + "  REJECT  [" + String(parts[0]) + "] " + String(parts[1]))

# ── Direct Graph Builder ("31 Direct Graph Builder.md"): arena-free value tree in ──
def _build_direct(exp: UInt64) raises -> DirectClaims:
    var roles = DirectJson.array([
        Optional(_Box(DirectJson.string(String("admin")))),
        Optional(_Box(DirectJson.string(String("billing"))))])
    var members = List[DirectJsonMember]()
    members.append(DirectJsonMember(String("tenant"), Optional(_Box(DirectJson.string(String("acme"))))))
    members.append(DirectJsonMember(String("roles"), Optional(_Box(roles^))))
    members.append(DirectJsonMember(String("mfa"), Optional(_Box(DirectJson.bool(True)))))
    members.append(DirectJsonMember(String("fp"), Optional(_Box(DirectJson.data([UInt8(0xDE), UInt8(0xAD), UInt8(0xBE), UInt8(0xEF)])))))
    var custom = DirectJson.object(members^)
    return DirectClaims(
        Optional[String](String("user-42")),
        Optional[String](String("https://issuer.dagr.one")),
        Optional[String](String("dagr-api")),
        NOW, exp,
        [String("read:profile"), String("write:posts")],
        Optional(_Box(custom^)))

def mint_direct(alg: String, exp: UInt64) raises -> List[UInt8]:
    var n = _build_direct(exp)
    # Single pass: the serializer stores the body, then calls this gate over the body
    # bytes (in the same builder) to build the signed header — no re-serialize, no copy.
    @parameter
    def gate(root_off: Int, body: List[UInt8]) raises -> Jws:
        var sig = hmac_sha256_preimage(SECRET, root_off, Span(body))
        return Jws(alg, Optional[String](String(KID)), sig^)
    return serialize_claims_graph_with_header_direct[gate](n^)

# ── Reflective Direct Builder: serialize a user's plain domain struct via comptime ──
# reflection. `reflect[T].field_ref[i](obj)` borrows into `obj` (passed by `ref`, so alive
# for the whole serialize call) → sound, no copy, no intermediate tree, no pool, no boxes,
# no origins. `rebind` here concretizes the opaque reflected field TYPE inside a
# `comptime if name==…` guard (a type rebind that is genuinely correct — NOT the origin-lie
# rebind). The user just declares a struct whose field NAMES are the JSON keys. Emits
# bytes byte-identical to the DirectJson union path (gated below).
@fieldwise_init
struct CustomClaims(Copyable, Movable):
    var tenant: String        # → json string
    var roles: List[String]   # → json array of strings
    var mfa: Bool             # → json bool
    var fp: List[UInt8]       # → json data

def _json_str_array(mut b: Builder[1], ref arr: List[String]) raises -> UInt64:
    var _acb = b.cursor
    var _ph = List[UInt64](); var _pp = List[Bool]()
    for _k in range(len(arr) - 1, -1, -1):
        _ = b.store_utf8(arr[_k], False)
        _ph.append(UInt64((0 << 3) | 6)); _pp.append(True)
    _ = b.store_packed_union_array_frame(_ph, _pp, len(arr), True, _acb)
    return UInt64((3 << 3) | 6)

def _store_json_object_reflect[T: AnyType](mut b: Builder[1], ref obj: T) raises -> UInt64:
    var _pcb = b.cursor
    comptime N = reflect[T].field_count()
    comptime names = reflect[T].field_names()
    comptime for _r in range(N):
        comptime i = N - 1 - _r                      # members backward (matches _apply object)
        var _mb = b.cursor
        comptime nm = reflect[T].field_at[i].name()
        var _tw: UInt64 = 0
        comptime if nm == "String":
            _ = b.store_utf8(rebind[String](reflect[T].field_ref[i](obj)), False)
            _tw = UInt64((0 << 3) | 6)
        elif nm == "Bool":
            _ = b.store_u8(UInt8(1) if rebind[Bool](reflect[T].field_ref[i](obj)) else UInt8(0))
            _tw = UInt64((2 << 3) | 1)
        elif nm == "List[String]":
            _tw = _json_str_array(b, rebind[List[String]](reflect[T].field_ref[i](obj)))
        elif nm == "List[SIMD[DType.uint8, 1]]":
            _ = b.store_data(rebind[List[UInt8]](reflect[T].field_ref[i](obj)))
            _tw = UInt64((5 << 3) | 6)
        else:                                        # nested struct → recurse (json object)
            _tw = _store_json_object_reflect(b, reflect[T].field_ref[i](obj))
        _ = b.store_leb(_tw)                          # value's union tag word
        _ = b.store_utf8(String(materialize[names[i]]()), False)   # member key = field name
        _ = b.store_u8(UInt8(1))                      # presence byte: value present (bit 0)
        _ = b.store_leb(UInt64(b.cursor - _mb))       # member frame size
    _ = b.store_leb(UInt64(N))                        # member count
    _ = b.store_leb(UInt64(b.cursor - _pcb))          # object frame size
    return UInt64((4 << 3) | 6)

def _store_claims_reflect[CT: AnyType](mut b: Builder[1], n: DirectClaims, ref custom: CT) raises -> NodeStoreRef:
    # Byte-for-byte the generated `_store_claims_d`, except the `custom` union field is
    # emitted by reflecting over the live `custom` struct (no pool, no DirectJson tree).
    var _before = b.cursor
    var _rawbits: UInt64 = 0
    var _pr0 = Bool(n.subject)
    var _pr1 = Bool(n.issuer)
    var _pr2 = Bool(n.audience)
    var _tw = _store_json_object_reflect(b, custom)   # ← reflective custom (was pool/idx)
    _ = b.store_leb(_tw)
    ref _pa5 = n.scopes
    var _pcb5 = b.cursor
    for _k5 in range(len(_pa5) - 1, -1, -1):
        _ = b.store_utf8(_pa5[_k5], False)
    _ = b.store_leb(UInt64(len(_pa5)))
    _ = b.store_leb(UInt64(b.cursor - _pcb5))
    if leb_length(UInt64(n.expires_at)) < 8:
        _ = b.store_leb(UInt64(n.expires_at))
    else:
        _ = b.store_u64(n.expires_at); _rawbits |= UInt64(1) << 1
    if leb_length(UInt64(n.issued_at)) < 8:
        _ = b.store_leb(UInt64(n.issued_at))
    else:
        _ = b.store_u64(n.issued_at); _rawbits |= UInt64(1) << 0
    if _pr2: _ = b.store_utf8(n.audience.value(), False)
    if _pr1: _ = b.store_utf8(n.issuer.value(), False)
    if _pr0: _ = b.store_utf8(n.subject.value(), False)
    _ = b.store_u8(UInt8(_rawbits & 0xff))
    var _pb: UInt64 = 0
    if _pr0: _pb |= UInt64(1) << 0
    if _pr1: _pb |= UInt64(1) << 1
    if _pr2: _pb |= UInt64(1) << 2
    _pb |= UInt64(1) << 3                              # scopes always present
    _pb |= UInt64(1) << 4                              # custom always present
    _ = b.store_u8(UInt8(_pb & 0xff))
    _ = b.store_leb(UInt64(b.cursor - _before))
    return resolved_ref(b.cursor)

def mint_direct_reflect(alg: String, exp: UInt64) raises -> List[UInt8]:
    var custom = CustomClaims(String("acme"), [String("admin"), String("billing")], True,
                              [UInt8(0xDE), UInt8(0xAD), UInt8(0xBE), UInt8(0xEF)])
    var n = DirectClaims(
        Optional[String](String("user-42")),
        Optional[String](String("https://issuer.dagr.one")),
        Optional[String](String("dagr-api")),
        NOW, exp,
        [String("read:profile"), String("write:posts")],
        None)                                          # custom carried by the reflected struct
    var b = Builder[1]()
    var _off = node_offset(_store_claims_reflect(b, n, custom))
    var _oo = Int(b.cursor - _off)
    var _body_len = Int(b.cursor)
    var _body = b.make_data()
    @parameter
    def gate(root_off: Int, body: List[UInt8]) raises -> Jws:
        var sig = hmac_sha256_preimage(SECRET, root_off, Span(body))
        return Jws(alg, Optional[String](String(KID)), sig^)
    var header = gate(_oo, _body)
    _store_jws(b, header)
    var _h = Int(b.cursor) - _body_len
    var _so = _oo + _h
    _ = b.store_leb((UInt64(_so) << 2) | 1)
    return b.make_data()

# Mint + verify throughput (no JWT baseline in Mojo — see Rust/TS/Python for that).
def bench() raises:
    var n = 50000
    # Bench BOTH arena-free build paths (spec 31) against the zero-alloc lazy verify:
    #   reflect = comptime-reflection over a live domain struct (no intermediate tree)
    #   tree    = DirectJson value tree (non-atomic _Box recursive union)
    # Both are byte-identical to the arena mint (gated below); only build strategy differs.
    var tok = mint_direct_reflect(String("HS256"), EXP)
    var tok_tree = mint_direct(String("HS256"), EXP)
    var arena_tok = mint(String("HS256"), EXP)
    if verify(tok, SECRET, NOW) != String(""):
        raise Error("dagr verify must accept")
    if tok != arena_tok:
        raise Error("reflect != arena")
    if tok_tree != arena_tok:
        raise Error("tree != arena")
    if verify(mint_direct_reflect(String("HS256"), NOW - 1), SECRET, NOW) == String(""):
        raise Error("expired must reject")
    var sink: UInt64 = 0                              # keep results live (defeat DCE)
    # mint: reflection path
    for _ in range(n // 10):
        var m = mint_direct_reflect(String("HS256"), EXP); sink += UInt64(m[0])
    var t0 = perf_counter_ns()
    for _ in range(n):
        var m = mint_direct_reflect(String("HS256"), EXP); sink += UInt64(m[0])
    var dm_reflect = Int(perf_counter_ns() - t0) // n
    # mint: DirectJson tree path
    for _ in range(n // 10):
        var m = mint_direct(String("HS256"), EXP); sink += UInt64(m[0])
    var t0t = perf_counter_ns()
    for _ in range(n):
        var m = mint_direct(String("HS256"), EXP); sink += UInt64(m[0])
    var dm_tree = Int(perf_counter_ns() - t0t) // n
    # verify (identical token either way — measure once)
    for _ in range(n // 10):
        sink += UInt64(verify(tok, SECRET, NOW).byte_length())
    var t1 = perf_counter_ns()
    for _ in range(n):
        sink += UInt64(verify(tok, SECRET, NOW).byte_length())
    var dv = Int(perf_counter_ns() - t1) // n
    print("BENCH mojo reflect mint=" + String(dm_reflect) + " verify=" + String(dv) + " size=" + String(len(tok)))
    print("BENCH mojo tree mint=" + String(dm_tree) + " verify=" + String(dv) + " size=" + String(len(tok_tree)))
    if sink == 12345678:
        print("")

# Decompose verify's ~640 ns into phases so the bottleneck is visible.
def profile() raises:
    var n = 200000
    var tok = mint_direct(String("HS256"), EXP)
    if verify(tok, SECRET, NOW) != String(""):
        raise Error("verify must accept")
    # (root_off, body) exactly as the gate's HMAC signs — the headerless serialize yields the
    # same body bytes (the header is prepended AFTER signing), so timing the HMAC over these
    # is representative of what the gate recomputes.
    var a = _build_arena(EXP)
    var buf0 = serialize_claims_graph(a)
    var fr = read_leb(Span(buf0), 0)
    var root_off = Int(fr[0] >> 2)
    var body = _tail(buf0, fr[1])
    var sink: UInt64 = 0

    @parameter
    def noop(hdr: JwsAccessor[ImmutAnyOrigin], ro: Int, b: Span[UInt8, ImmutAnyOrigin]) raises:
        pass

    # 1) full verify
    for _ in range(n // 10):
        sink += UInt64(verify(tok, SECRET, NOW).byte_length())
    var t0 = perf_counter_ns()
    for _ in range(n):
        sink += UInt64(verify(tok, SECRET, NOW).byte_length())
    var t_full = Int(perf_counter_ns() - t0) // n

    # 2) HMAC over the preimage — the crypto the gate runs
    for _ in range(n // 10):
        var s = hmac_sha256_preimage(SECRET, root_off, Span(body)); sink += UInt64(s[0])
    var t1 = perf_counter_ns()
    for _ in range(n):
        var s = hmac_sha256_preimage(SECRET, root_off, Span(body)); sink += UInt64(s[0])
    var t_hmac = Int(perf_counter_ns() - t1) // n

    # 3) one bare SHA-256 of the body — block-compression cost, no HMAC doubling / key blocks
    for _ in range(n // 10):
        var h = Sha256(); h.update(Span(body)); var d = h.finalize(); sink += UInt64(d[0])
    var t2 = perf_counter_ns()
    for _ in range(n):
        var h = Sha256(); h.update(Span(body)); var d = h.finalize(); sink += UInt64(d[0])
    var t_sha = Int(perf_counter_ns() - t2) // n

    # 4) decode + lazy reads — everything verify does EXCEPT the HMAC (no-op gate)
    for _ in range(n // 10):
        var c = read_claims_root_with_header[noop](Span(tok)); sink += UInt64(c.expires_at())
    var t3 = perf_counter_ns()
    for _ in range(n):
        var c = read_claims_root_with_header[noop](Span(tok))
        sink += UInt64(c.expires_at())
        var aud = c.audience()
        if aud:
            if aud.value() == String("dagr-api"):
                sink += 1
    var t_decode = Int(perf_counter_ns() - t3) // n

    # 5) lazy reads only — decode the accessor ONCE, then read fields repeatedly (isolates
    #    the field reads; decode+header-restore = t_decode - t_lazy).
    var cc = read_claims_root_with_header[noop](Span(tok))
    for _ in range(n // 10):
        sink += UInt64(cc.expires_at())
    var t4 = perf_counter_ns()
    for _ in range(n):
        sink += UInt64(cc.expires_at())
        var aud2 = cc.audience()
        if aud2:
            if aud2.value() == String("dagr-api"):
                sink += 1
    var t_lazy = Int(perf_counter_ns() - t4) // n

    # ── Mint phases ─────────────────────────────────────────────────────────────
    for _ in range(n // 10):
        var _v = _build_direct(EXP); sink += UInt64(_v.expires_at)
    var t5 = perf_counter_ns()
    for _ in range(n):
        var _v = _build_direct(EXP); sink += UInt64(_v.expires_at)
    var t_build = Int(perf_counter_ns() - t5) // n

    # bare build: Claims scalars/strings/scopes only (custom=None) — isolates the recursive
    # JSON tree (_Box heap boxes + Lists) cost = t_build - t_bare.
    for _ in range(n // 10):
        var _b = DirectClaims(Optional[String](String("user-42")), Optional[String](String("https://issuer.dagr.one")), Optional[String](String("dagr-api")), NOW, EXP, [String("read:profile"), String("write:posts")], None); sink += UInt64(_b.expires_at)
    var t5b = perf_counter_ns()
    for _ in range(n):
        var _b = DirectClaims(Optional[String](String("user-42")), Optional[String](String("https://issuer.dagr.one")), Optional[String](String("dagr-api")), NOW, EXP, [String("read:profile"), String("write:posts")], None); sink += UInt64(_b.expires_at)
    var t_bare = Int(perf_counter_ns() - t5b) // n

    for _ in range(n // 10):
        var _m = mint_direct(String("HS256"), EXP); sink += UInt64(_m[0])
    var t6 = perf_counter_ns()
    for _ in range(n):
        var _m = mint_direct(String("HS256"), EXP); sink += UInt64(_m[0])
    var t_mint = Int(perf_counter_ns() - t6) // n

    # reflective mint: no intermediate tree at all — serialize straight from a live domain
    # struct via comptime reflection (borrowed field refs). Compare vs the index-pool mint.
    for _ in range(n // 10):
        var _mr = mint_direct_reflect(String("HS256"), EXP); sink += UInt64(_mr[0])
    var t6r = perf_counter_ns()
    for _ in range(n):
        var _mr = mint_direct_reflect(String("HS256"), EXP); sink += UInt64(_mr[0])
    var t_mint_reflect = Int(perf_counter_ns() - t6r) // n

    print("PROFILE mojo mint(reflect)=" + String(t_mint_reflect) + "ns  vs  mint(tree)="
          + String(t_mint) + "ns  (no intermediate tree; serialize straight from live struct)")
    print("PROFILE mojo mint total=" + String(t_mint) + "ns  =  build_tree=" + String(t_build)
          + "ns + serialize+hmac=" + String(t_mint - t_build) + "ns  (hmac≈" + String(t_hmac) + "ns)")
    print("        build_tree " + String(t_build) + "ns  =  Claims scalars/strings/scopes="
          + String(t_bare) + "ns + custom JSON tree (_Box+Lists)=" + String(t_build - t_bare) + "ns")
    print("PROFILE mojo verify total=" + String(t_full) + "ns  =  decode+lazy=" + String(t_decode)
          + "ns + hmac=" + String(t_hmac) + "ns + residual(sig-compare/call)="
          + String(t_full - t_decode - t_hmac) + "ns")
    print("        decode+lazy " + String(t_decode) + "ns  =  framing+header-restore="
          + String(t_decode - t_lazy) + "ns + lazy field reads=" + String(t_lazy) + "ns")
    print("        ref: 1x bare SHA-256 of the " + String(len(body)) + "B body=" + String(t_sha)
          + "ns (~28ns/block ≈ ring); hmac = 2 hashes: ipad+le+body then opad+innerhash")
    if sink == 12345678:
        print("")

def main() raises:
    var args = argv()
    if len(args) >= 2 and args[1] == "bench":
        bench()
        return
    if len(args) >= 2 and args[1] == "profile":
        profile()
        return
    if len(args) >= 2 and args[1] == "direct":
        var a = mint(String("HS256"), EXP)
        var d = mint_direct(String("HS256"), EXP)
        if a == d:                                   # List[UInt8] ==: length + elementwise
            print("[mojo] direct == arena (" + String(len(d)) + " bytes) — spec 31 gate OK")
        else:
            print("[mojo] direct != arena (arena " + String(len(a)) + " vs direct " + String(len(d)) + ")")
            _write_file(String("/tmp/mojo_a.bin"), a)
            _write_file(String("/tmp/mojo_d.bin"), d)
            exit(1)
        return
    if len(args) >= 2 and args[1] == "reflect":
        var a = mint(String("HS256"), EXP)
        var r = mint_direct_reflect(String("HS256"), EXP)
        if a == r:
            print("[mojo] reflect == arena (" + String(len(r)) + " bytes) — comptime-reflection gate OK")
        else:
            print("[mojo] reflect != arena (arena " + String(len(a)) + " vs reflect " + String(len(r)) + ")")
            _write_file(String("/tmp/mojo_a.bin"), a)
            _write_file(String("/tmp/mojo_r.bin"), r)
            exit(1)
        return
    if len(args) >= 3 and args[1] == "emit":
        _write_file(String(args[2]), mint(String("HS256"), EXP))
        print("[mojo] emitted -> " + String(args[2]))
        return
    if len(args) >= 3 and args[1] == "verify":
        var buf = _read_file(String(args[2]))
        var r = verify(buf, SECRET, NOW)
        if r == String(""):
            print("  [mojo] " + String(args[2]) + "  ACCEPT")
        else:
            var parts = r.split("|")
            print("  [mojo] " + String(args[2]) + "  REJECT [" + String(parts[0]) + "] " + String(parts[1]))
            # non-zero exit for the harness
            exit(1)
        return

    print("== dagr-signed-token — Mojo ==\n")
    var token = mint(String("HS256"), EXP)
    print("Minted token: " + String(len(token)) + " bytes\n")
    print("Verification:")
    _report("valid token   ", token)
    var tampered = token.copy()
    var sp = Span(token)
    var fr = read_leb(sp, 0)
    var hcs = read_leb(sp, fr[1])
    tampered[fr[1] + hcs[1] + Int(hcs[0])] ^= 0x01  # flip a byte in the body
    _report("tampered body ", tampered)
    var none_tok = mint(String("none"), EXP)
    _report("alg:none token", none_tok)
    var exp_tok = mint(String("HS256"), NOW - 1)
    _report("expired token ", exp_tok)
