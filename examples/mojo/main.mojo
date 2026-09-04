# dagr-signed-token — Mojo example (see ../../CONTRACT.md).
#
# Codec is the generated gen/mojo modules; crypto (HMAC-SHA256) is hand-rolled native
# Mojo (see _sha256/hmac_sha256); file I/O is native — zero third-party deps, no Python.
#
#   mojo run -I gen/mojo main.mojo             → showcase
#   mojo run -I gen/mojo main.mojo emit  PATH  → write a valid token
#   mojo run -I gen/mojo main.mojo verify PATH → verify+decode a token minted by any language
from std.sys import argv, exit
from std.time import perf_counter_ns
from std.memory import ArcPointer
from token_arena import TokenArena
from token_serde import Jws, serialize_claims_graph, serialize_claims_graph_with_header
from token_direct import DirectClaims, DirectJson, DirectJsonMember, serialize_claims_graph_direct, serialize_claims_graph_with_header_direct
from token_reader import ClaimsAccessor, JsonPackedView, read_claims_root_with_header
from dagr_reader import read_leb

comptime SECRET = "dagr-signed-token-demo-secret-2026"
comptime KID = "hmac-key-2026"
comptime NOW = UInt64(1_760_000_000)
comptime EXP = NOW + 3600

# ── Zero-dependency crypto: hand-rolled SHA-256 + HMAC-SHA256 ──────────────────
# Mirrors examples/rust/src/sha256.rs — no Python runtime, no third-party deps, so
# the whole demo (crypto included) pulls in nothing, matching Dagr's own ethos.
# Small and readable, NOT hardened production crypto; for real systems use a vetted
# library. The point is that the *envelope mechanics* are Dagr's; the algorithm is
# the caller's choice.
def _rotr(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (UInt32(32) - n))

# SHA-256 of an arbitrary byte string → 32-byte digest.
def _sha256(msg: Span[UInt8, _]) -> List[UInt8]:
    var k: List[UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    var h: List[UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    # Pad: append 0x80, then zeros, then the 64-bit big-endian bit length.
    var data = List[UInt8]()
    for i in range(len(msg)):
        data.append(msg[i])
    var bitlen = UInt64(len(msg)) * 8
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    for i in range(8):
        data.append(UInt8((bitlen >> UInt64((7 - i) * 8)) & 0xFF))

    var nblocks = len(data) // 64
    for b in range(nblocks):
        var off = b * 64
        var w = List[UInt32]()
        for i in range(16):
            var j = off + i * 4
            w.append((UInt32(data[j]) << 24) | (UInt32(data[j + 1]) << 16)
                     | (UInt32(data[j + 2]) << 8) | UInt32(data[j + 3]))
        for i in range(16, 64):
            var s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            var s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append(w[i - 16] + s0 + w[i - 7] + s1)

        var aa = h[0]; var bb = h[1]; var cc = h[2]; var dd = h[3]
        var ee = h[4]; var ff = h[5]; var gg = h[6]; var hh = h[7]
        for i in range(64):
            var big_s1 = _rotr(ee, 6) ^ _rotr(ee, 11) ^ _rotr(ee, 25)
            var ch = (ee & ff) ^ (~ee & gg)
            var t1 = hh + big_s1 + ch + k[i] + w[i]
            var big_s0 = _rotr(aa, 2) ^ _rotr(aa, 13) ^ _rotr(aa, 22)
            var maj = (aa & bb) ^ (aa & cc) ^ (bb & cc)
            var t2 = big_s0 + maj
            hh = gg; gg = ff; ff = ee; ee = dd + t1
            dd = cc; cc = bb; bb = aa; aa = t1 + t2
        h[0] = h[0] + aa; h[1] = h[1] + bb; h[2] = h[2] + cc; h[3] = h[3] + dd
        h[4] = h[4] + ee; h[5] = h[5] + ff; h[6] = h[6] + gg; h[7] = h[7] + hh

    var out = List[UInt8]()
    for i in range(8):
        out.append(UInt8((h[i] >> 24) & 0xFF))
        out.append(UInt8((h[i] >> 16) & 0xFF))
        out.append(UInt8((h[i] >> 8) & 0xFF))
        out.append(UInt8(h[i] & 0xFF))
    return out^

# HMAC-SHA256 (RFC 2104) → 32-byte tag. This is the "HS256" of JWT.
def hmac_sha256(key: String, msg: List[UInt8]) -> List[UInt8]:
    comptime BLOCK = 64
    var kb = String(key).as_bytes()
    var k = List[UInt8]()
    for _ in range(BLOCK):
        k.append(0)
    if len(kb) > BLOCK:
        var kh = _sha256(kb)
        for i in range(32):
            k[i] = kh[i]
    else:
        for i in range(len(kb)):
            k[i] = kb[i]

    var inner = List[UInt8]()
    var outer = List[UInt8]()
    for i in range(BLOCK):
        inner.append(UInt8(0x36) ^ k[i])
        outer.append(UInt8(0x5c) ^ k[i])
    for i in range(len(msg)):
        inner.append(msg[i])
    var inner_hash = _sha256(Span(inner))
    for i in range(32):
        outer.append(inner_hash[i])
    return _sha256(Span(outer))

def _read_file(path: String) raises -> List[UInt8]:
    return open(path, "r").read_bytes()

def _write_file(path: String, b: List[UInt8]) raises:
    var f = open(path, "w")
    f.write_bytes(Span(b))

# preimage(rootOffset, body) = LE_u64(rootOffset) ++ body  (see CONTRACT.md)
def preimage(root_offset: Int, body: List[UInt8]) raises -> List[UInt8]:
    var m = List[UInt8]()
    var v = UInt64(root_offset)
    for i in range(8):
        m.append(UInt8((v >> UInt64(i * 8)) & 0xFF))
    for i in range(len(body)):
        m.append(body[i])
    return m^

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
    var sig = hmac_sha256(SECRET, preimage(root_off, body))
    return serialize_claims_graph_with_header(a, Jws(alg, Optional[String](String(KID)), sig^))

# ── Verify ───────────────────────────────────────────────────────────────────────
# Returns "" on success, else a "STAGE|REASON" rejection string.
def verify(buf: List[UInt8], secret: String, now: UInt64) raises -> String:
    # The generated `read_claims_root_with_header` decodes framing + packed header,
    # runs this gate, and only THEN hands back a lazy ClaimsAccessor — no hand-rolled
    # offset math, and it validates the framing bits we used to skip.
    @parameter
    def gate(hdr: Jws, root_off: Int, body: List[UInt8]) raises:
        # Gate (verify-before-parse): pin algorithm, recompute HMAC.
        if hdr.algorithm != String("HS256"):
            raise Error("GATE (verify-before-parse)|BadAlg")
        var expected = hmac_sha256(secret, preimage(root_off, body))
        var ok = len(hdr.signature) == len(expected)
        if ok:
            var diff = 0
            for i in range(len(expected)):
                diff |= Int(hdr.signature[i] ^ expected[i])
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
        Optional(ArcPointer(DirectJson.string(String("admin")))),
        Optional(ArcPointer(DirectJson.string(String("billing"))))])
    var members = List[DirectJsonMember]()
    members.append(DirectJsonMember(String("tenant"), Optional(ArcPointer(DirectJson.string(String("acme"))))))
    members.append(DirectJsonMember(String("roles"), Optional(ArcPointer(roles^))))
    members.append(DirectJsonMember(String("mfa"), Optional(ArcPointer(DirectJson.bool(True)))))
    members.append(DirectJsonMember(String("fp"), Optional(ArcPointer(DirectJson.data([UInt8(0xDE), UInt8(0xAD), UInt8(0xBE), UInt8(0xEF)])))))
    var custom = DirectJson.object(members^)
    return DirectClaims(
        Optional[String](String("user-42")),
        Optional[String](String("https://issuer.dagr.one")),
        Optional[String](String("dagr-api")),
        NOW, exp,
        [String("read:profile"), String("write:posts")],
        Optional(ArcPointer(custom^)))

def mint_direct(alg: String, exp: UInt64) raises -> List[UInt8]:
    var n = _build_direct(exp)
    # Single pass: the serializer stores the body, then calls this gate over the body
    # bytes (in the same builder) to build the signed header — no re-serialize, no copy.
    @parameter
    def gate(root_off: Int, body: List[UInt8]) raises -> Jws:
        var sig = hmac_sha256(SECRET, preimage(root_off, body))
        return Jws(alg, Optional[String](String(KID)), sig^)
    return serialize_claims_graph_with_header_direct[gate](n^)

# Mint + verify throughput (no JWT baseline in Mojo — see Rust/TS/Python for that).
def bench() raises:
    var n = 50000
    # Bench the FAST PATH: arena-free direct build (spec 31) + zero-alloc lazy verify.
    var tok = mint_direct(String("HS256"), EXP)
    if verify(tok, SECRET, NOW) != String(""):
        raise Error("dagr verify must accept")
    if tok != mint(String("HS256"), EXP):
        raise Error("direct != arena")
    if verify(mint_direct(String("HS256"), NOW - 1), SECRET, NOW) == String(""):
        raise Error("expired must reject")
    var sink: UInt64 = 0                              # keep results live (defeat DCE)
    for _ in range(n // 10):
        var m = mint_direct(String("HS256"), EXP); sink += UInt64(m[0])
    var t0 = perf_counter_ns()
    for _ in range(n):
        var m = mint_direct(String("HS256"), EXP); sink += UInt64(m[0])
    var dm = Int(perf_counter_ns() - t0) // n
    for _ in range(n // 10):
        sink += UInt64(verify(tok, SECRET, NOW).byte_length())
    var t1 = perf_counter_ns()
    for _ in range(n):
        sink += UInt64(verify(tok, SECRET, NOW).byte_length())
    var dv = Int(perf_counter_ns() - t1) // n
    print("BENCH mojo dagr mint=" + String(dm) + " verify=" + String(dv) + " size=" + String(len(tok)))
    if sink == 12345678:
        print("")

def main() raises:
    var args = argv()
    if len(args) >= 2 and args[1] == "bench":
        bench()
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
