# dagr-signed-token — Mojo example (see ../../CONTRACT.md).
#
# Codec is the generated gen/mojo modules; crypto (HMAC-SHA256) + file I/O go through
# Python interop (stdlib hmac/hashlib) — no third-party Mojo deps.
#
#   mojo run -I gen/mojo main.mojo             → showcase
#   mojo run -I gen/mojo main.mojo emit  PATH  → write a valid token
#   mojo run -I gen/mojo main.mojo verify PATH → verify+decode a token minted by any language
from std.python import Python, PythonObject
from std.sys import argv
from std.memory import ArcPointer
from token_arena import TokenArena
from token_serde import Jws, serialize_claims_graph, serialize_claims_graph_with_header, read_claims_header
from token_direct import DirectClaims, DirectJson, DirectJsonMember, serialize_claims_graph_direct, serialize_claims_graph_with_header_direct
from token_reader import ClaimsAccessor, JsonPackedView
from dagr_reader import read_leb

comptime SECRET = "dagr-signed-token-demo-secret-2026"
comptime KID = "hmac-key-2026"
comptime NOW = UInt64(1_760_000_000)
comptime EXP = NOW + 3600

# ── Python-interop helpers: bytes conversion, HMAC, file I/O ───────────────────
def _to_pybytes(b: Span[UInt8, _]) raises -> PythonObject:
    var builtins = Python.import_module("builtins")
    var lst = builtins.list()
    for i in range(len(b)):
        _ = lst.append(Int(b[i]))
    return builtins.bytes(lst)

def _from_pybytes(o: PythonObject) raises -> List[UInt8]:
    var out = List[UInt8]()
    for v in o:
        out.append(UInt8(Int(py=v)))
    return out^

def hmac_sha256(key: String, msg: List[UInt8]) raises -> List[UInt8]:
    var hmac = Python.import_module("hmac")
    var hashlib = Python.import_module("hashlib")
    var kb = _to_pybytes(String(key).as_bytes())
    var mb = _to_pybytes(Span(msg))
    return _from_pybytes(hmac.new(kb, mb, hashlib.sha256).digest())

def _read_file(path: String) raises -> List[UInt8]:
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "rb")
    var data = f.read()
    _ = f.close()
    return _from_pybytes(data)

def _write_file(path: String, b: List[UInt8]) raises:
    var builtins = Python.import_module("builtins")
    var f = builtins.open(path, "wb")
    _ = f.write(_to_pybytes(b))
    _ = f.close()

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

def _push_leb(mut out: List[UInt8], value: UInt64):
    var v = value
    while True:
        var b = UInt8(v & 0x7F)
        v >>= 7
        if v != 0:
            b |= 0x80
        out.append(b)
        if v == 0:
            break

# ── Mint ───────────────────────────────────────────────────────────────────────
def _build_arena(exp: UInt64) raises -> TokenArena:
    var a = TokenArena()
    var c = a.new_claims(String("user-42"), String("https://issuer.dagr.one"),
                         String("dagr-api"), NOW, exp)
    c.set_scopes([String("read:profile"), String("write:posts")])
    # custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true }
    var roles = a.new_json_array([
        Optional(a.new_json_string(String("admin"))),
        Optional(a.new_json_string(String("billing")))])
    var m_tenant = a.new_json_member(String("tenant")); m_tenant.set_value(a.new_json_string(String("acme")))
    var m_roles = a.new_json_member(String("roles"));   m_roles.set_value(roles)
    var m_mfa = a.new_json_member(String("mfa"));       m_mfa.set_value(a.new_json_bool(True))
    c.set_custom(a.new_json_object([m_tenant, m_roles, m_mfa]))
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
    var sp = Span(buf)
    var fr = read_leb(sp, 0)
    var stored_off = Int(fr[0] >> 2)
    var flen = fr[1]
    var hcs = read_leb(sp, flen)
    var H = hcs[1] + Int(hcs[0])
    var root_off = stored_off - H
    var body = _tail(buf, flen + H)
    var hdr = read_claims_header(sp)
    # Gate (verify-before-parse): pin algorithm, recompute HMAC.
    if hdr.algorithm != String("HS256"):
        return String("GATE (verify-before-parse)|BadAlg")
    var expected = hmac_sha256(secret, preimage(root_off, body))
    if len(hdr.signature) != len(expected):
        return String("GATE (verify-before-parse)|BadSignature")
    var diff = 0
    for i in range(len(expected)):
        diff |= Int(hdr.signature[i] ^ expected[i])
    if diff != 0:
        return String("GATE (verify-before-parse)|BadSignature")
    # Post-decode over the now-trusted body — ZERO-ALLOC LAZY ACCESSOR, no arena restore.
    # The root sits at `flen + stored_off` (past the framing word + packed header, §14 §4).
    var c = ClaimsAccessor(Span(buf), flen + stored_off)
    if now >= c.expiresAt():
        return String("post-decode claim check|Expired")
    var aud = c.audience()
    if not aud or aud.value() != String("dagr-api"):
        return String("post-decode claim check|WrongAudience")
    return String("")

# Lazy render of the packed-JSON `custom` claim — walks the buffer, no owned graph.
def _json_str_lazy[o: ImmOrigin](j: JsonPackedView[o]) raises -> String:
    var t = j.tag()
    if t == 0:
        return String('"') + j.string() + String('"')
    if t == 1:
        return String(j.number())
    if t == 2:
        return String("true") if j.bool() else String("false")
    if t == 3:
        var s = String("[")
        var arr = j.array()
        for i in range(len(arr)):
            if i > 0: s += String(",")
            var e = arr.get(i)
            if e: s += _json_str_lazy(e.value())
            else: s += String("null")
        return s + String("]")
    if t == 4:
        var s = String("{")
        var obj = j.object()
        for i in range(len(obj)):
            if i > 0: s += String(",")
            var m = obj.get(i)
            var v = m.value()
            s += String('"') + m.key() + String('":')
            s += _json_str_lazy(v.value()) if v else String("null")
        return s + String("}")
    return String("?")

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
    var buf0 = serialize_claims_graph_direct(n.copy())
    var fr = read_leb(Span(buf0), 0)
    var root_off = Int(fr[0] >> 2)
    var body = _tail(buf0, fr[1])
    var sig = hmac_sha256(SECRET, preimage(root_off, body))
    return serialize_claims_graph_with_header_direct(n^, Jws(alg, Optional[String](String(KID)), sig^))

def main() raises:
    var args = argv()
    if len(args) >= 2 and args[1] == "direct":
        var a = mint(String("HS256"), EXP)
        var d = mint_direct(String("HS256"), EXP)
        var eq = len(a) == len(d)
        if eq:
            for i in range(len(a)):
                if a[i] != d[i]:
                    eq = False
                    break
        if eq:
            print("[mojo] direct == arena (" + String(len(d)) + " bytes) — spec 31 gate OK")
        else:
            print("[mojo] direct != arena (arena " + String(len(a)) + " vs direct " + String(len(d)) + ")")
            _write_file(String("/tmp/mojo_a.bin"), a)
            _write_file(String("/tmp/mojo_d.bin"), d)
            var sys = Python.import_module("sys")
            _ = sys.exit(1)
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
            var sys = Python.import_module("sys")
            _ = sys.exit(1)
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
