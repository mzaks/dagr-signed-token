# dagr-signed-token — Mojo example (see ../../CONTRACT.md).
#
# Codec is the generated gen/mojo modules; crypto is native Mojo — SHA-256 on the ARMv8
# hardware intrinsics + a streaming HMAC (see Sha256/hmac_sha256); native file I/O — zero deps.
#
#   mojo run -I gen/mojo main.mojo             → showcase
#   mojo run -I gen/mojo main.mojo emit  PATH  → write a valid token
#   mojo run -I gen/mojo main.mojo verify PATH → verify+decode a token minted by any language
from std.sys import argv, exit
from std.sys.intrinsics import llvm_intrinsic
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

# ── Native hardware SHA-256 + HMAC-SHA256 (zero dependencies) ──────────────────
# SHA-256 built directly on the ARMv8 crypto extensions via LLVM intrinsics
# (sha256h / sha256h2 / sha256su0 / sha256su1) — the SAME hardware `ring` reaches
# through hand-written asm, but written in plain Mojo with no FFI and no third-party
# crate. ~4-5× faster than a scalar reference impl. Targets ARMv8-A + crypto (e.g.
# Apple Silicon); a scalar fallback would be a comptime branch on the target.
comptime _u32x4 = SIMD[DType.uint32, 4]

@always_inline
def _sha256h(a: _u32x4, b: _u32x4, c: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h", _u32x4, has_side_effect=False](a, b, c)
@always_inline
def _sha256h2(a: _u32x4, b: _u32x4, c: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h2", _u32x4, has_side_effect=False](a, b, c)
@always_inline
def _sha256su0(a: _u32x4, b: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su0", _u32x4, has_side_effect=False](a, b)
@always_inline
def _sha256su1(a: _u32x4, b: _u32x4, c: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su1", _u32x4, has_side_effect=False](a, b, c)

@always_inline
def _bew(b: Span[UInt8, _], i: Int) -> UInt32:   # big-endian u32 load
    return (UInt32(b[i]) << 24) | (UInt32(b[i + 1]) << 16) | (UInt32(b[i + 2]) << 8) | UInt32(b[i + 3])

# The 64 round constants as 16 comptime vectors of 4 — baked in as immediates (like ring's
# static K table). No per-call heap List, no bounds-checked loads in the compression loop.
comptime _K0  = _u32x4(0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5)
comptime _K1  = _u32x4(0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5)
comptime _K2  = _u32x4(0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3)
comptime _K3  = _u32x4(0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174)
comptime _K4  = _u32x4(0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc)
comptime _K5  = _u32x4(0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da)
comptime _K6  = _u32x4(0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7)
comptime _K7  = _u32x4(0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967)
comptime _K8  = _u32x4(0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13)
comptime _K9  = _u32x4(0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85)
comptime _K10 = _u32x4(0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3)
comptime _K11 = _u32x4(0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070)
comptime _K12 = _u32x4(0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5)
comptime _K13 = _u32x4(0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3)
comptime _K14 = _u32x4(0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208)
comptime _K15 = _u32x4(0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

# Compress one 64-byte block into (s0, s1) = (H0..H3, H4..H7) — the canonical 16-quad
# ARMv8 SHA-256 sequence (msg schedule via su0/su1, rounds via sha256h/h2).
def _block(mut s0: _u32x4, mut s1: _u32x4, blk: Span[UInt8, _], off: Int):
    var abef = s0
    var cdgh = s1
    var m0 = _u32x4(_bew(blk, off + 0),  _bew(blk, off + 4),  _bew(blk, off + 8),  _bew(blk, off + 12))
    var m1 = _u32x4(_bew(blk, off + 16), _bew(blk, off + 20), _bew(blk, off + 24), _bew(blk, off + 28))
    var m2 = _u32x4(_bew(blk, off + 32), _bew(blk, off + 36), _bew(blk, off + 40), _bew(blk, off + 44))
    var m3 = _u32x4(_bew(blk, off + 48), _bew(blk, off + 52), _bew(blk, off + 56), _bew(blk, off + 60))
    var t0 = m0 + _K0; var t1: _u32x4; var t2: _u32x4
    m0 = _sha256su0(m0, m1); t2 = s0; t1 = m1 + _K1;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m0 = _sha256su1(m0, m2, m3)
    m1 = _sha256su0(m1, m2); t2 = s0; t0 = m2 + _K2;  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m1 = _sha256su1(m1, m3, m0)
    m2 = _sha256su0(m2, m3); t2 = s0; t1 = m3 + _K3;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m2 = _sha256su1(m2, m0, m1)
    m3 = _sha256su0(m3, m0); t2 = s0; t0 = m0 + _K4;  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m3 = _sha256su1(m3, m1, m2)
    m0 = _sha256su0(m0, m1); t2 = s0; t1 = m1 + _K5;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m0 = _sha256su1(m0, m2, m3)
    m1 = _sha256su0(m1, m2); t2 = s0; t0 = m2 + _K6;  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m1 = _sha256su1(m1, m3, m0)
    m2 = _sha256su0(m2, m3); t2 = s0; t1 = m3 + _K7;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m2 = _sha256su1(m2, m0, m1)
    m3 = _sha256su0(m3, m0); t2 = s0; t0 = m0 + _K8;  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m3 = _sha256su1(m3, m1, m2)
    m0 = _sha256su0(m0, m1); t2 = s0; t1 = m1 + _K9;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m0 = _sha256su1(m0, m2, m3)
    m1 = _sha256su0(m1, m2); t2 = s0; t0 = m2 + _K10; s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m1 = _sha256su1(m1, m3, m0)
    m2 = _sha256su0(m2, m3); t2 = s0; t1 = m3 + _K11; s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m2 = _sha256su1(m2, m0, m1)
    m3 = _sha256su0(m3, m0); t2 = s0; t0 = m0 + _K12; s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m3 = _sha256su1(m3, m1, m2)
    t2 = s0; t1 = m1 + _K13; s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0)
    t2 = s0; t0 = m2 + _K14; s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1)
    t2 = s0; t1 = m3 + _K15; s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0)
    t2 = s0;                  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1)
    s0 = s0 + abef
    s1 = s1 + cdgh

# Streaming SHA-256: keep the partial block on the STACK (InlineArray) and feed full
# 64-byte blocks straight from the caller's Span — no per-message heap copy, no padding
# List. `kw` = the round-constant vectors (built once by the caller; HMAC reuses across 3
# hashes). The digest is returned in a stack InlineArray so intermediate hashes never touch
# the heap either.
struct Sha256(Copyable, Movable):
    var s0: _u32x4
    var s1: _u32x4
    var buf: InlineArray[UInt8, 64]
    var n: Int
    var total: UInt64

    def __init__(out self):
        self.s0 = _u32x4(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a)
        self.s1 = _u32x4(0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
        self.buf = InlineArray[UInt8, 64](fill=0)
        self.n = 0
        self.total = 0

    def update(mut self, data: Span[UInt8, _]):
        self.total += UInt64(len(data))
        var i = 0
        if self.n > 0:                                   # top up the partial block first
            while self.n < 64 and i < len(data):
                self.buf[self.n] = data[i]; self.n += 1; i += 1
            if self.n == 64:
                _block(self.s0, self.s1, Span(self.buf), 0); self.n = 0
        while i + 64 <= len(data):                       # full blocks straight from the Span
            _block(self.s0, self.s1, data, i); i += 64
        while i < len(data):                             # buffer the remainder
            self.buf[self.n] = data[i]; self.n += 1; i += 1

    def finalize(mut self) -> InlineArray[UInt8, 32]:
        var bits = self.total * 8
        self.buf[self.n] = 0x80; self.n += 1
        if self.n > 56:
            while self.n < 64: self.buf[self.n] = 0; self.n += 1
            _block(self.s0, self.s1, Span(self.buf), 0); self.n = 0
        while self.n < 56: self.buf[self.n] = 0; self.n += 1
        for j in range(8): self.buf[56 + j] = UInt8((bits >> UInt64((7 - j) * 8)) & 0xFF)
        _block(self.s0, self.s1, Span(self.buf), 0)
        var out = InlineArray[UInt8, 32](fill=0)
        for lane in range(4):
            out[lane * 4] = UInt8((self.s0[lane] >> 24) & 0xFF);      out[lane * 4 + 1] = UInt8((self.s0[lane] >> 16) & 0xFF)
            out[lane * 4 + 2] = UInt8((self.s0[lane] >> 8) & 0xFF);   out[lane * 4 + 3] = UInt8(self.s0[lane] & 0xFF)
        for lane in range(4):
            out[16 + lane * 4] = UInt8((self.s1[lane] >> 24) & 0xFF); out[16 + lane * 4 + 1] = UInt8((self.s1[lane] >> 16) & 0xFF)
            out[16 + lane * 4 + 2] = UInt8((self.s1[lane] >> 8) & 0xFF); out[16 + lane * 4 + 3] = UInt8(self.s1[lane] & 0xFF)
        return out^

# HMAC-SHA256 (RFC 2104) → 32-byte tag. This is the "HS256" of JWT. Streaming: the ipad/
# opad key blocks live on the STACK (InlineArray) and the message is fed directly to the
# hash — no inner/outer/key Lists, only the final 32-byte tag is heap-allocated.
def hmac_sha256(key: String, msg: List[UInt8]) -> List[UInt8]:
    var kb = String(key).as_bytes()
    var ipad = InlineArray[UInt8, 64](fill=0x36)     # ipad[i] = 0x36 ^ key[i] (0x36 where key runs out)
    var opad = InlineArray[UInt8, 64](fill=0x5c)
    if len(kb) > 64:
        var d = Sha256(); d.update(kb); var dh = d.finalize()
        for i in range(32):
            ipad[i] = 0x36 ^ dh[i]; opad[i] = 0x5c ^ dh[i]
    else:
        for i in range(len(kb)):
            ipad[i] = 0x36 ^ kb[i]; opad[i] = 0x5c ^ kb[i]

    var inner = Sha256(); inner.update(Span(ipad)); inner.update(Span(msg))
    var ih = inner.finalize()
    var outer = Sha256(); outer.update(Span(opad)); outer.update(Span(ih))
    var fh = outer.finalize()
    var out = List[UInt8](unsafe_uninit_length=32)
    for i in range(32):
        out[i] = fh[i]
    return out^

# HMAC over the signing preimage `LE_u64(root_off) ++ body` — streamed, so the preimage
# is never materialised as a List (the 8-byte prefix lives on the stack; the body Span is
# hashed in place). Assumes a <=64-byte key (the demo secret). This is the verify/mint hot path.
def hmac_sha256_preimage(key: String, root_off: Int, body: Span[UInt8, _]) -> List[UInt8]:
    var kb = String(key).as_bytes()
    var ipad = InlineArray[UInt8, 64](fill=0x36)
    var opad = InlineArray[UInt8, 64](fill=0x5c)
    for i in range(len(kb)):
        ipad[i] = 0x36 ^ kb[i]; opad[i] = 0x5c ^ kb[i]
    var le = InlineArray[UInt8, 8](fill=0)
    var v = UInt64(root_off)
    for i in range(8):
        le[i] = UInt8((v >> UInt64(i * 8)) & 0xFF)
    var inner = Sha256()
    inner.update(Span(ipad)); inner.update(Span(le)); inner.update(body)
    var ih = inner.finalize()
    var outer = Sha256(); outer.update(Span(opad)); outer.update(Span(ih))
    var fh = outer.finalize()
    var out = List[UInt8](unsafe_uninit_length=32)
    for i in range(32):
        out[i] = fh[i]
    return out^

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
    def gate(hdr: Jws, root_off: Int, body: Span[UInt8, ImmutAnyOrigin]) raises:
        # Gate (verify-before-parse): pin algorithm, recompute HMAC.
        if hdr.algorithm != String("HS256"):
            raise Error("GATE (verify-before-parse)|BadAlg")
        var expected = hmac_sha256_preimage(secret, root_off, body)
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
        var sig = hmac_sha256_preimage(SECRET, root_off, Span(body))
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
