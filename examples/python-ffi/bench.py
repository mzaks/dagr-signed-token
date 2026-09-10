"""Emit BENCH lines for run_bench.sh: this ctypes-over-Rust binding, and (if PyJWT is
installed) an equivalent classic HS256 JWT with the same claims."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dagr_token as dt

S = "dagr-signed-token-demo-secret-2026"; SB = S.encode()
NOW = 1_760_000_000; EXP = NOW + 3600

def ns(f, n=50000):
    for _ in range(n // 10): f()          # warmup
    t = time.perf_counter_ns()
    for _ in range(n): f()
    return (time.perf_counter_ns() - t) // n

dtok = dt.mint(SB, EXP)
assert len(dtok) == 207
dt.verify(dtok, SB, NOW)                   # correctness gate
dm = ns(lambda: dt.mint(SB, EXP))
dv = ns(lambda: dt.verify(dtok, SB, NOW))
print(f"BENCH python dagr mint={dm} verify={dv} size={len(dtok)}")

rn = int(time.time())                      # baselines validate exp against the real clock

# --- PyJWT baseline: the classic base64url-JSON HS256 JWT, same claims -----------------
try:
    import jwt                              # PyJWT
    jc = {"sub": "user-42", "iss": "https://issuer.dagr.one", "aud": "dagr-api",
          "iat": rn, "exp": rn + 3600, "scopes": ["read:profile", "write:posts"],
          "tenant": "acme", "roles": ["admin", "billing"], "mfa": True, "fp": "0xdeadbeef"}
    jt = jwt.encode(jc, S, algorithm="HS256"); jb = jt.encode() if isinstance(jt, str) else jt
    jm = ns(lambda: jwt.encode(jc, S, algorithm="HS256"))
    jv = ns(lambda: jwt.decode(jb, S, algorithms=["HS256"], audience="dagr-api"))
    print(f"BENCH python jwt mint={jm} verify={jv} size={len(jb)}")
except ImportError:
    sys.stderr.write("  (PyJWT not installed — skipping the python jwt row)\n")

# --- CWT / COSE baseline: the *binary* peer of JWT (RFC 8392 / RFC 9052) ----------------
# The honest comparison — CBOR is already compact, so this is where Dagr's size win over
# base64url JSON mostly evaporates. A standards-exact COSE_Mac0 (HMAC 256/256) built by the
# real `pycose` library: registered claims use integer keys (iss=1/sub=2/aud=3/exp=4/iat=6,
# RFC 8392 §3.1.2), profile claims use text keys — same values as the PyJWT row. Note pycose
# is a *reference* implementation (Python object model per COSE element), not a tuned codec,
# so its ns/op reflect the library, not the format; the size column is the load-bearing one.
# pycose caps a symmetric HMAC-256 key at 32 bytes, so we derive one from the shared secret
# (this token is a size/speed peer, not cross-verified against the Dagr/JWT tokens).
try:
    import hashlib, cbor2
    from pycose.messages import Mac0Message
    from pycose.keys import CoseKey
    from pycose.keys.keyparam import KpKty, KpAlg, KpKeyOps, SymKpK
    from pycose.keys.keytype import KtySymmetric
    from pycose.keys.keyops import MacCreateOp, MacVerifyOp
    from pycose.headers import Algorithm, KID
    from pycose.algorithms import HMAC256

    ckey = CoseKey.from_dict({KpKty: KtySymmetric, SymKpK: hashlib.sha256(SB).digest(),
                              KpAlg: HMAC256, KpKeyOps: [MacCreateOp, MacVerifyOp]})
    cc = {1: "https://issuer.dagr.one", 2: "user-42", 3: "dagr-api", 4: rn + 3600, 6: rn,
          "scopes": ["read:profile", "write:posts"], "tenant": "acme",
          "roles": ["admin", "billing"], "mfa": True, "fp": "0xdeadbeef"}

    def cwt_mint():
        m = Mac0Message(phdr={Algorithm: HMAC256}, uhdr={KID: b"hmac-key-2026"},
                        payload=cbor2.dumps(cc))
        m.key = ckey
        return m.encode(tag=True)

    def cwt_verify(buf):
        m = Mac0Message.decode(buf)         # runs the tag check below, then read the claims
        m.key = ckey
        if not m.verify_tag():
            raise ValueError("bad tag")
        claims = cbor2.loads(m.payload)     # post-verify claim checks (exp/aud), over trusted body
        if not (claims.get(3) == "dagr-api" and rn < claims.get(4, 0)):
            raise ValueError("claim check failed")
        return claims

    cb = cwt_mint(); cwt_verify(cb)         # correctness gate
    cm = ns(cwt_mint)
    cv = ns(lambda: cwt_verify(cb))
    print(f"BENCH python cwt mint={cm} verify={cv} size={len(cb)}")
except ImportError:
    sys.stderr.write("  (pycose/cbor2 not installed — skipping the python cwt row)\n")
