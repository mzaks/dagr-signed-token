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

try:
    import jwt                              # PyJWT — the classic-JWT baseline
except ImportError:
    sys.stderr.write("  (PyJWT not installed — skipping the python jwt row)\n")
    sys.exit(0)

rn = int(time.time())                      # PyJWT validates exp against the real clock
jc = {"sub": "user-42", "iss": "https://issuer.dagr.one", "aud": "dagr-api",
      "iat": rn, "exp": rn + 3600, "scopes": ["read:profile", "write:posts"],
      "tenant": "acme", "roles": ["admin", "billing"], "mfa": True, "fp": "0xdeadbeef"}
jt = jwt.encode(jc, S, algorithm="HS256"); jb = jt.encode() if isinstance(jt, str) else jt
jm = ns(lambda: jwt.encode(jc, S, algorithm="HS256"))
jv = ns(lambda: jwt.decode(jb, S, algorithms=["HS256"], audience="dagr-api"))
print(f"BENCH python jwt mint={jm} verify={jv} size={len(jb)}")
