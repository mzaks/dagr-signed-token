"""dagr-signed-token — pure-Python example. Mints and verifies the shared token (see
../../CONTRACT.md). The codec is the generated pure-Python target (gen/python, which ships
its own copy of the Dagr runtime): `to_bytes_with_header` writes the token, and
`from_bytes_with_header` runs the gate before the body is decoded. HMAC-SHA256 is the
standard library's. (examples/python-ffi is the other Python route: the Rust codec over ctypes.)

CLI:  python3 demo.py             → run the showcase (mint, verify, tamper, alg:none, expiry)
      python3 demo.py emit   PATH → write a valid token to PATH
      python3 demo.py verify PATH → verify+decode a token minted by any language
      python3 demo.py bench       → mint + verify, ns/op (for run_bench.sh)
"""
import hashlib
import hmac
import importlib.util
import os
import struct
import sys
import time
import token as _stdlib_token  # noqa: F401  load the standard library's `token` (and `tokenize`)
import tokenize  # noqa: F401  first: the generated module below is also a `token.py`

GEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "gen", "python")
sys.path.insert(0, GEN)  # the generated runtime (`dagr`) and schema (`dagr_schema`)
# The graph is `Token`, so the generated module is `token.py`, the name of a standard-library
# module; load it under another name rather than shadow `token` for the rest of the program.
_spec = importlib.util.spec_from_file_location("dst_token", os.path.join(GEN, "token.py"))
tok = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tok)

from dagr.runtime.dagr_reader import read_leb  # noqa: E402

SECRET = b"dagr-signed-token-demo-secret-2026"
KID = "hmac-key-2026"
NOW = 1_760_000_000
EXP = NOW + 3600


def preimage(root_offset: int, body: bytes) -> bytes:
    """preimage(rootOffset, body) = LE_u64(rootOffset) ++ body  (see CONTRACT.md)."""
    return struct.pack("<Q", root_offset) + bytes(body)


def mint(key: bytes, alg: str, exp: int) -> bytes:
    # custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }
    custom = tok.Json.object([
        tok.JsonMember("tenant", tok.Json.string("acme")),
        tok.JsonMember("roles", tok.Json.array([tok.Json.string("admin"), tok.Json.string("billing")])),
        tok.JsonMember("mfa", tok.Json.bool(True)),
        tok.JsonMember("fp", tok.Json.data(bytes([0xDE, 0xAD, 0xBE, 0xEF]))),
    ])
    claims = tok.Claims(
        subject="user-42",
        issuer="https://issuer.dagr.one",
        audience="dagr-api",
        issued_at=NOW,
        expires_at=exp,
        scopes=["read:profile", "write:posts"],
        custom=custom,
    )

    def header(root_offset, body):
        return {"algorithm": alg, "keyId": KID,
                "signature": hmac.new(key, preimage(root_offset, body), hashlib.sha256).digest()}

    return tok.to_bytes_with_header(claims, header)


class Rejected(Exception):
    STAGE = {"BadAlg": "GATE (verify-before-parse)", "BadSignature": "GATE (verify-before-parse)"}

    @property
    def stage(self):
        return self.STAGE.get(self.args[0], "post-decode claim check")


def verify(token: bytes, key: bytes, now: int):
    """The gate checks the header before the body is decoded; then the claims are checked
    over the now-trusted body. Returns the claims, or raises Rejected."""
    def gate(h, root_offset, body):
        if h.get("algorithm") != "HS256":
            raise Rejected("BadAlg")
        want = hmac.new(key, preimage(root_offset, body), hashlib.sha256).digest()
        if not hmac.compare_digest(bytes(h.get("signature") or b""), want):
            raise Rejected("BadSignature")

    try:
        c = tok.from_bytes_with_header(token, gate)
    except Rejected:
        raise
    except Exception:
        raise Rejected("BadSignature")
    if now >= c.expires_at:
        raise Rejected("Expired")
    if c.audience != "dagr-api":
        raise Rejected("WrongAudience")
    return c


def quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def json_str(j) -> str:
    if j.tag == "string":
        return quote(j.value)
    if j.tag == "number":
        return str(int(j.value)) if float(j.value).is_integer() else repr(j.value)
    if j.tag == "bool":
        return "true" if j.value else "false"
    if j.tag == "array":
        return "[" + ",".join("null" if e is None else json_str(e) for e in j.value) + "]"
    if j.tag == "object":
        return "{" + ",".join(quote(m.key) + ":" + ("null" if m.value is None else json_str(m.value))
                              for m in j.value) + "}"
    if j.tag == "data":
        return "0x" + bytes(j.value).hex()
    return "?"


def report(label: str, token: bytes, key: bytes):
    try:
        c = verify(token, key, NOW)
    except Rejected as r:
        print(f"  {label:<20} REJECT  [{r.stage}] {r.args[0]}")
        return False
    custom = json_str(c.custom) if c.custom is not None else "-"
    print(f"  {label:<20} ACCEPT  sub={quote(c.subject or '')} custom={custom}")
    return True


def body_start(token: bytes) -> int:
    _framing, fl = read_leb(memoryview(token), 0)
    size, sl = read_leb(memoryview(token), fl)
    return fl + sl + size


def time_ns(iters: int, f) -> int:
    for _ in range(max(iters // 10, 1)):
        f()
    t = time.perf_counter_ns()
    for _ in range(iters):
        f()
    return (time.perf_counter_ns() - t) // iters


def bench(iters: int = 5_000):
    """mint (to_bytes_with_header + HMAC) and verify (gate + full restore: the pure-Python target
    is eager only), correctness-gated first. Fewer reps than the compiled languages' 50k: a
    pure-Python call takes tens of microseconds, and 5k reps already give a stable mean."""
    tok = mint(SECRET, "HS256", EXP)
    verify(tok, SECRET, NOW)
    try:
        verify(mint(SECRET, "HS256", NOW - 1), SECRET, NOW)
        raise SystemExit("bench: correctness gate failed")
    except Rejected:
        pass
    m = time_ns(iters, lambda: mint(SECRET, "HS256", EXP))
    v = time_ns(iters, lambda: verify(tok, SECRET, NOW))
    print(f"BENCH py-pure dagr mint={m} verify={v} size={len(tok)}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "bench":
        bench()
        return 0
    if len(sys.argv) > 2 and sys.argv[1] == "emit":
        with open(sys.argv[2], "wb") as f:
            f.write(mint(SECRET, "HS256", EXP))
        print(f"[python] emitted -> {sys.argv[2]}")
        return 0
    if len(sys.argv) > 2 and sys.argv[1] == "verify":
        with open(sys.argv[2], "rb") as f:
            data = f.read()
        return 0 if report(f"[python] {sys.argv[2]}", data, SECRET) else 1

    print("== dagr-signed-token — Python ==\n")
    token = mint(SECRET, "HS256", EXP)
    print(f"Minted token: {len(token)} bytes\n")
    print("Verification:")
    report("valid token", token, SECRET)
    tampered = bytearray(token)
    tampered[body_start(token)] ^= 0x01
    report("tampered body", bytes(tampered), SECRET)
    report("wrong key", token, b"not-the-secret")
    report("alg:none token", mint(SECRET, "none", EXP), SECRET)
    report("expired token", mint(SECRET, "HS256", NOW - 1), SECRET)
    return 0


if __name__ == "__main__":
    sys.exit(main())
