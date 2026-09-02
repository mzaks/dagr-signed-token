#!/usr/bin/env python3
"""dagr-web-token — Python example (see ../../CONTRACT.md).

Codec is the generated pure-Python module in gen/python (reflective Fork A); crypto
is the standard-library `hmac`/`hashlib` — no third-party dependencies.

    python3 demo.py             → showcase
    python3 demo.py emit  PATH  → write a valid token
    python3 demo.py verify PATH → verify+decode a token minted by any language
"""
import hashlib
import hmac
import importlib.util
import os
import sys

# The generated module is gen/python/token.py — but `token` is also a Python STDLIB
# module (used by dataclasses/tokenize), so we must NOT shadow it. Keep gen/python at
# the END of sys.path (so stdlib wins) and load token.py by file path under a private
# name; its own siblings (dagr_py, dagr_schema, …) still resolve from gen/python.
_GEN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "gen", "python"))
sys.path.append(_GEN)
_spec = importlib.util.spec_from_file_location("dwt_token", os.path.join(_GEN, "token.py"))
_wt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _wt   # dataclasses resolves annotations via sys.modules[cls.__module__]
_spec.loader.exec_module(_wt)
Claims, JsonMember, Json = _wt.Claims, _wt.JsonMember, _wt.Json
to_bytes_with_header, from_bytes_with_header = _wt.to_bytes_with_header, _wt.from_bytes_with_header

SECRET = b"dagr-web-token-demo-secret-2026"
KID = "hmac-key-2026"
NOW = 1_760_000_000
EXP = NOW + 3600


def preimage(root_offset: int, body: bytes) -> bytes:
    # preimage(rootOffset, body) = LE_u64(rootOffset) ++ body  (see CONTRACT.md)
    return root_offset.to_bytes(8, "little") + body


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def mint(secret: bytes, alg: str, exp: int) -> bytes:
    # custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true }
    custom = Json.object([
        JsonMember("tenant", Json.string("acme")),
        JsonMember("roles", Json.array([Json.string("admin"), Json.string("billing")])),
        JsonMember("mfa", Json.bool(True)),
    ])
    root = Claims(
        subject="user-42",
        issuer="https://issuer.dagr.one",
        audience="dagr-api",
        issuedAt=NOW,
        expiresAt=exp,
        scopes=["read:profile", "write:posts"],
        custom=custom,
    )
    return to_bytes_with_header(
        root,
        lambda root_offset, body: {
            "algorithm": alg,
            "keyId": KID,
            "signature": hmac_sha256(secret, preimage(root_offset, body)),
        },
    )


class Rejected(Exception):
    def __init__(self, reason, stage):
        super().__init__(reason)
        self.reason, self.stage = reason, stage


def verify(token: bytes, secret: bytes, now: int) -> Claims:
    def gate(header, root_offset, body):
        if header.get("algorithm") != "HS256":
            raise Rejected("BadAlg", "GATE (verify-before-parse)")
        expected = hmac_sha256(secret, preimage(root_offset, body))
        got = header.get("signature") or b""
        if not hmac.compare_digest(bytes(got), expected):
            raise Rejected("BadSignature", "GATE (verify-before-parse)")

    root = from_bytes_with_header(token, gate)  # raises Rejected before body decode on failure
    if now >= root.expiresAt:
        raise Rejected("Expired", "post-decode claim check")
    if root.audience != "dagr-api":
        raise Rejected("WrongAudience", "post-decode claim check")
    return root


def json_str(j) -> str:
    if j is None:
        return "-"
    if j.tag == "string":
        return '"%s"' % j.value
    if j.tag == "number":
        return str(j.value)
    if j.tag == "bool":
        return "true" if j.value else "false"
    if j.tag == "array":
        return "[" + ",".join(json_str(e) for e in j.value) + "]"
    if j.tag == "object":
        return "{" + ",".join('"%s":%s' % (m.key, json_str(m.value)) for m in j.value) + "}"
    return "?"


def report(label, run):
    try:
        c = run()
        print('  %-20s ACCEPT  sub="%s" custom=%s' % (label, c.subject, json_str(c.custom)))
    except Rejected as e:
        print("  %-20s REJECT  [%s] %s" % (label, e.stage, e.reason))


def main():
    argv = sys.argv
    if len(argv) >= 3 and argv[1] == "emit":
        with open(argv[2], "wb") as f:
            f.write(mint(SECRET, "HS256", EXP))
        print("[python] emitted -> %s" % argv[2])
        return
    if len(argv) >= 3 and argv[1] == "verify":
        with open(argv[2], "rb") as f:
            data = f.read()
        try:
            c = verify(data, SECRET, NOW)
            print('  [python] %s  ACCEPT  sub="%s" custom=%s' % (argv[2], c.subject, json_str(c.custom)))
            sys.exit(0)
        except Rejected as e:
            print("  [python] %s  REJECT  [%s] %s" % (argv[2], e.stage, e.reason))
            sys.exit(1)

    print("== dagr-web-token — Python ==\n")
    token = mint(SECRET, "HS256", EXP)
    print("Minted token: %d bytes\n" % len(token))
    print("Verification:")
    report("valid token", lambda: verify(token, SECRET, NOW))
    tampered = bytearray(token)
    # flip a byte in the body region (past framing + header)
    from dagr_py.dagr_reader import read_leb
    mv = memoryview(bytes(tampered))
    _framing, flen = read_leb(mv, 0)
    hcs, after = read_leb(mv, flen)
    tampered[after + hcs] ^= 0x01
    report("tampered body", lambda: verify(bytes(tampered), SECRET, NOW))
    report("wrong key", lambda: verify(token, b"not-the-secret", NOW))
    report("alg:none token", lambda: verify(mint(SECRET, "none", EXP), SECRET, NOW))
    report("expired token", lambda: verify(mint(SECRET, "HS256", NOW - 1), SECRET, NOW))


if __name__ == "__main__":
    main()
