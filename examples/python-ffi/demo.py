"""Python mints, verifies, and reads the token through the Rust cdylib (ctypes)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dagr_token as dt

SECRET = b"dagr-signed-token-demo-secret-2026"
NOW = 1_760_000_000
EXP = NOW + 3600

def _show(label, fn):
    try:
        fn(); print(f"  {label:<20} ACCEPT")
    except dt.Rejected as e:
        print(f"  {label:<20} REJECT  {e}")

def main():
    print("== dagr-signed-token — Python (ctypes → Rust cdylib) ==\n")
    tok = dt.mint(SECRET, EXP)
    print(f"Minted token: {len(tok)} bytes  (byte-identical to the other targets)\n")

    print("Verification:")
    _show("valid token",    lambda: dt.verify(tok, SECRET, NOW))
    tampered = bytearray(tok); tampered[-1] ^= 0x01
    _show("tampered body",  lambda: dt.verify(bytes(tampered), SECRET, NOW))
    _show("wrong key",      lambda: dt.verify(tok, b"not-the-secret", NOW))
    _show("alg:none token", lambda: dt.verify(dt.mint(SECRET, EXP, alg="none"), SECRET, NOW))
    _show("expired token",  lambda: dt.verify(dt.mint(SECRET, NOW - 1), SECRET, NOW))

    print("\nClaims (read on demand after verify — only the requested field is decoded):")
    c = dt.open(tok, SECRET, NOW)
    print("  subject          =", c.subject)
    print("  audience         =", c.audience)
    print("  expiresAt        =", c.expires_at)
    print("  scopes[0]        =", c.scopes[0].value(), " (len", len(c.scopes), ")")
    print("  custom.tenant    =", c.custom["tenant"].value())
    print("  custom.roles[0]  =", c.custom["roles"][0].value(), " (len", len(c.custom["roles"]), ")")
    print("  custom.roles[1]  =", c.custom["roles"][1].value())
    print("  custom.mfa       =", c.custom["mfa"].value())
    print("  custom.fp        = 0x" + c.custom["fp"].value().hex())

    # correctness gates
    assert len(tok) == 207, f"expected 207 bytes, got {len(tok)}"
    assert c.subject == "user-42" and c.expires_at == EXP
    assert c.custom["roles"][0].value() == "admin" and len(c.custom["roles"]) == 2
    assert c.custom["mfa"].value() is True
    assert c.custom["fp"].value() == bytes([0xDE, 0xAD, 0xBE, 0xEF])
    print("\nOK — 207 bytes, verified, path reads correct.")

if __name__ == "__main__":
    main()
