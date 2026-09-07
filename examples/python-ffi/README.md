# python-ffi — a Python binding over the Rust codec

Python mints, verifies, and reads the token by calling the compiled Rust codec through a
small C ABI (`ctypes`). The token on the wire is a compact binary graph, not base64url JSON.

## Build + run

```bash
cargo build --release --manifest-path examples/python-ffi/dagr_token_ffi/Cargo.toml
python3 examples/python-ffi/demo.py
```

## API

```python
import dagr_token as dt

tok = dt.mint(secret, exp)              # -> 207-byte token (bytes)
dt.verify(tok, secret, now)             # raises dt.Rejected on any failure
c = dt.open(tok, secret, now)           # verify, then read claims on demand
c.subject; c.audience; c.expires_at     # registered claims
c.scopes[0].value(); len(c.scopes)
c.custom["roles"][0].value()            # freeform custom claim, read pinpoint
```

`verify` checks the signature before any claim is parsed; reads then fetch only the field
requested, so there is no full decode of the token into a dict.

## Benchmark vs PyJWT

Same claims, HS256, 50k reps each (Apple Silicon, Python 3.14, PyJWT 2.13):

| | mint | verify | token size |
|---|--:|--:|--:|
| this (Python → Rust) | ~4.9 µs | ~2.8 µs | **207 B** |
| PyJWT | ~5.7 µs | ~7.3 µs | 365 B |

Verify is **~2.6× faster**, mint **~1.2× faster**, and the token is **43% smaller** than the
equivalent classic HS256 JWT. The bytes are also identical to the Rust, Swift, TypeScript,
Mojo, and Odin examples, so a token minted here verifies unchanged in any of them.

## Files

- `dagr_token_ffi/` — the Rust `cdylib`. C ABI: `dagr_token_mint`, `dagr_token_verify`,
  `dagr_token_get` (field read by path), `dagr_free`.
- `dagr_token.py` — the `ctypes` wrapper (the API above).
- `demo.py` — mint, the five verify outcomes, and the claim reads.
