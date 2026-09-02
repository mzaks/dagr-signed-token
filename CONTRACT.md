# The cross-language token contract

Every language example mints the **exact same token**, so the buffers are
byte-for-byte identical and each language can verify the others'. The shared
constants and rules below are the contract — keep them identical across
`examples/rust`, `examples/swift`, `examples/typescript`.

## Constants

| Name | Value |
|---|---|
| `SECRET` (HMAC key) | ASCII `dagr-web-token-demo-secret-2026` |
| `KID` | `hmac-key-2026` |
| `NOW` (issuedAt) | `1760000000` (unix seconds) |
| `EXP` (expiresAt) | `NOW + 3600` = `1760003600` |

## Claims (the body)

```
subject   = "user-42"
issuer    = "https://issuer.dagr.one"
audience  = "dagr-api"
issuedAt  = 1760000000
expiresAt = 1760003600
scopes    = ["read:profile", "write:posts"]
custom    = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true }
```

## Header (`Jws`)

```
algorithm = "HS256"
keyId     = "hmac-key-2026"
signature = HMAC-SHA256(SECRET, preimage(rootOffset, body))
```

## Preimage

`preimage(rootOffset, body) = LE_u64(rootOffset) ++ body`

The 8-byte little-endian root offset, followed by the body bytes. Dagr hands the
signing/verify closure the body and the root offset *as a value*; the body is
position-independent, so this preimage is stable regardless of the header length.

## Verifier policy

- Gate (runs before the body is parsed): `algorithm == "HS256"` and the recomputed
  HMAC matches (constant-time). Reject → `BadAlg` / `BadSignature`.
- Post-decode (over the now-trusted body): `now < expiresAt` and `audience == "dagr-api"`.
  Reject → `Expired` / `WrongAudience`.
