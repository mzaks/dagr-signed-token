//! CWT / COSE baseline — the *binary* peer of JWT (RFC 8392 CWT carried in an RFC 9052
//! `COSE_Mac0`). Built with a **tuned native stack**: `coset` (RustCrypto COSE) for the
//! envelope, `ciborium` for the CBOR claims, and **`ring`** for HMAC-SHA256 — the *same*
//! crypto the Dagr Rust row uses. So unlike the Python `pycose` row (a reference
//! implementation, whose ns/op reflect its object model, not the format), this is a fair
//! *efficiency* comparison: same crypto, both sides, only the wire format differs.
//! Bench-only (compiled behind `--features bench`).
//!
//! Same claims as the JWT/Dagr tokens. Registered claims use CWT integer keys
//! (iss=1 / sub=2 / aud=3 / exp=4 / iat=6, RFC 8392 §3.1.2); the profile claims
//! (`scopes`/`tenant`/`roles`/`mfa`/`fp`) use text keys.

use ciborium::value::Value;
use coset::{iana, CoseMac0, CoseMac0Builder, HeaderBuilder, TaggedCborSerializable};
use ring::hmac;

const KID: &[u8] = b"hmac-key-2026";

// CBOR-encode the claims set (a map with the mixed int/text keys above).
fn claims_cbor(iat: u64, exp: u64) -> Vec<u8> {
    let claims = Value::Map(vec![
        (Value::from(1u64), Value::from("https://issuer.dagr.one")),
        (Value::from(2u64), Value::from("user-42")),
        (Value::from(3u64), Value::from("dagr-api")),
        (Value::from(4u64), Value::from(exp)),
        (Value::from(6u64), Value::from(iat)),
        (Value::from("scopes"), Value::Array(vec![
            Value::from("read:profile"), Value::from("write:posts")])),
        (Value::from("tenant"), Value::from("acme")),
        (Value::from("roles"), Value::Array(vec![
            Value::from("admin"), Value::from("billing")])),
        (Value::from("mfa"), Value::Bool(true)),
        (Value::from("fp"), Value::from("0xdeadbeef")),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&claims, &mut out).expect("cbor claims");
    out
}

// Mint: alg (HS256) pinned in the *protected* header (so it is covered by the MAC — the
// COSE construction that sidesteps alg-substitution), `kid` in the unprotected header,
// claims as the payload, tag = HMAC-SHA256 over the COSE `MAC_structure`.
pub fn cwt_mint(secret: &[u8], iat: u64, exp: u64) -> Vec<u8> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::HMAC_256_256)
        .build();
    let unprotected = HeaderBuilder::new().key_id(KID.to_vec()).build();
    let mac0 = CoseMac0Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(claims_cbor(iat, exp))
        .create_tag(b"", |data| {
            let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
            hmac::sign(&key, data).as_ref().to_vec()
        })
        .build();
    mac0.to_tagged_vec().expect("cose encode")
}

// Verify-before-use, COSE-style: recompute the tag (constant-time via `ring::hmac::verify`)
// as the GATE, then run the post-verify claim checks (exp/aud) over the trusted payload.
pub fn cwt_verify(token: &[u8], secret: &[u8], now: u64) -> Result<(), ()> {
    let mac0 = CoseMac0::from_tagged_slice(token).map_err(|_| ())?;
    mac0.verify_tag(b"", |tag, data| {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        hmac::verify(&key, data, tag).map_err(|_| ())
    })?;
    let payload = mac0.payload.as_ref().ok_or(())?;
    let claims: Value = ciborium::from_reader(payload.as_slice()).map_err(|_| ())?;
    let map = claims.as_map().ok_or(())?;
    let get = |k: Value| map.iter().find(|(mk, _)| *mk == k).map(|(_, v)| v);
    let exp: i128 = get(Value::from(4u64)).and_then(Value::as_integer).ok_or(())?.into();
    if now as i128 >= exp {
        return Err(());
    }
    if get(Value::from(3u64)).and_then(Value::as_text) != Some("dagr-api") {
        return Err(());
    }
    Ok(())
}
