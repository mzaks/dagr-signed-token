//! Classic JWT baseline via the **`jsonwebtoken`** crate — the standard Rust JWT
//! library, so this is a *proper* real-world comparison: serde-derived claims, its
//! own header + base64url + signature handling, and full validation on decode
//! (signature + `exp` + `aud`). Bench-only (compiled behind `--features bench`).
//!
//! NOTE: `jsonwebtoken` validates `exp` against the real wall clock (there's no
//! injectable "now"), so the bench mints the valid token with a `now + 1h` exp while
//! the Dagr token keeps its fixed demo timestamps. jsonwebtoken's crypto backend is
//! its own (ring), vs Dagr's RustCrypto `hmac`+`sha2` — both production-grade native
//! implementations; the format + serde overhead is what the delta actually measures.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    scopes: Vec<String>,
    tenant: String,
    roles: Vec<String>,
    mfa: bool,
    fp: String,
}

fn claims(exp: u64) -> Claims {
    Claims {
        sub: "user-42".into(),
        iss: "https://issuer.dagr.one".into(),
        aud: "dagr-api".into(),
        iat: 1_760_000_000,
        exp,
        scopes: vec!["read:profile".into(), "write:posts".into()],
        tenant: "acme".into(),
        roles: vec!["admin".into(), "billing".into()],
        mfa: true,
        fp: "0xdeadbeef".into(),
    }
}

/// Current-timestamp helper (jsonwebtoken validates `exp` against wall-clock).
pub fn now() -> u64 {
    jsonwebtoken::get_current_timestamp()
}

pub fn jwt_mint(secret: &[u8], exp: u64) -> Vec<u8> {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("hmac-key-2026".into());
    encode(&header, &claims(exp), &EncodingKey::from_secret(secret))
        .expect("jwt encode")
        .into_bytes()
}

pub fn jwt_verify(token: &[u8], secret: &[u8]) -> Result<(), jsonwebtoken::errors::Error> {
    let mut v = Validation::new(Algorithm::HS256); // validates signature + exp by default
    v.set_audience(&["dagr-api"]);
    let s = match std::str::from_utf8(token) {
        Ok(s) => s,
        Err(_) => return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into()),
    };
    decode::<Claims>(s, &DecodingKey::from_secret(secret), &v).map(|_| ())
}
