//! A minimal classic **JWS/JWT** (HS256) for the benchmark's apples-to-apples
//! comparison — same claims, same HMAC-SHA256, same runtime as the Dagr token, so
//! the delta isolates the *format* (compact base64url JSON `header.payload.sig`
//! vs Dagr's binary graph). Hand-rolled + zero-dependency, matching the demo.
//!
//! NOT a hardened JWT library. `verify` recomputes the MAC then does a light,
//! payload-shape-specific scan for `exp`/`aud` (a real lib would `serde_json`-parse
//! the whole payload — strictly MORE work, so this is conservative toward JWT).

use crate::sha256::{ct_eq, hmac_sha256};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 { out.push(B64[(n >> 6 & 63) as usize] as char); }
        if chunk.len() > 2 { out.push(B64[(n & 63) as usize] as char); }
    }
    out // no '=' padding (base64url, RFC 7515 §2)
}

fn b64url_decode(s: &[u8]) -> Vec<u8> {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'-' => 62, b'_' => 63,
            _ => 0,
        }
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() { n |= val(c) << (18 - 6 * i); }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    out
}

/// Mint the same claim set the Dagr token carries, as a compact HS256 JWT string.
pub fn jwt_mint(secret: &[u8], alg: &str, exp: u64) -> Vec<u8> {
    let header = format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"hmac-key-2026"}}"#);
    let payload = format!(
        r#"{{"sub":"user-42","iss":"https://issuer.dagr.one","aud":"dagr-api","iat":1760000000,"exp":{exp},"scopes":["read:profile","write:posts"],"tenant":"acme","roles":["admin","billing"],"mfa":true,"fp":"0xdeadbeef"}}"#
    );
    let signing_input = format!("{}.{}", b64url_encode(header.as_bytes()), b64url_encode(payload.as_bytes()));
    let sig = hmac_sha256(secret, signing_input.as_bytes());
    format!("{signing_input}.{}", b64url_encode(&sig)).into_bytes()
}

/// Verify-before-use: recompute the MAC over `header.payload`, constant-time compare,
/// then decode the payload and check `alg`/`exp`/`aud`. Returns Ok on accept.
pub fn jwt_verify(token: &[u8], secret: &[u8], now: u64) -> Result<(), &'static str> {
    let dot2 = token.iter().rposition(|&b| b == b'.').ok_or("malformed")?;
    let signing_input = &token[..dot2];
    let sig = b64url_decode(&token[dot2 + 1..]);
    let expected = hmac_sha256(secret, signing_input);
    if !ct_eq(&sig, &expected) { return Err("BadSignature"); }
    // Now decode header + payload (the work Dagr's binary body avoids).
    let dot1 = signing_input.iter().position(|&b| b == b'.').ok_or("malformed")?;
    let header = b64url_decode(&signing_input[..dot1]);
    if !find_str(&header, b"\"alg\":\"").is_some_and(|v| v == b"HS256") { return Err("BadAlg"); }
    let payload = b64url_decode(&signing_input[dot1 + 1..]);
    let exp: u64 = find_str(&payload, b"\"exp\":")
        .and_then(|d| std::str::from_utf8(d).ok()).and_then(|s| s.parse().ok()).ok_or("malformed")?;
    if now >= exp { return Err("Expired"); }
    if find_str(&payload, b"\"aud\":\"") != Some(b"dagr-api") { return Err("WrongAudience"); }
    Ok(())
}

/// Read the token value following `key` — a quoted string (stops at `"`) or a bare
/// number (stops at `,`/`}`). Enough for the fixed benchmark payload.
fn find_str<'a>(buf: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let start = buf.windows(key.len()).position(|w| w == key)? + key.len();
    let end = buf[start..].iter().position(|&c| c == b'"' || c == b',' || c == b'}')?;
    Some(&buf[start..start + end])
}
