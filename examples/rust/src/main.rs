//! dagr-signed-token — Rust example. Mints and verifies the shared token (see
//! ../../CONTRACT.md). The codec is the generated `dagr_signed_token` crate; the
//! crypto is the hand-rolled, NIST/RFC-4231-validated SHA-256/HMAC in sha256.rs.
//!
//! CLI:  dst            → run the showcase (mint, verify, tamper, alg:none, expiry)
//!       dst emit  PATH → write a valid token to PATH
//!       dst verify PATH → verify+decode a token minted by any language

mod sha256;

use dagr_signed_token::dagr_runtime::DagrError;
use dagr_signed_token::token::{Json, Jws, TokenArena, TokenGraph};
use dagr_signed_token::token_lazy::{self, JsonPackedArrayAccessor};
use sha256::{ct_eq, hmac_sha256};

const SECRET: &[u8] = b"dagr-signed-token-demo-secret-2026";
const KID: &str = "hmac-key-2026";
const NOW: u64 = 1_760_000_000;
const EXP: u64 = NOW + 3600;

/// preimage(rootOffset, body) = LE_u64(rootOffset) ++ body  (see CONTRACT.md).
fn preimage(root_offset: usize, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + body.len());
    m.extend_from_slice(&(root_offset as u64).to_le_bytes());
    m.extend_from_slice(body);
    m
}

fn mint(secret: &[u8], alg: &str, exp: u64) -> Vec<u8> {
    let a = TokenArena::<0>::new();
    // custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }
    let custom = Json::Object(vec![
        a.new_json_member("tenant", Some(Json::String("acme".into()))),
        a.new_json_member("roles", Some(Json::Array(vec![
            Some(Json::String("admin".into())),
            Some(Json::String("billing".into())),
        ]))),
        a.new_json_member("mfa", Some(Json::Bool(true))),
        a.new_json_member("fp", Some(Json::Data(vec![0xDE, 0xAD, 0xBE, 0xEF]))),
    ]);
    a.set_root(Some(a.new_claims(
        Some("user-42"),
        Some("https://issuer.dagr.one"),
        Some("dagr-api"),
        NOW,
        exp,
        vec!["read:profile".into(), "write:posts".into()],
        Some(custom),
    )));
    a.to_bytes_with_header(|root_offset, body| Jws {
        algorithm: alg.into(),
        keyId: Some(KID.into()),
        signature: hmac_sha256(secret, &preimage(root_offset, body)).to_vec(),
    })
    .expect("mint")
}

/// Direct Graph Builder ("31 Direct Graph Builder.md"): mint the SAME token from a
/// plain value tree, arena-free. Must be byte-identical to `mint` — see the
/// `direct_equals_arena` test below (spec §6 gate). Exercised only by that test, so
/// it reads as dead code in the CLI (non-test) build.
#[cfg_attr(not(test), allow(dead_code))]
fn mint_direct(secret: &[u8], alg: &str, exp: u64) -> Vec<u8> {
    use dagr_signed_token::token::{direct, Token};
    // custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }
    let custom = direct::Json::Object(vec![
        direct::JsonMember { key: "tenant".into(), value: Some(direct::Json::String("acme".into())) },
        direct::JsonMember { key: "roles".into(), value: Some(direct::Json::Array(vec![
            Some(Box::new(direct::Json::String("admin".into()))),
            Some(Box::new(direct::Json::String("billing".into()))),
        ])) },
        direct::JsonMember { key: "mfa".into(), value: Some(direct::Json::Bool(true)) },
        direct::JsonMember { key: "fp".into(), value: Some(direct::Json::Data(vec![0xDE, 0xAD, 0xBE, 0xEF])) },
    ]);
    let claims = direct::Claims {
        subject: Some("user-42".into()),
        issuer: Some("https://issuer.dagr.one".into()),
        audience: Some("dagr-api".into()),
        issued_at: NOW,
        expires_at: exp,
        scopes: vec!["read:profile".into(), "write:posts".into()],
        custom: Some(custom),
    };
    Token::to_bytes_with_header(&claims, |root_offset, body| Jws {
        algorithm: alg.into(),
        keyId: Some(KID.into()),
        signature: hmac_sha256(secret, &preimage(root_offset, body)).to_vec(),
    })
    .expect("mint direct")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_equals_arena() {
        // Spec 31 §6: the arena-free direct builder is byte-for-byte identical.
        let a = mint(SECRET, "HS256", EXP);
        let d = mint_direct(SECRET, "HS256", EXP);
        assert_eq!(a, d, "direct builder diverged from arena ({} vs {} bytes)", a.len(), d.len());
        assert_eq!(d.len(), 207, "expected the 207-byte reference token");
    }
}

#[derive(Debug)]
enum Rejected { BadAlg, BadSignature, Expired, WrongAudience }
impl Rejected {
    fn stage(&self) -> &'static str {
        match self {
            Rejected::BadAlg | Rejected::BadSignature => "GATE (verify-before-parse)",
            _ => "post-decode claim check",
        }
    }
}

// Verify-before-parse, then read claims with ZERO-ALLOC LAZY ACCESSORS — no arena restore.
// `read_root_with_header` runs the crypto GATE (below) before returning a `ClaimsAccessor`
// that reads fields straight off the token buffer on demand.
fn verify(token: &[u8], secret: &[u8], now: u64) -> Result<(), Rejected> {
    let reason = std::cell::Cell::new(None);
    let root = token_lazy::read_root_with_header(token, |h, root_offset, body| {
        if h.algorithm != "HS256" { reason.set(Some(Rejected::BadAlg)); return Err(DagrError::InvalidData); }
        let expected = hmac_sha256(secret, &preimage(root_offset, body));
        if !ct_eq(&h.signature, &expected) { reason.set(Some(Rejected::BadSignature)); return Err(DagrError::InvalidData); }
        Ok(())
    });
    let c = match root { Ok(c) => c, Err(_) => return Err(reason.take().unwrap_or(Rejected::BadSignature)) };
    // Post-decode claim checks — lazy reads, still no owned graph.
    if now >= c.expires_at().map_err(|_| Rejected::Expired)? { return Err(Rejected::Expired); }
    if c.audience() != Some("dagr-api") { return Err(Rejected::WrongAudience); }
    Ok(())
}

// Lazy render of the packed-JSON `custom` claim — walks the buffer, no owned graph.
fn json_str_lazy(j: &JsonPackedArrayAccessor) -> String {
    match j {
        JsonPackedArrayAccessor::String(s) => format!("{:?}", s.as_deref().unwrap_or("")),
        JsonPackedArrayAccessor::Number(n) => format!("{}", n),
        JsonPackedArrayAccessor::Bool(b) => format!("{}", b),
        JsonPackedArrayAccessor::Array(a) => format!("[{}]",
            a.iter().map(|e| e.ok().flatten().map(|v| json_str_lazy(&v)).unwrap_or_else(|| "null".into()))
                .collect::<Vec<_>>().join(",")),
        JsonPackedArrayAccessor::Object(o) => format!("{{{}}}",
            o.iter().map(|m| m.map(|m| format!("{:?}:{}", m.key().unwrap_or(""),
                m.value().map(|v| json_str_lazy(&v)).unwrap_or_else(|| "null".into()))).unwrap_or_default())
                .collect::<Vec<_>>().join(",")),
        JsonPackedArrayAccessor::Data(d) => format!("0x{}", d.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        JsonPackedArrayAccessor::Unknown(_) => "?".into(),
    }
}

fn report(label: &str, token: &[u8], r: &Result<(), Rejected>) {
    match r {
        Ok(()) => {
            // Already verified — re-open lazily (no-op gate) purely to render; still arena-free.
            let c = token_lazy::read_root_with_header(token, |_, _, _| Ok(())).expect("root");
            println!("  {label:<20} ACCEPT  sub={:?} custom={}",
                     c.subject().unwrap_or_default(),
                     c.custom().map(|j| json_str_lazy(&j)).unwrap_or_else(|| "-".into()));
        }
        Err(e) => println!("  {label:<20} REJECT  [{}] {:?}", e.stage(), e),
    }
}

fn body_start(data: &[u8]) -> usize {
    let (_f, rl) = dagr_signed_token::dagr_runtime::read_leb(data, 0).unwrap();
    let (hcs, hcsb) = dagr_signed_token::dagr_runtime::read_leb(data, rl).unwrap();
    rl + hcsb + hcs as usize
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("emit") => {
            std::fs::write(&args[2], mint(SECRET, "HS256", EXP)).expect("write");
            println!("[rust] emitted -> {}", args[2]);
            return;
        }
        Some("verify") => {
            let data = std::fs::read(&args[2]).expect("read");
            let r = verify(&data, SECRET, NOW);
            report(&format!("[rust] {}", args[2]), &data, &r);
            std::process::exit(if r.is_ok() { 0 } else { 1 });
        }
        _ => {}
    }

    println!("== dagr-signed-token — Rust ==\n");
    let token = mint(SECRET, "HS256", EXP);
    println!("Minted token: {} bytes\n", token.len());
    println!("Verification:");
    report("valid token", &token, &verify(&token, SECRET, NOW));
    let mut tampered = token.clone();
    let bs = body_start(&tampered);
    tampered[bs] ^= 0x01;
    report("tampered body", &tampered, &verify(&tampered, SECRET, NOW));
    report("wrong key", &token, &verify(&token, b"not-the-secret", NOW));
    let none_tok = mint(SECRET, "none", EXP);
    report("alg:none token", &none_tok, &verify(&none_tok, SECRET, NOW));
    let expired_tok = mint(SECRET, "HS256", NOW - 1);
    report("expired token", &expired_tok, &verify(&expired_tok, SECRET, NOW));
}
