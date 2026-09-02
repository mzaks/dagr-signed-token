//! dagr-web-token — Rust example. Mints and verifies the shared token (see
//! ../../CONTRACT.md). The codec is the generated `dagr_web_token` crate; the
//! crypto is the hand-rolled, NIST/RFC-4231-validated SHA-256/HMAC in sha256.rs.
//!
//! CLI:  dwt            → run the showcase (mint, verify, tamper, alg:none, expiry)
//!       dwt emit  PATH → write a valid token to PATH
//!       dwt verify PATH → verify+decode a token minted by any language

mod sha256;

use dagr_web_token::dagr_runtime::DagrError;
use dagr_web_token::token::{Json, Jws, TokenArena, TokenGraph};
use sha256::{ct_eq, hmac_sha256};

const SECRET: &[u8] = b"dagr-web-token-demo-secret-2026";
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
    // custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true }
    let custom = Json::Object(vec![
        a.new_json_member("tenant", Some(Json::String("acme".into()))),
        a.new_json_member("roles", Some(Json::Array(vec![
            Some(Json::String("admin".into())),
            Some(Json::String("billing".into())),
        ]))),
        a.new_json_member("mfa", Some(Json::Bool(true))),
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

fn verify(token: &[u8], secret: &[u8], now: u64) -> Result<TokenArena<0>, Rejected> {
    let reason = std::cell::Cell::new(None);
    let decoded = TokenArena::<0>::from_bytes_with_header(token, |h, root_offset, body| {
        if h.algorithm != "HS256" { reason.set(Some(Rejected::BadAlg)); return Err(DagrError::InvalidData); }
        let expected = hmac_sha256(secret, &preimage(root_offset, body));
        if !ct_eq(&h.signature, &expected) { reason.set(Some(Rejected::BadSignature)); return Err(DagrError::InvalidData); }
        Ok(())
    });
    let arena = match decoded { Ok(a) => a, Err(_) => return Err(reason.take().unwrap_or(Rejected::BadSignature)) };
    let c = arena.get_root().expect("root");
    if now >= c.expires_at() { return Err(Rejected::Expired); }
    if c.audience().as_deref() != Some("dagr-api") { return Err(Rejected::WrongAudience); }
    Ok(arena)
}

fn json_str<G: TokenGraph>(j: &Json<G>) -> String {
    match j {
        Json::String(s) => format!("{:?}", s),
        Json::Number(n) => format!("{}", n),
        Json::Bool(b) => format!("{}", b),
        Json::Array(a) => format!("[{}]", a.iter().map(|e| e.as_ref().map(json_str).unwrap_or_else(|| "null".into())).collect::<Vec<_>>().join(",")),
        Json::Object(o) => format!("{{{}}}", o.iter().map(|m| format!("{:?}:{}", m.key(), m.value().map(|v| json_str(&v)).unwrap_or_else(|| "null".into()))).collect::<Vec<_>>().join(",")),
        Json::Unknown(_) => "?".into(),
    }
}

fn report(label: &str, r: &Result<TokenArena<0>, Rejected>) {
    match r {
        Ok(a) => {
            let c = a.get_root().unwrap();
            println!("  {label:<20} ACCEPT  sub={:?} custom={}",
                     c.subject().unwrap_or_default(), c.custom().map(|j| json_str(&j)).unwrap_or_else(|| "-".into()));
        }
        Err(e) => println!("  {label:<20} REJECT  [{}] {:?}", e.stage(), e),
    }
}

fn body_start(data: &[u8]) -> usize {
    let (_f, rl) = dagr_web_token::dagr_runtime::read_leb(data, 0).unwrap();
    let (hcs, hcsb) = dagr_web_token::dagr_runtime::read_leb(data, rl).unwrap();
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
            report(&format!("[rust] {}", args[2]), &r);
            std::process::exit(if r.is_ok() { 0 } else { 1 });
        }
        _ => {}
    }

    println!("== dagr-web-token — Rust ==\n");
    let token = mint(SECRET, "HS256", EXP);
    println!("Minted token: {} bytes\n", token.len());
    println!("Verification:");
    report("valid token", &verify(&token, SECRET, NOW));
    let mut tampered = token.clone();
    let bs = body_start(&tampered);
    tampered[bs] ^= 0x01;
    report("tampered body", &verify(&tampered, SECRET, NOW));
    report("wrong key", &verify(&token, b"not-the-secret", NOW));
    report("alg:none token", &verify(&mint(SECRET, "none", EXP), SECRET, NOW));
    report("expired token", &verify(&mint(SECRET, "HS256", NOW - 1), SECRET, NOW));
}
