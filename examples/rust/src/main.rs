//! dagr-signed-token — Rust example. Mints and verifies the shared token (see
//! ../../CONTRACT.md). The codec is the generated `dagr_signed_token` crate; the
//! crypto is the hand-rolled, NIST/RFC-4231-validated SHA-256/HMAC in sha256.rs.
//!
//! CLI:  dst            → run the showcase (mint, verify, tamper, alg:none, expiry)
//!       dst emit  PATH → write a valid token to PATH
//!       dst verify PATH → verify+decode a token minted by any language

mod sha256;
#[cfg(feature = "bench")]
mod jwt;

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
        key_id: Some(KID.into()),
        signature: hmac_sha256(secret, &preimage(root_offset, body)).to_vec(),
    })
    .expect("mint")
}

/// Direct Graph Builder ("31 Direct Graph Builder.md"): mint the SAME token from a
/// plain value tree, arena-free. Must be byte-identical to `mint` — see the
/// `direct_equals_arena` test below (spec §6 gate). Exercised only by that test, so
/// it reads as dead code in the CLI (non-test) build.
// Build the direct value tree (the allocation-heavy part: Strings, Vecs, Boxes).
#[cfg_attr(not(test), allow(dead_code))]
fn build_direct(exp: u64) -> dagr_signed_token::token::direct::Claims<'static> {
    use dagr_signed_token::token::direct;
    // custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }
    // Borrowed value tree from string/slice literals → 'static (rvalue-promoted), ZERO heap
    // allocation to construct; the serializer copies straight from these slices.
    let custom = direct::Json::Object(&[
        direct::JsonMember { key: "tenant", value: Some(direct::Json::String("acme")) },
        direct::JsonMember { key: "roles", value: Some(direct::Json::Array(&[
            Some(direct::Json::String("admin")),
            Some(direct::Json::String("billing")),
        ])) },
        direct::JsonMember { key: "mfa", value: Some(direct::Json::Bool(true)) },
        direct::JsonMember { key: "fp", value: Some(direct::Json::Data(&[0xDE, 0xAD, 0xBE, 0xEF])) },
    ]);
    direct::Claims {
        subject: Some("user-42"),
        issuer: Some("https://issuer.dagr.one"),
        audience: Some("dagr-api"),
        issued_at: NOW,
        expires_at: exp,
        scopes: &["read:profile", "write:posts"],
        custom: Some(custom),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn mint_direct(secret: &[u8], alg: &str, exp: u64) -> Vec<u8> {
    use dagr_signed_token::token::Token;
    Token::to_bytes_with_header(&build_direct(exp), |root_offset, body| Jws {
        algorithm: alg.into(),
        key_id: Some(KID.into()),
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
        // `h` is the zero-alloc header view — algorithm() borrows &str, signature() borrows
        // &[u8] straight from the buffer (no String/Vec), and key_id is never touched.
        if h.algorithm()? != "HS256" { reason.set(Some(Rejected::BadAlg)); return Err(DagrError::InvalidData); }
        let expected = hmac_sha256(secret, &preimage(root_offset, body));
        if !ct_eq(h.signature()?, &expected) { reason.set(Some(Rejected::BadSignature)); return Err(DagrError::InvalidData); }
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

// Time `f` over `iters` reps (after a warmup) → nanoseconds per call.
#[cfg(feature = "bench")]
fn time_ns(iters: u32, mut f: impl FnMut()) -> u128 {
    for _ in 0..(iters / 10).max(1) { f(); }        // warmup
    let t = std::time::Instant::now();
    for _ in 0..iters { f(); }
    t.elapsed().as_nanos() / iters as u128
}

// Mint + verify throughput for the Dagr token (direct build + lazy verify) and a real
// `jsonwebtoken` HS256 JWT with the same claims. Emits `BENCH …` lines for run_bench.sh.
#[cfg(feature = "bench")]
fn bench() {
    let n = 50_000;
    // Dagr: FAST PATH — arena-free direct build (spec 31) + zero-alloc lazy verify.
    let tok = mint_direct(SECRET, "HS256", EXP);
    // JWT: jsonwebtoken validates exp against the real wall clock, so mint valid at now+1h.
    let jtok = jwt::jwt_mint(SECRET, jwt::now() + 3600);
    // Correctness gate: both accept the valid token and reject expired/tampered.
    assert!(verify(&tok, SECRET, NOW).is_ok() && jwt::jwt_verify(&jtok, SECRET).is_ok());
    assert_eq!(tok, mint(SECRET, "HS256", EXP), "direct build must be byte-identical to arena");
    assert!(verify(&mint_direct(SECRET, "HS256", NOW - 1), SECRET, NOW).is_err());
    assert!(jwt::jwt_verify(&jwt::jwt_mint(SECRET, jwt::now() - 3600), SECRET).is_err());  // expired (past 60s leeway)
    let mut bad = jtok.clone(); let mid = bad.len() / 2; bad[mid] ^= 1;                  // tampered
    assert!(jwt::jwt_verify(&bad, SECRET).is_err());

    let dm = time_ns(n, || { std::hint::black_box(mint_direct(SECRET, "HS256", EXP)); });
    let dv = time_ns(n, || { std::hint::black_box(verify(std::hint::black_box(&tok), SECRET, NOW).is_ok()); });
    println!("BENCH rust dagr mint={dm} verify={dv} size={}", tok.len());

    let jexp = jwt::now() + 3600;
    let jm = time_ns(n, || { std::hint::black_box(jwt::jwt_mint(SECRET, jexp)); });
    let jv = time_ns(n, || { std::hint::black_box(jwt::jwt_verify(std::hint::black_box(&jtok), SECRET).is_ok()); });
    println!("BENCH rust jwt mint={jm} verify={jv} size={}", jtok.len());
}

// Break `mint_direct` into phases — build the value tree, serialize it (no HMAC), and
// HMAC alone — so we can see where the mint time goes. `to_bytes_with_header` borrows the
// tree, so serialize is timed over a pre-built one.
#[cfg(feature = "bench")]
fn profile() {
    use dagr_signed_token::token::Token;
    let n = 200_000u32;
    let claims = build_direct(EXP);
    let t_build = time_ns(n, || { std::hint::black_box(build_direct(EXP)); });
    let t_jwt_build = time_ns(n, || { jwt::build_only(EXP); });
    let sig = [0u8; 32].to_vec();
    let t_ser = time_ns(n, || {
        let out = Token::to_bytes_with_header(std::hint::black_box(&claims), |_o, _b| Jws {
            algorithm: "HS256".into(), key_id: Some(KID.into()), signature: sig.clone(),
        }).unwrap();
        std::hint::black_box(out);
    });
    let body = mint_direct(SECRET, "HS256", EXP);
    let pre = preimage(10, &body);
    let t_hmac = time_ns(n, || { std::hint::black_box(hmac_sha256(SECRET, std::hint::black_box(&pre))); });
    let t_full = time_ns(n, || { std::hint::black_box(mint_direct(SECRET, "HS256", EXP)); });
    // A bare DagrBuilder::new() — `to_bytes_with_header` allocates 3 of these (body, header, framing).
    let t_alloc = time_ns(n, || { std::hint::black_box(dagr_signed_token::dagr_runtime::DagrBuilder::new()); });
    println!("PROFILE rust mint_direct total={t_full}ns = build_tree={t_build}ns + serialize(no-hmac)={t_ser}ns + hmac(ring)={t_hmac}ns");
    println!("        DagrBuilder::new()={t_alloc}ns — now 1 builder for the whole [framing][header][body], finalized once");
    println!("        build cost: dagr value tree={t_build}ns  vs  jsonwebtoken claims struct={t_jwt_build}ns");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        #[cfg(feature = "bench")]
        Some("bench") => { bench(); return; }
        #[cfg(feature = "bench")]
        Some("profile") => { profile(); return; }
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
