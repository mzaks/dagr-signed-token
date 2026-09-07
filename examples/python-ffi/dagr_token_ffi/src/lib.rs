//! C-ABI over the generated Dagr codec — the native half of a `python-ffi` target.
//!
//! Python (via ctypes) mints/verifies/reads the token by calling straight into the Rust
//! codec: `mint` = the arena builder + hand-rolled HMAC, `verify` = the zero-alloc
//! verify-before-parse gate, `get` = the lazy path-query cursors. Byte-identical to the
//! other five targets; self-contained (path-deps the committed gen/rust, no dagr CLI).
use std::os::raw::c_char;
use dagr_signed_token::token::{Json, Jws, TokenArena, TokenGraph};
use dagr_signed_token::token_lazy::{self, ClaimsAccessor, JsonPackedArrayAccessor};
use dagr_signed_token::dagr_runtime::DagrError;

mod sha256;
use sha256::{ct_eq, hmac_sha256};

const KID: &str = "hmac-key-2026";
const NOW: u64 = 1_760_000_000;

// status codes (mirror the demo's Rejected reasons)
const OK: i32 = 0;
const BAD_ALG: i32 = 1;
const BAD_SIG: i32 = 2;
const EXPIRED: i32 = 3;
const WRONG_AUD: i32 = 4;
const MALFORMED: i32 = 5;

// value kinds
const K_ABSENT: i32 = 0;
const K_STR: i32 = 1;
const K_BYTES: i32 = 2;
const K_U64: i32 = 3;
const K_I64: i32 = 4;
const K_F64: i32 = 5;
const K_BOOL: i32 = 6;
const K_ARRAY: i32 = 7;
const K_OBJECT: i32 = 8;

#[repr(C)] pub struct DagrStr { ptr: *const u8, len: usize }
#[repr(C)] pub struct DagrBytes { ptr: *mut u8, len: usize }
#[repr(C)] pub struct DagrValue { kind: i32, num: u64, bytes: DagrBytes }

impl DagrStr {
    unsafe fn slice(&self) -> &[u8] {
        if self.ptr.is_null() { &[] } else { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    unsafe fn s(&self) -> &str { std::str::from_utf8(self.slice()).unwrap_or("") }
}

fn own(v: Vec<u8>) -> DagrBytes {
    let mut b = v.into_boxed_slice();
    let (ptr, len) = (b.as_mut_ptr(), b.len());
    std::mem::forget(b);
    DagrBytes { ptr, len }
}
fn nobytes() -> DagrBytes { DagrBytes { ptr: std::ptr::null_mut(), len: 0 } }

/// Free a buffer handed out via DagrBytes / DagrValue.bytes.
#[no_mangle] pub unsafe extern "C" fn dagr_free(b: DagrBytes) {
    if !b.ptr.is_null() { drop(Box::from_raw(std::slice::from_raw_parts_mut(b.ptr, b.len))); }
}

fn preimage(off: usize, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + body.len());
    m.extend_from_slice(&(off as u64).to_le_bytes());
    m.extend_from_slice(body);
    m
}

// The CONTRACT token (fixed claims incl `fp` = Data, which plain JSON can't round-trip) —
// built in Rust so it stays byte-identical to the other five targets. Params: secret/alg/exp
// (alg drives the alg:none test, exp the expiry test), exactly like the other examples' mint().
fn contract_token(secret: &[u8], alg: &str, exp: u64) -> Vec<u8> {
    let a = TokenArena::<0>::new();
    let custom = Json::Object(vec![
        a.new_json_member("tenant", Some(Json::String("acme".into()))),
        a.new_json_member("roles", Some(Json::Array(vec![
            Some(Json::String("admin".into())), Some(Json::String("billing".into())),
        ]))),
        a.new_json_member("mfa", Some(Json::Bool(true))),
        a.new_json_member("fp", Some(Json::Data(vec![0xDE, 0xAD, 0xBE, 0xEF]))),
    ]);
    a.set_root(Some(a.new_claims(
        Some("user-42"), Some("https://issuer.dagr.one"), Some("dagr-api"),
        NOW, exp, vec!["read:profile".into(), "write:posts".into()], Some(custom))));
    a.to_bytes_with_header(|off, body| Jws {
        algorithm: alg.into(),
        key_id: Some(KID.into()),
        signature: hmac_sha256(secret, &preimage(off, body)).to_vec(),
    }).expect("mint")
}

#[no_mangle] pub unsafe extern "C" fn dagr_token_mint(
    secret: DagrStr, alg: DagrStr, exp: u64, out: *mut DagrBytes) -> i32 {
    *out = own(contract_token(secret.slice(), alg.s(), exp));
    OK
}

#[no_mangle] pub unsafe extern "C" fn dagr_token_verify(
    token: DagrStr, secret: DagrStr, now: u64) -> i32 {
    let (tk, sec) = (token.slice(), secret.slice());
    let reason = std::cell::Cell::new(0i32);
    let root = token_lazy::read_root_with_header(tk, |h, off, body| {
        if h.algorithm().unwrap_or("") != "HS256" { reason.set(BAD_ALG); return Err(DagrError::InvalidData); }
        let want = hmac_sha256(sec, &preimage(off, body));
        if !ct_eq(h.signature().unwrap_or(&[]), &want) { reason.set(BAD_SIG); return Err(DagrError::InvalidData); }
        Ok(())
    });
    let c = match root { Ok(c) => c, Err(_) => { let r = reason.get(); return if r != 0 { r } else { MALFORMED }; } };
    if now >= c.expires_at().unwrap_or(0) { return EXPIRED; }
    if c.audience() != Some("dagr-api") { return WRONG_AUD; }
    OK
}

// ── DagrValue constructors ──
fn v_absent() -> DagrValue { DagrValue { kind: K_ABSENT, num: 0, bytes: nobytes() } }
fn v_str(s: &str) -> DagrValue { DagrValue { kind: K_STR, num: 0, bytes: own(s.as_bytes().to_vec()) } }
fn v_u64(n: u64) -> DagrValue { DagrValue { kind: K_U64, num: n, bytes: nobytes() } }
fn v_f64(f: f64) -> DagrValue { DagrValue { kind: K_F64, num: f.to_bits(), bytes: nobytes() } }
fn v_bool(b: bool) -> DagrValue { DagrValue { kind: K_BOOL, num: b as u64, bytes: nobytes() } }
fn v_bytes(b: &[u8]) -> DagrValue { DagrValue { kind: K_BYTES, num: 0, bytes: own(b.to_vec()) } }
fn v_arr(n: usize) -> DagrValue { DagrValue { kind: K_ARRAY, num: n as u64, bytes: nobytes() } }
fn v_obj(n: usize) -> DagrValue { DagrValue { kind: K_OBJECT, num: n as u64, bytes: nobytes() } }

// Navigate the freeform `custom` subtree by the remaining dotted segments.
fn nav_json(j: JsonPackedArrayAccessor, segs: &[&str]) -> DagrValue {
    if segs.is_empty() {
        return match j {
            JsonPackedArrayAccessor::String(s) => v_str(s.as_deref().unwrap_or("")),
            JsonPackedArrayAccessor::Number(n) => v_f64(n),
            JsonPackedArrayAccessor::Bool(b) => v_bool(b),
            JsonPackedArrayAccessor::Data(d) => v_bytes(&d),
            JsonPackedArrayAccessor::Array(a) => v_arr(a.len()),
            JsonPackedArrayAccessor::Object(o) => v_obj(o.len()),
            JsonPackedArrayAccessor::Unknown(_) => v_absent(),
        };
    }
    let (head, rest) = (segs[0], &segs[1..]);
    match j {
        JsonPackedArrayAccessor::Object(o) => {
            for m in o.iter().flatten() {
                if m.key().map(|k| k == head).unwrap_or(false) {
                    return match m.value() { Some(v) => nav_json(v, rest), None => v_absent() };
                }
            }
            v_absent()
        }
        JsonPackedArrayAccessor::Array(a) => {
            let idx: usize = match head.parse() { Ok(i) => i, Err(_) => return v_absent() };
            match a.iter().nth(idx) {
                Some(Ok(Some(v))) => nav_json(v, rest),
                _ => v_absent(),
            }
        }
        _ => v_absent(),
    }
}

fn nav_root(c: &ClaimsAccessor, path: &str) -> DagrValue {
    let segs: Vec<&str> = path.split('.').collect();
    match segs[0] {
        "subject"   => c.subject().map(v_str).unwrap_or_else(v_absent),
        "issuer"    => c.issuer().map(v_str).unwrap_or_else(v_absent),
        "audience"  => c.audience().map(v_str).unwrap_or_else(v_absent),
        "issuedAt"  => c.issued_at().map(v_u64).unwrap_or_else(|_| v_absent()),
        "expiresAt" => c.expires_at().map(v_u64).unwrap_or_else(|_| v_absent()),
        "scopes"    => match c.scopes() {
            Ok(sc) => {
                if segs.len() == 1 { return v_arr(sc.len()); }
                let idx: usize = segs[1].parse().unwrap_or(usize::MAX);
                match sc.iter().nth(idx) { Some(Ok(s)) => v_str(s), _ => v_absent() }
            }
            Err(_) => v_absent(),
        },
        "custom"    => match c.custom() { Some(j) => nav_json(j, &segs[1..]), None => v_absent() },
        _ => v_absent(),
    }
}

#[no_mangle] pub unsafe extern "C" fn dagr_token_get(
    token: DagrStr, path: *const c_char, out: *mut DagrValue) -> i32 {
    let tk = token.slice();
    let p = match std::ffi::CStr::from_ptr(path).to_str() { Ok(p) => p, Err(_) => return MALFORMED };
    // already verified by the caller — re-open with a no-op gate purely to read.
    let c = match token_lazy::read_root_with_header(tk, |_, _, _| Ok::<(), DagrError>(())) {
        Ok(c) => c, Err(_) => return MALFORMED,
    };
    *out = nav_root(&c, p);
    OK
}
