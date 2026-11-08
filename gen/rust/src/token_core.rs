#![allow(dead_code, non_snake_case, unused_imports, unused_variables, unexpected_cfgs, clippy::all)]
#[cfg(all(dagr_no_std, not(dagr_no_alloc)))] use alloc::{vec, vec::Vec, string::String, string::ToString, boxed::Box, borrow::ToOwned};
use crate::dagr_runtime::{DagrError, PackedSink, StorePacked};

#[cfg(not(dagr_no_alloc))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Jws {
    pub algorithm: String,
    pub key_id: Option<String>,
    pub signature: Vec<u8>,
}

#[cfg(not(dagr_no_alloc))]
impl Jws {
    pub fn store_packed<B: crate::dagr_runtime::PackedSink + ?Sized>(&self, b: &mut B) -> Result<(), crate::dagr_runtime::DagrError> {
        let _before = b.cursor();
        { let _bs: &[u8] = &self.signature[..]; b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; b.store_leb((2u64 << 1) | 1)?; }
        if let Some(ref _v) = self.key_id {
            { let _bs = _v.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; b.store_leb((1u64 << 1) | 1)?; }
        }
        { let _bs = self.algorithm.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; b.store_leb((0u64 << 1) | 1)?; }
        b.store_leb((b.cursor() - _before) as u64)?;
        Ok(())
    }
    #[cfg(not(dagr_no_std))]
    pub fn store_packed_std(&self, b: &mut crate::dagr_runtime::DagrBuilder) {
        let _before = b.cursor();
        { let _bs: &[u8] = &self.signature[..]; b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((2u64 << 1) | 1); }
        if let Some(ref _v) = self.key_id {
            { let _bs = _v.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((1u64 << 1) | 1); }
        }
        { let _bs = self.algorithm.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((0u64 << 1) | 1); }
        b.store_leb((b.cursor() - _before) as u64);
    }

    pub fn restore(data: &[u8], at: usize) -> Self {
        Self::restore_d(data, at, 0)
    }
    #[doc(hidden)]
    pub fn restore_d(data: &[u8], at: usize, _d: u32) -> Self {
        use crate::dagr_runtime::*;
        let mut values = Jws::default();
        if _d >= MAX_DEPTH { return values; }
        let _d = _d + 1;
        let (_bl, _blb) = read_leb(data, at).unwrap_or((0, 1));
        let mut _cursor = at + _blb;
        let _end = _cursor + _bl as usize;
        if _cursor < _end {
            let (_tag, _tagb) = read_leb(data, _cursor).unwrap_or((0, 1));
            if (_tag >> 1) as usize == 0 {
                _cursor += _tagb;
                let (_sv, _sb) = read_leb(data, _cursor).unwrap_or((0, 1)); _cursor += _sb;
                values.algorithm = String::from_utf8_lossy(crate::dagr_runtime::slice_at(data, _cursor, _sv as usize)).into_owned(); _cursor += _sv as usize;
            }
        }
        if _cursor < _end {
            let (_tag, _tagb) = read_leb(data, _cursor).unwrap_or((0, 1));
            if (_tag >> 1) as usize == 1 {
                _cursor += _tagb;
                let (_sv, _sb) = read_leb(data, _cursor).unwrap_or((0, 1)); _cursor += _sb;
                values.key_id = Some(String::from_utf8_lossy(crate::dagr_runtime::slice_at(data, _cursor, _sv as usize)).into_owned()); _cursor += _sv as usize;
            }
        }
        if _cursor < _end {
            let (_tag, _tagb) = read_leb(data, _cursor).unwrap_or((0, 1));
            if (_tag >> 1) as usize == 2 {
                _cursor += _tagb;
                let (_dv, _db) = read_leb(data, _cursor).unwrap_or((0, 1)); _cursor += _db;
                values.signature = crate::dagr_runtime::slice_at(data, _cursor, _dv as usize).to_vec(); _cursor += _dv as usize;
            }
        }
        values
    }
    /// The borrowed `JwsRef` view of this record — same bytes when stored (36 §7).
    pub fn as_ref(&self) -> JwsRef<'_> {
        JwsRef { algorithm: &self.algorithm, key_id: self.key_id.as_deref(), signature: &self.signature[..] }
    }
}
#[cfg(not(dagr_no_alloc))]
impl crate::dagr_runtime::StorePacked for Jws { #[inline] fn store_packed<B: crate::dagr_runtime::PackedSink + ?Sized>(&self, b: &mut B) -> Result<(), crate::dagr_runtime::DagrError> { Jws::store_packed(self, b) } }
#[cfg(not(dagr_no_std))]
impl crate::dagr_runtime::StorePackedStd for Jws { #[inline] fn store_packed_std(&self, b: &mut crate::dagr_runtime::DagrBuilder) { Jws::store_packed_std(self, b) } }

/// Borrowed write form of `Jws` (36 §7): same bytes, no heap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JwsRef<'a> {
    pub algorithm: &'a str,
    pub key_id: Option<&'a str>,
    pub signature: &'a [u8],
}
impl<'a> JwsRef<'a> {
    pub fn store_packed<B: crate::dagr_runtime::PackedSink + ?Sized>(&self, b: &mut B) -> Result<(), crate::dagr_runtime::DagrError> {
        let _before = b.cursor();
        { let _bs: &[u8] = &self.signature[..]; b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; b.store_leb((2u64 << 1) | 1)?; }
        if let Some(ref _v) = self.key_id {
            { let _bs = _v.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; b.store_leb((1u64 << 1) | 1)?; }
        }
        { let _bs = self.algorithm.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; b.store_leb((0u64 << 1) | 1)?; }
        b.store_leb((b.cursor() - _before) as u64)?;
        Ok(())
    }
    #[cfg(not(dagr_no_std))]
    pub fn store_packed_std(&self, b: &mut crate::dagr_runtime::DagrBuilder) {
        let _before = b.cursor();
        { let _bs: &[u8] = &self.signature[..]; b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((2u64 << 1) | 1); }
        if let Some(ref _v) = self.key_id {
            { let _bs = _v.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((1u64 << 1) | 1); }
        }
        { let _bs = self.algorithm.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((0u64 << 1) | 1); }
        b.store_leb((b.cursor() - _before) as u64);
    }
}
impl<'a> crate::dagr_runtime::StorePacked for JwsRef<'a> { #[inline] fn store_packed<B: crate::dagr_runtime::PackedSink + ?Sized>(&self, b: &mut B) -> Result<(), crate::dagr_runtime::DagrError> { JwsRef::store_packed(self, b) } }
#[cfg(not(dagr_no_std))]
impl<'a> crate::dagr_runtime::StorePackedStd for JwsRef<'a> { #[inline] fn store_packed_std(&self, b: &mut crate::dagr_runtime::DagrBuilder) { JwsRef::store_packed_std(self, b) } }


// ── Direct Graph Builder ("spec/33-direct-graph-builder.md") ─────────────────────
// Arena-free construction for this packed-rooted tree: plain value structs in,
// byte-identical graph buffer out. `direct::to_bytes*(v) == arena.to_bytes*()`.
pub mod direct {
    use crate::dagr_runtime::{NodeStoreRef, DagrError, PackedSink};
    #[cfg(not(dagr_no_std))] use crate::dagr_runtime::DagrBuilder;
    #[cfg(all(dagr_no_std, not(dagr_no_alloc)))] use alloc::vec::Vec;
    #[cfg(not(dagr_no_std))] use super::Jws;   // owned header: std `to_bytes_with_header` only

    #[derive(Debug, Clone, PartialEq)]
    pub enum Json<'a> {
        String(&'a str),
        Number(f64),
        Bool(bool),
        Array(&'a [Option<Json<'a>>]),
        Object(&'a [JsonMember<'a>]),
        Data(&'a [u8]),
        Unknown(u8),
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Claims<'a> {
        pub subject: Option<&'a str>,
        pub issuer: Option<&'a str>,
        pub audience: Option<&'a str>,
        pub issued_at: u64,
        pub expires_at: u64,
        pub scopes: &'a [&'a str],
        pub custom: Option<Json<'a>>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct JsonMember<'a> {
        pub key: &'a str,
        pub value: Option<Json<'a>>,
    }

    fn _supp_json<'a, B: PackedSink + ?Sized>(u: &Json<'a>, b: &mut B) -> Result<(u64, u64), DagrError> {
        let (_tid, _code): (u64, u64) = match u {
            Json::String(v) => { let _bs = v.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; (0u64, 6u64) },
            Json::Number(v) => { if b.store_packed_f64(*v)? { (1u64, 5u64) } else { (1u64, 4u64) } },
            Json::Bool(v) => { b.store_bool(*v)?; (2u64, 1u64) },
            Json::Array(v) => {
                let _arr = &v[..];
                let _cnt = _arr.len();
                let _bef = b.cursor();
                for _e in _arr.iter().rev() { if let Some(_u) = _e { _supp_json(_u, b)?; } }
                let _hbef = b.cursor();
                for _e in _arr.iter().rev() { if let Some(_u) = _e { let (_t, _c) = _tc_json(_u); b.store_leb((_t << 3) | _c)?; } }
                b.store_leb((b.cursor() - _hbef) as u64)?;
                b.store_zeros((_cnt + 7) / 8)?; let _bn = b.cursor();
                for _i in 0.._cnt { if _arr[_i].is_none() { b.or_byte(_bn, _i >> 3, 1u8 << (_i & 7)); } }
                b.store_leb(_cnt as u64)?;
                b.store_leb((b.cursor() - _bef) as u64)?;
                (3u64, 6u64)
            },
            Json::Object(v) => {
                let _arr = &v[..];
                let _cnt = _arr.len();
                let _bef = b.cursor();
                for _e in _arr.iter().rev() { _e.store_packed(b)?; }
                b.store_leb(_cnt as u64)?;
                b.store_leb((b.cursor() - _bef) as u64)?;
                (4u64, 6u64)
            },
            Json::Data(v) => { let _bs: &[u8] = v; b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; (5u64, 6u64) },
            Json::Unknown(id) => (*id as u64, 1u64),
        };
        Ok((_tid, _code))
    }
    fn _spv_json<'a, B: PackedSink + ?Sized>(u: &Json<'a>, b: &mut B) -> Result<(), DagrError> {
        let (_t, _c) = _supp_json(u, b)?;
        b.store_leb((_t << 3) | _c)?;
        Ok(())
    }
    fn _tc_json(u: &Json<'_>) -> (u64, u64) {
        match u {
            Json::String(_) => (0u64, 6u64),
            Json::Number(v) => { if crate::dagr_runtime::packs_f64(*v) { (1u64, 5u64) } else { (1u64, 4u64) } },
            Json::Bool(v) => { (2u64, 1u64) },
            Json::Array(_) => (3u64, 6u64),
            Json::Object(_) => (4u64, 6u64),
            Json::Data(_) => (5u64, 6u64),
            Json::Unknown(id) => (*id as u64, 1u64),
        }
    }

    impl<'a> Claims<'a> {
        pub fn store_packed<B: PackedSink + ?Sized>(&self, b: &mut B) -> Result<NodeStoreRef, DagrError> {
            let _before = b.cursor();
            let mut _obs0 = 0u8;
            _obs0 |= u8::from(self.subject.is_some()) << 0;
            _obs0 |= u8::from(self.issuer.is_some()) << 1;
            _obs0 |= u8::from(self.audience.is_some()) << 2;
            _obs0 |= u8::from(!self.scopes.is_empty()) << 3;
            _obs0 |= u8::from(self.custom.is_some()) << 4;
            let mut _ebs0 = 0u8;
            { let _v = self.issued_at; _ebs0 |= u8::from(crate::dagr_runtime::leb_length(_v as u64) >= 8) << 0; }
            { let _v = self.expires_at; _ebs0 |= u8::from(crate::dagr_runtime::leb_length(_v as u64) >= 8) << 1; }
            if let Some(_u) = self.custom.as_ref() {
                let (_tid, _code) = _supp_json(_u, b)?;
                b.store_leb((_tid << 3) | _code)?;
            }
            {
                let _scopes_arr = &self.scopes;
                if !_scopes_arr.is_empty() {
                let _cnt_scopes = _scopes_arr.len();
                let _bef_scopes = b.cursor();
                for _e in _scopes_arr.iter().rev() { b.store_blob(_e.as_bytes())?; }
                b.store_leb(_cnt_scopes as u64)?;
                b.store_leb((b.cursor() - _bef_scopes) as u64)?;
                }
            }
            { let _v = self.expires_at; if _ebs0 & 2 != 0 { b.store_u64(_v)?; } else { b.store_leb(_v as u64)?; } }
            { let _v = self.issued_at; if _ebs0 & 1 != 0 { b.store_u64(_v)?; } else { b.store_leb(_v as u64)?; } }
            if let Some(_s) = self.audience.as_deref() { let _bs = _s.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; }
            if let Some(_s) = self.issuer.as_deref() { let _bs = _s.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; }
            if let Some(_s) = self.subject.as_deref() { let _bs = _s.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; }
            b.store_u8(_ebs0)?;
            b.store_u8(_obs0)?;
            b.store_leb((b.cursor() - _before) as u64)?;
            Ok(NodeStoreRef::Offset(b.cursor()))
        }
    }

    impl<'a> JsonMember<'a> {
        pub fn store_packed<B: PackedSink + ?Sized>(&self, b: &mut B) -> Result<NodeStoreRef, DagrError> {
            let _before = b.cursor();
            let mut _obs0 = 0u8;
            _obs0 |= u8::from(self.value.is_some()) << 0;
            if let Some(_u) = self.value.as_ref() {
                let (_tid, _code) = _supp_json(_u, b)?;
                b.store_leb((_tid << 3) | _code)?;
            }
            { let _bs = self.key.as_bytes(); b.store_raw(_bs)?; b.store_leb(_bs.len() as u64)?; }
            b.store_u8(_obs0)?;
            b.store_leb((b.cursor() - _before) as u64)?;
            Ok(NodeStoreRef::Offset(b.cursor()))
        }
    }

    /// 36 §8 — `[framing][header][body]` into any `PackedSink` (no heap with a `FixedBuilder`).
    /// `header_fn(root_offset, body)` returns the header — owned `Jws` or borrowed
    /// `JwsRef`. Start from an empty builder; returns the length (`b.record_bytes()`).
    pub fn write_into_with_header<B, H, F>(root: &Claims<'_>, b: &mut B, header_fn: F) -> Result<usize, DagrError>
    where B: PackedSink + ?Sized, H: crate::dagr_runtime::StorePacked, F: FnOnce(usize, &[u8]) -> H {
        let root_ref = root.store_packed(b)?;
        let root_off = root_ref.to_offset().unwrap_or(0);
        let body_len = b.cursor();
        let original_offset = body_len - root_off;
        let header_value = header_fn(original_offset, b.record_bytes());
        header_value.store_packed(b)?;
        let h = b.cursor() - body_len;
        let stored_offset = (((original_offset + h) as u64) << 2) | 0b01;
        b.store_leb(stored_offset)?;
        Ok(b.cursor())
    }

    #[cfg(not(dagr_no_std))]
    pub fn to_bytes_with_header<F>(root: &Claims<'_>, header_fn: F) -> Result<Vec<u8>, DagrError>
    where F: FnOnce(usize, &[u8]) -> Jws {
        let mut b = DagrBuilder::with_capacity(4096);   // direct = tree → small buffer, grows if needed
        write_into_with_header(root, &mut b, header_fn)?;
        Ok(b.finalize())
    }

    #[cfg(not(dagr_no_std))]
    pub struct Writer;
    #[cfg(not(dagr_no_std))]
    impl Writer {
        pub fn new() -> Self { Writer }
        pub fn to_bytes_with_header<F>(&mut self, root: &Claims<'_>, header_fn: F) -> Result<Vec<u8>, DagrError>
        where F: FnOnce(usize, &[u8]) -> Jws { to_bytes_with_header(root, header_fn) }
    }
    #[cfg(not(dagr_no_std))]
    impl Default for Writer { fn default() -> Self { Writer::new() } }
}

pub struct Token;
impl Token {
    #[cfg(not(dagr_no_std))]
    pub fn to_bytes_with_header<F>(root: &direct::Claims<'_>, header_fn: F) -> Result<Vec<u8>, crate::dagr_runtime::DagrError>
    where F: FnOnce(usize, &[u8]) -> Jws { direct::to_bytes_with_header(root, header_fn) }
    pub fn write_into_with_header<B, H, F>(root: &direct::Claims<'_>, b: &mut B, header_fn: F) -> Result<usize, crate::dagr_runtime::DagrError>
    where B: crate::dagr_runtime::PackedSink + ?Sized, H: crate::dagr_runtime::StorePacked, F: FnOnce(usize, &[u8]) -> H {
        direct::write_into_with_header(root, b, header_fn)
    }
}