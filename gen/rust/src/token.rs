#![allow(unsafe_code, dead_code, non_snake_case)]
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeRef { pub index: u32 }

#[derive(Debug, Clone)]
pub enum _Json {
    String(String),
    Number(f64),
    Bool(bool),
    Array(Vec<Option<_Json>>),
    Object(Vec<NodeRef>),
    Data(Vec<u8>),
    Unknown(u8),
}

pub enum Json<'arena, G: TokenGraph> {
    String(String),
    Number(f64),
    Bool(bool),
    Array(Vec<Option<Json<'arena, G>>>),
    Object(Vec<JsonMember<'arena, G>>),
    Data(Vec<u8>),
    Unknown(u8),
}

impl<'arena, G: TokenGraph> Json<'arena, G> {
    pub(crate) fn _to_storage(self, _graph: &G) -> _Json {
        match self {
            Json::String(v) => _Json::String(v),
            Json::Number(v) => _Json::Number(v),
            Json::Bool(v) => _Json::Bool(v),
            Json::Array(v) => _Json::Array(v.into_iter().map(|o| o.map(|e| e._to_storage(_graph))).collect()),
            Json::Object(v) => _Json::Object(v.into_iter().map(|e| NodeRef { index: e.index }).collect()),
            Json::Data(v) => _Json::Data(v),
            Json::Unknown(id) => _Json::Unknown(id),
        }
    }

    pub(crate) fn _cycle_eq<B: TokenGraph>(&self, other: &Json<'_, B>,
        visited: &mut HashSet<((u64, usize, usize), (u64, usize, usize))>) -> bool {
        match (self, other) {
            (Json::String(a), Json::String(b)) => a == b,
            (Json::Number(a), Json::Number(b)) => a == b,
            (Json::Bool(a), Json::Bool(b)) => a == b,
            (Json::Array(a), Json::Array(b)) => a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| match (x, y) { (Some(x), Some(y)) => x._cycle_eq(y, visited), (None, None) => true, _ => false }),
            (Json::Object(a), Json::Object(b)) => a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x._cycle_eq(y, visited)),
            (Json::Data(a), Json::Data(b)) => a == b,
            (Json::Unknown(a), Json::Unknown(b)) => a == b,
            _ => false,
        }
    }

    pub(crate) fn _hash_with<H: std::hash::Hasher>(&self, state: &mut H,
        visited: &mut HashSet<(u64, usize, usize)>) {
        match self {
            Json::String(v) => { 0u8.hash(state); v.hash(state); }
            Json::Number(v) => { 1u8.hash(state); v.to_bits().hash(state); }
            Json::Bool(v) => { 2u8.hash(state); v.hash(state); }
            Json::Array(v) => { 3u8.hash(state); v.len().hash(state); for e in v.iter() { match e { Some(x) => { 1u8.hash(state); x._hash_with(state, visited); }, None => 0u8.hash(state) } } }
            Json::Object(v) => { 4u8.hash(state); v.len().hash(state); for e in v.iter() { e._hash_with(state, visited); } }
            Json::Data(v) => { 5u8.hash(state); v.hash(state); }
            Json::Unknown(id) => { 255u8.hash(state); id.hash(state); }
        }
    }

    pub(crate) fn _fmt_with(&self, f: &mut fmt::Formatter<'_>,
        visited: &mut HashSet<(u64, usize, usize)>) -> fmt::Result {
        match self {
            Json::String(v) => write!(f, "String({:?})", v),
            Json::Number(v) => write!(f, "Number({:?})", v),
            Json::Bool(v) => write!(f, "Bool({:?})", v),
            Json::Array(v) => { write!(f, "Array([")?; for (i, e) in v.iter().enumerate() { if i > 0 { write!(f, ", ")?; } match e { Some(x) => x._fmt_with(f, visited)?, None => write!(f, "None")? } } write!(f, "])") }
            Json::Object(v) => { write!(f, "Object([")?; for (i, e) in v.iter().enumerate() { if i > 0 { write!(f, ", ")?; } e._fmt_with(f, visited)?; } write!(f, "])") }
            Json::Data(v) => write!(f, "Data({:?})", v),
            Json::Unknown(id) => write!(f, "Unknown({})", id),
        }
    }
}

impl<'a, 'b, A: TokenGraph, B: TokenGraph> PartialEq<Json<'b, B>> for Json<'a, A> {
    fn eq(&self, other: &Json<'b, B>) -> bool {
        let mut v = HashSet::new(); self._cycle_eq(other, &mut v)
    }
}
impl<'arena, G: TokenGraph> Eq for Json<'arena, G> {}

impl<'arena, G: TokenGraph> fmt::Display for Json<'arena, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v = HashSet::new(); self._fmt_with(f, &mut v)
    }
}

fn _union_to_public_json<'arena, G: TokenGraph>(stor: _Json, graph: &'arena G) -> Option<Json<'arena, G>> {
    match stor {
        _Json::String(v) => Some(Json::String(v)),
        _Json::Number(v) => Some(Json::Number(v)),
        _Json::Bool(v) => Some(Json::Bool(v)),
        _Json::Array(v) => Some(Json::Array(v.into_iter().map(|o| o.and_then(|e| _union_to_public_json(e, graph))).collect())),
        _Json::Object(v) => Some(Json::Object(v.into_iter().map(|nr| JsonMember { index: nr.index, graph: graph }).collect())),
        _Json::Data(v) => Some(Json::Data(v)),
        _Json::Unknown(id) => Some(Json::Unknown(id)),
    }
}

// ── ClaimsValues ──────────────────────────────────────────────────────────
pub struct ClaimsValues {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub scopes: Vec<String>,
    pub custom: Option<_Json>,
}

// ── JsonMemberValues ──────────────────────────────────────────────────────────
pub struct JsonMemberValues {
    pub key: Option<String>,
    pub value: Option<_Json>,
}

pub trait ClaimsArena {
    const CLAIMS_TYPE_ID: u64;
    fn arena_of_claims(&self) -> &RefCell<Vec<ClaimsValues>>;
}

pub trait JsonMemberArena {
    const JSONMEMBER_TYPE_ID: u64;
    fn arena_of_json_member(&self) -> &RefCell<Vec<JsonMemberValues>>;
}

// ── TokenGraph ─────────────────────────────────────────────────────────────────────
pub trait TokenGraph: ClaimsArena + JsonMemberArena {
    fn new_claims(&self, subject: Option<&str>, issuer: Option<&str>, audience: Option<&str>, issued_at: u64, expires_at: u64, scopes: Vec<String>, custom: Option<Json<'_, Self>>) -> Claims<'_, Self> where Self: Sized {
        let _values = ClaimsValues {
                subject: subject.map(str::to_owned),
                issuer: issuer.map(str::to_owned),
                audience: audience.map(str::to_owned),
                issued_at: issued_at,
                expires_at: expires_at,
                scopes: scopes,
                custom: custom.map(|v| v._to_storage(self)),
        };
        let index = {
            let mut _arena = self.arena_of_claims().borrow_mut();
            let idx = _arena.len() as u32;
            _arena.push(_values);
            idx
        };
        Claims { index: index, graph: self }
    }
    fn new_claims_defaulted(&self, issued_at: u64, expires_at: u64) -> Claims<'_, Self> where Self: Sized {
        self.new_claims(None, None, None, issued_at, expires_at, Vec::new(), None)
    }
    fn new_json_member(&self, key: &str, value: Option<Json<'_, Self>>) -> JsonMember<'_, Self> where Self: Sized {
        let _values = JsonMemberValues {
                key: Some(key.to_owned()),
                value: value.map(|v| v._to_storage(self)),
        };
        let index = {
            let mut _arena = self.arena_of_json_member().borrow_mut();
            let idx = _arena.len() as u32;
            _arena.push(_values);
            idx
        };
        JsonMember { index: index, graph: self }
    }
    fn new_json_member_defaulted(&self, key: &str) -> JsonMember<'_, Self> where Self: Sized {
        self.new_json_member(key, None)
    }
}
impl<T: ClaimsArena + JsonMemberArena> TokenGraph for T {}

// ── Claims handle ────────────────────────────────────────────────────────
pub struct Claims<'arena, G: TokenGraph> {
    pub(crate) index: u32,
    pub(crate) graph: &'arena G,
}

impl<'arena, G: TokenGraph> Clone for Claims<'arena, G> {
    fn clone(&self) -> Self { Claims { index: self.index, graph: self.graph } }
}
impl<'arena, G: TokenGraph> Copy for Claims<'arena, G> {}

impl<'arena, G: TokenGraph> Claims<'arena, G> {
    pub fn subject(&self) -> Option<String> {
        self.graph.arena_of_claims().borrow()[self.index as usize].subject.clone()
    }
    pub fn set_subject(&self, v: Option<&str>) {
        self.graph.arena_of_claims().borrow_mut()[self.index as usize].subject = v.map(str::to_owned);
    }
    pub fn issuer(&self) -> Option<String> {
        self.graph.arena_of_claims().borrow()[self.index as usize].issuer.clone()
    }
    pub fn set_issuer(&self, v: Option<&str>) {
        self.graph.arena_of_claims().borrow_mut()[self.index as usize].issuer = v.map(str::to_owned);
    }
    pub fn audience(&self) -> Option<String> {
        self.graph.arena_of_claims().borrow()[self.index as usize].audience.clone()
    }
    pub fn set_audience(&self, v: Option<&str>) {
        self.graph.arena_of_claims().borrow_mut()[self.index as usize].audience = v.map(str::to_owned);
    }
    pub fn issued_at(&self) -> u64 {
        self.graph.arena_of_claims().borrow()[self.index as usize].issued_at
    }
    pub fn set_issued_at(&self, v: u64) {
        self.graph.arena_of_claims().borrow_mut()[self.index as usize].issued_at = v;
    }
    pub fn expires_at(&self) -> u64 {
        self.graph.arena_of_claims().borrow()[self.index as usize].expires_at
    }
    pub fn set_expires_at(&self, v: u64) {
        self.graph.arena_of_claims().borrow_mut()[self.index as usize].expires_at = v;
    }
    pub fn scopes(&self) -> Vec<String> {
        self.graph.arena_of_claims().borrow()[self.index as usize].scopes.clone()
    }
    pub fn set_scopes(&self, vs: Vec<String>) {
        self.graph.arena_of_claims().borrow_mut()[self.index as usize].scopes = vs;
    }
    pub fn push_scopes(&self, v: String) {
        self.graph.arena_of_claims().borrow_mut()[self.index as usize].scopes.push(v);
    }
    pub fn custom(&self) -> Option<Json<'arena, G>> {
        let stor = {
            let arena = self.graph.arena_of_claims().borrow();
            arena.get(self.index as usize)
                .and_then(|v| v.custom.clone())
        };
        stor.and_then(|s| _union_to_public_json(s, self.graph))
    }
    pub fn set_custom(&self, v: Option<Json<'_, G>>) {
        let stor = v.map(|u| u._to_storage(self.graph));
        self.graph.arena_of_claims().borrow_mut()[self.index as usize].custom = stor;
    }

    fn _id(&self) -> (u64, usize, usize) {
        (G::CLAIMS_TYPE_ID, self.graph as *const G as usize, self.index as usize)
    }

    fn _hash_with<H: std::hash::Hasher>(&self, state: &mut H, visited: &mut HashSet<(u64, usize, usize)>) {
        if !visited.insert(self._id()) { return; }
        self.subject().hash(state);
        self.issuer().hash(state);
        self.audience().hash(state);
        self.issued_at().hash(state);
        self.expires_at().hash(state);
        self.scopes().hash(state);
        if let Some(v) = self.custom() { v._hash_with(state, visited); }
    }

    fn _fmt_with(&self, f: &mut fmt::Formatter<'_>, visited: &mut HashSet<(u64, usize, usize)>) -> fmt::Result {
        if !visited.insert(self._id()) {
            return write!(f, "Claims@{}", self.index);
        }
        write!(f, "Claims@{} {{ ", self.index)?;
        write!(f, "subject: {:?}, ", self.subject())?;
        write!(f, "issuer: {:?}, ", self.issuer())?;
        write!(f, "audience: {:?}, ", self.audience())?;
        write!(f, "issued_at: {:?}, ", self.issued_at())?;
        write!(f, "expires_at: {:?}, ", self.expires_at())?;
        write!(f, "scopes: {:?}, ", self.scopes())?;
        write!(f, "custom: ")?;
        match self.custom() { Some(v) => v._fmt_with(f, visited)?, None => write!(f, "None")? };
        write!(f, " }}")
    }

    fn _cycle_eq<B: TokenGraph>(&self, other: &Claims<'_, B>,
        visited: &mut HashSet<((u64, usize, usize), (u64, usize, usize))>) -> bool {
        let pair = (self._id(), other._id());
        if visited.contains(&pair) { return true; }
        visited.insert(pair);
        if self.subject() != other.subject() { return false; }
        if self.issuer() != other.issuer() { return false; }
        if self.audience() != other.audience() { return false; }
        if self.issued_at() != other.issued_at() { return false; }
        if self.expires_at() != other.expires_at() { return false; }
        if self.scopes() != other.scopes() { return false; }
        match (self.custom(), other.custom()) {
            (None, None) => {}
            (Some(a), Some(b)) => { if !a._cycle_eq(&b, visited) { return false; } }
            _ => return false,
        }
        true
    }
}

impl<'a, 'b, A: TokenGraph, B: TokenGraph> PartialEq<Claims<'b, B>> for Claims<'a, A> {
    fn eq(&self, other: &Claims<'b, B>) -> bool {
        let mut v = HashSet::new(); self._cycle_eq(other, &mut v)
    }
}
impl<'arena, G: TokenGraph> Eq for Claims<'arena, G> {}

impl<'arena, G: TokenGraph> std::hash::Hash for Claims<'arena, G> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut v = HashSet::new(); self._hash_with(state, &mut v);
    }
}

impl<'arena, G: TokenGraph> fmt::Display for Claims<'arena, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v = HashSet::new(); self._fmt_with(f, &mut v)
    }
}

// ── JsonMember handle ────────────────────────────────────────────────────────
pub struct JsonMember<'arena, G: TokenGraph> {
    pub(crate) index: u32,
    pub(crate) graph: &'arena G,
}

impl<'arena, G: TokenGraph> Clone for JsonMember<'arena, G> {
    fn clone(&self) -> Self { JsonMember { index: self.index, graph: self.graph } }
}
impl<'arena, G: TokenGraph> Copy for JsonMember<'arena, G> {}

impl<'arena, G: TokenGraph> JsonMember<'arena, G> {
    pub fn key(&self) -> String {
        self.graph.arena_of_json_member().borrow()[self.index as usize].key.clone().unwrap_or_else(|| String::new())
    }
    pub fn set_key(&self, v: Option<&str>) {
        self.graph.arena_of_json_member().borrow_mut()[self.index as usize].key = v.map(str::to_owned);
    }
    pub fn value(&self) -> Option<Json<'arena, G>> {
        let stor = {
            let arena = self.graph.arena_of_json_member().borrow();
            arena.get(self.index as usize)
                .and_then(|v| v.value.clone())
        };
        stor.and_then(|s| _union_to_public_json(s, self.graph))
    }
    pub fn set_value(&self, v: Option<Json<'_, G>>) {
        let stor = v.map(|u| u._to_storage(self.graph));
        self.graph.arena_of_json_member().borrow_mut()[self.index as usize].value = stor;
    }

    fn _id(&self) -> (u64, usize, usize) {
        (G::JSONMEMBER_TYPE_ID, self.graph as *const G as usize, self.index as usize)
    }

    fn _hash_with<H: std::hash::Hasher>(&self, state: &mut H, visited: &mut HashSet<(u64, usize, usize)>) {
        if !visited.insert(self._id()) { return; }
        self.key().hash(state);
        if let Some(v) = self.value() { v._hash_with(state, visited); }
    }

    fn _fmt_with(&self, f: &mut fmt::Formatter<'_>, visited: &mut HashSet<(u64, usize, usize)>) -> fmt::Result {
        if !visited.insert(self._id()) {
            return write!(f, "JsonMember@{}", self.index);
        }
        write!(f, "JsonMember@{} {{ ", self.index)?;
        write!(f, "key: {:?}, ", self.key())?;
        write!(f, "value: ")?;
        match self.value() { Some(v) => v._fmt_with(f, visited)?, None => write!(f, "None")? };
        write!(f, " }}")
    }

    fn _cycle_eq<B: TokenGraph>(&self, other: &JsonMember<'_, B>,
        visited: &mut HashSet<((u64, usize, usize), (u64, usize, usize))>) -> bool {
        let pair = (self._id(), other._id());
        if visited.contains(&pair) { return true; }
        visited.insert(pair);
        if self.key() != other.key() { return false; }
        match (self.value(), other.value()) {
            (None, None) => {}
            (Some(a), Some(b)) => { if !a._cycle_eq(&b, visited) { return false; } }
            _ => return false,
        }
        true
    }
}

impl<'a, 'b, A: TokenGraph, B: TokenGraph> PartialEq<JsonMember<'b, B>> for JsonMember<'a, A> {
    fn eq(&self, other: &JsonMember<'b, B>) -> bool {
        let mut v = HashSet::new(); self._cycle_eq(other, &mut v)
    }
}
impl<'arena, G: TokenGraph> Eq for JsonMember<'arena, G> {}

impl<'arena, G: TokenGraph> std::hash::Hash for JsonMember<'arena, G> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut v = HashSet::new(); self._hash_with(state, &mut v);
    }
}

impl<'arena, G: TokenGraph> fmt::Display for JsonMember<'arena, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v = HashSet::new(); self._fmt_with(f, &mut v)
    }
}

// ── TokenArena<const ID: u64> ─────────────────────────────────────────────────────
pub struct TokenArena<const ID: u64> {
    arena_of_claims: RefCell<Vec<ClaimsValues>>,
    arena_of_json_member: RefCell<Vec<JsonMemberValues>>,
    root: Cell<Option<NodeRef>>,
}

impl<const ID: u64> ClaimsArena for TokenArena<ID> {
    const CLAIMS_TYPE_ID: u64 = ID * 100 + 0;
    fn arena_of_claims(&self) -> &RefCell<Vec<ClaimsValues>> {
        &self.arena_of_claims
    }
}

impl<const ID: u64> JsonMemberArena for TokenArena<ID> {
    const JSONMEMBER_TYPE_ID: u64 = ID * 100 + 1;
    fn arena_of_json_member(&self) -> &RefCell<Vec<JsonMemberValues>> {
        &self.arena_of_json_member
    }
}

impl<const ID: u64> TokenArena<ID> {
    pub fn new() -> Self {
        TokenArena {
            arena_of_claims: RefCell::new(Vec::new()),
            arena_of_json_member: RefCell::new(Vec::new()),
            root: Cell::new(None),
        }
    }

    pub fn get_root(&self) -> Option<Claims<'_, Self>> {
        self.root.get().and_then(|nr| {
            let a = self.arena_of_claims().borrow();
            a.get(nr.index as usize)
                .map(|_| Claims { index: nr.index, graph: self })
        })
    }

    pub fn set_root(&self, node: Option<Claims<'_, Self>>) {
        self.root.set(node.map(|h| NodeRef { index: h.index }));
    }
}

impl<const ID: u64> Default for TokenArena<ID> {
    fn default() -> Self { Self::new() }
}


// ── Serde: use dagr_runtime ─────────────────────────────────────────────────
use crate::dagr_runtime::{DagrBuilder, NodeStoreRef, UnionApplied, CycleId, DagrError};
use crate::dagr_runtime;

fn _store_union_json<'a, G: TokenGraph>(u: Json<'a, G>, b: &mut DagrBuilder) -> (u8, Option<usize>) {
    match u {
        Json::String(v) => {
            let _sc = b.store_string(&v);
            b.store_forward_pointer(_sc);
            (0u8, Some(b.cursor()))
        },
        Json::Number(v) => (1u8, Some(b.store_f64(v))),
        Json::Bool(v) => (2u8, Some(b.store_bool(v))),
        Json::Array(v) => {
            let mut _items = b.take_union_arr_scratch();
            _items.extend(v.into_iter().rev().map(|o| o.map(|u| _store_union_arr_json(u, b)).unwrap_or(dagr_runtime::UnionArrSlot::Nil)));
            let _c = b.store_union_optional_array(&_items, b.cursor(), 4);
            b.return_union_arr_scratch(_items);
            b.store_forward_pointer(_c);
            (3u8, Some(b.cursor()))
        },
        Json::Object(v) => {
            let mut _items = b.take_ref_scratch();
            _items.extend(v.iter().rev().map(|n| n.store(b).unwrap_or(NodeStoreRef::Offset(0))));
            let _c = b.store_node_ref_array(&_items, b.cursor());
            b.return_ref_scratch(_items);
            b.store_forward_pointer(_c);
            (4u8, Some(b.cursor()))
        },
        Json::Data(v) => {
            let _dc = b.store_blob(&v);
            b.store_forward_pointer(_dc);
            (5u8, Some(b.cursor()))
        },
        Json::Unknown(id) => (id, None),
    }
}

fn _store_union_field_json<'a, G: TokenGraph>(u: Json<'a, G>, b: &mut DagrBuilder) -> usize {
    match u {
        Json::String(v) => {
            let _c = b.store_string(&v);
            let _bef = b.cursor();
            b.store_forward_pointer(_c);
            let _wc = match b.cursor() - _bef { 1 => 0u64, 2 => 1, 4 => 2, _ => 3 };
            b.store_leb(0u64 << 2 | _wc)
        },
        Json::Number(v) => { b.store_f64(v); b.store_leb(1u64 << 2 | 3) },
        Json::Bool(v) => { b.store_bool(v); b.store_leb(2u64 << 2 | 0) },
        Json::Array(v) => {
            let mut _items = b.take_union_arr_scratch();
            _items.extend(v.into_iter().rev().map(|o| o.map(|u| _store_union_arr_json(u, b)).unwrap_or(dagr_runtime::UnionArrSlot::Nil)));
            let _c = b.store_union_optional_array(&_items, b.cursor(), 4);
            b.return_union_arr_scratch(_items);
            let _bef = b.cursor();
            b.store_forward_pointer(_c);
            let _wc = match b.cursor() - _bef { 1 => 0u64, 2 => 1, 4 => 2, _ => 3 };
            b.store_leb(3u64 << 2 | _wc)
        },
        Json::Object(v) => {
            let mut _items = b.take_ref_scratch();
            _items.extend(v.iter().rev().map(|n| n.store(b).unwrap_or(NodeStoreRef::Offset(0))));
            let _c = b.store_node_ref_array(&_items, b.cursor());
            b.return_ref_scratch(_items);
            let _bef = b.cursor();
            b.store_forward_pointer(_c);
            let _wc = match b.cursor() - _bef { 1 => 0u64, 2 => 1, 4 => 2, _ => 3 };
            b.store_leb(4u64 << 2 | _wc)
        },
        Json::Data(v) => {
            let _c = b.store_blob(&v);
            let _bef = b.cursor();
            b.store_forward_pointer(_c);
            let _wc = match b.cursor() - _bef { 1 => 0u64, 2 => 1, 4 => 2, _ => 3 };
            b.store_leb(5u64 << 2 | _wc)
        },
        Json::Unknown(id) => { b.store_u8(0u8); b.store_leb((id as u64) << 2) },
    }
}

fn _apply_union_field_json<'a, G: TokenGraph>(u: Json<'a, G>, b: &mut DagrBuilder) -> UnionApplied {
    match u {
        Json::String(v) => UnionApplied::FwdPtr(0u64, b.store_string(&v)),
        Json::Number(v) => UnionApplied::Value(1u64, 3u64, v.to_bits()),
        Json::Bool(v) => UnionApplied::Value(2u64, 0u64, v as u64),
        Json::Array(v) => {
            let mut _items = b.take_union_arr_scratch();
            _items.extend(v.into_iter().rev().map(|o| o.map(|u| _store_union_arr_json(u, b)).unwrap_or(dagr_runtime::UnionArrSlot::Nil)));
            let _c = b.store_union_optional_array(&_items, b.cursor(), 4);
            b.return_union_arr_scratch(_items);
            UnionApplied::FwdPtr(3u64, _c)
        },
        Json::Object(v) => {
            let mut _items = b.take_ref_scratch();
            _items.extend(v.iter().rev().map(|n| n.store(b).unwrap_or(NodeStoreRef::Offset(0))));
            let _c = b.store_node_ref_array(&_items, b.cursor());
            b.return_ref_scratch(_items);
            UnionApplied::FwdPtr(4u64, _c)
        },
        Json::Data(v) => UnionApplied::FwdPtr(5u64, b.store_blob(&v)),
        Json::Unknown(id) => UnionApplied::Value(id as u64, 0u64, 0u64),
    }
}

fn _store_union_arr_json<'a, G: TokenGraph>(u: Json<'a, G>, b: &mut DagrBuilder) -> crate::dagr_runtime::UnionArrSlot {
    use crate::dagr_runtime::UnionArrSlot;
    match u {
        Json::String(v) => UnionArrSlot::FwdPtr(0u8, b.store_string(&v)),
        Json::Number(v) => UnionArrSlot::Value(1u8, v.to_bits()),
        Json::Bool(v) => UnionArrSlot::Value(2u8, if v { 1u64 } else { 0u64 }),
        Json::Array(v) => {
            let mut _items = b.take_union_arr_scratch();
            _items.extend(v.into_iter().rev().map(|o| o.map(|u| _store_union_arr_json(u, b)).unwrap_or(dagr_runtime::UnionArrSlot::Nil)));
            let _c = b.store_union_optional_array(&_items, b.cursor(), 4);
            b.return_union_arr_scratch(_items);
            UnionArrSlot::FwdPtr(3u8, _c)
        },
        Json::Object(v) => {
            let mut _items = b.take_ref_scratch();
            _items.extend(v.iter().rev().map(|n| n.store(b).unwrap_or(NodeStoreRef::Offset(0))));
            let _c = b.store_node_ref_array(&_items, b.cursor());
            b.return_ref_scratch(_items);
            UnionArrSlot::FwdPtr(4u8, _c)
        },
        Json::Data(v) => UnionArrSlot::FwdPtr(5u8, b.store_blob(&v)),
        Json::Unknown(_) => UnionArrSlot::Nil,
    }
}

fn _supp_json<'a, G: TokenGraph>(u: Json<'a, G>, b: &mut DagrBuilder) -> Result<(u64, u64), DagrError> {
    let (_tid, _code): (u64, u64) = match u {
        Json::String(v) => { let _bs = v.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); (0u64, 6u64) },
        Json::Number(v) => { b.store_always_packed_f64(v); (1u64, 5u64) },
        Json::Bool(v) => { b.store_bool(v); (2u64, 1u64) },
        Json::Array(v) => {
                let _uav_arr = v;
                let _cnt_uav = _uav_arr.len();
                let _bef_uav = b.cursor();
                let _is_nil_uav: Vec<bool> = _uav_arr.iter().map(|x| x.is_none()).collect();
                let mut _tids_uav: Vec<u64> = Vec::new();
                let mut _codes_uav: Vec<u64> = Vec::new();
                for _e in _uav_arr.into_iter().rev() {
                    if let Some(_u) = _e {
                        let (_tid, _code): (u64, u64) = _supp_json(_u, b)?;
                        _tids_uav.push(_tid); _codes_uav.push(_code);
                    }
                }
                let _hbef_uav = b.cursor();
                for _i in 0.._tids_uav.len() { b.store_leb((_tids_uav[_i] << 3) | _codes_uav[_i]); }
                b.store_leb((b.cursor() - _hbef_uav) as u64);
                let _bs_uav = (_cnt_uav + 7) / 8;
                for _bi in (0.._bs_uav).rev() {
                    let mut _byte = 0u8;
                    for _bit in 0usize..8 {
                        let _idx = _bi * 8 + _bit;
                        if _idx < _cnt_uav && _is_nil_uav[_idx] { _byte |= 1u8 << _bit; }
                    }
                    b.store_u8(_byte);
                }
                b.store_leb(_cnt_uav as u64);
                b.store_leb((b.cursor() - _bef_uav) as u64);
                (3u64, 6u64)
            },
        Json::Object(v) => {
                let _uav_arr = v;
                let _cnt_uav = _uav_arr.len();
                let _bef_uav = b.cursor();
                for _e in _uav_arr.iter().rev() {
                    _e.store_packed(b)?;
                }
                b.store_leb(_cnt_uav as u64);
                b.store_leb((b.cursor() - _bef_uav) as u64);
                (4u64, 6u64)
            },
        Json::Data(v) => { b.store_raw(&v); b.store_leb(v.len() as u64); (5u64, 6u64) },
        Json::Unknown(id) => (id as u64, 1u64),
    };
    Ok((_tid, _code))
}

fn _store_prim_array(offsets: &[Option<usize>], content_cursor: usize, b: &mut DagrBuilder) -> usize {
    // Value refs (utf8/data/nested arrays): inline just before the table -> UNSIGNED slots (spec §4.5).
    let mut width_code = 0usize;
    for opt in offsets {
        if let Some(off) = opt {
            let rel = (content_cursor - *off + 1) as u64;
            let wc = if rel <= u8::MAX as u64 { 0 } else if rel <= u16::MAX as u64 { 1 } else if rel <= u32::MAX as u64 { 2 } else { 3 };
            if wc > width_code { width_code = wc; }
        }
    }
    for opt in offsets.iter() {
        match opt {
            Some(off) => { let rel = (content_cursor - *off + 1) as u64; b.store_uint_w(rel, width_code); }
            None => { b.store_uint_w(0, width_code); }
        }
    }
    b.store_leb(((offsets.len() as u64) << 2) | (width_code as u64))
}

// ── Claims serde ──────────────────────────────────────────────────────────
impl<'arena, G: TokenGraph> Claims<'arena, G> {
    pub fn store(&self, b: &mut DagrBuilder) -> Result<NodeStoreRef, DagrError> {
        let _id = CycleId { type_id: G::CLAIMS_TYPE_ID, index: self.index as usize };
        if let Some(r) = b.begin_storing_acyclic(_id) { return Ok(r); }
        let _ = self.store_packed(b)?;
        let _offset = b.cursor();
        b.record_node_offset(_id, _offset);
        Ok(NodeStoreRef::Offset(_offset))
    }

    pub fn store_packed(&self, b: &mut DagrBuilder) -> Result<NodeStoreRef, DagrError> {
        let _id = CycleId { type_id: G::CLAIMS_TYPE_ID, index: self.index as usize };
        let _before = b.cursor();
        let _pr_row = self.graph.arena_of_claims().borrow();
        let _pr = &_pr_row[self.index as usize];
        let mut _obs0 = 0u8;
        _obs0 |= u8::from(_pr.subject.is_some()) << 0;
        _obs0 |= u8::from(_pr.issuer.is_some()) << 1;
        _obs0 |= u8::from(_pr.audience.is_some()) << 2;
        _obs0 |= u8::from(!_pr.scopes.is_empty()) << 3;
        _obs0 |= u8::from(self.custom().is_some()) << 4;
        let mut _ebs0 = 0u8;
        { let _v_issued_at = self.issued_at(); _ebs0 |= u8::from(crate::dagr_runtime::leb_length(_v_issued_at as u64) >= 8) << 0; }
        { let _v_expires_at = self.expires_at(); _ebs0 |= u8::from(crate::dagr_runtime::leb_length(_v_expires_at as u64) >= 8) << 1; }
        if let Some(_u_custom) = self.custom() {
            let (_tid_custom, _code_custom): (u64, u64) = match _u_custom {
                Json::String(v) => { let _bs = v.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); (0u64, 6u64) },
                Json::Number(v) => { b.store_always_packed_f64(v); (1u64, 5u64) },
                Json::Bool(v) => { b.store_bool(v); (2u64, 1u64) },
                Json::Array(v) => {
                let _uav_arr = v;
                let _cnt_uav = _uav_arr.len();
                let _bef_uav = b.cursor();
                let _is_nil_uav: Vec<bool> = _uav_arr.iter().map(|x| x.is_none()).collect();
                let mut _tids_uav: Vec<u64> = Vec::new();
                let mut _codes_uav: Vec<u64> = Vec::new();
                for _e in _uav_arr.into_iter().rev() {
                    if let Some(_u) = _e {
                        let (_tid, _code): (u64, u64) = _supp_json(_u, b)?;
                        _tids_uav.push(_tid); _codes_uav.push(_code);
                    }
                }
                let _hbef_uav = b.cursor();
                for _i in 0.._tids_uav.len() { b.store_leb((_tids_uav[_i] << 3) | _codes_uav[_i]); }
                b.store_leb((b.cursor() - _hbef_uav) as u64);
                let _bs_uav = (_cnt_uav + 7) / 8;
                for _bi in (0.._bs_uav).rev() {
                    let mut _byte = 0u8;
                    for _bit in 0usize..8 {
                        let _idx = _bi * 8 + _bit;
                        if _idx < _cnt_uav && _is_nil_uav[_idx] { _byte |= 1u8 << _bit; }
                    }
                    b.store_u8(_byte);
                }
                b.store_leb(_cnt_uav as u64);
                b.store_leb((b.cursor() - _bef_uav) as u64);
                (3u64, 6u64)
            },
                Json::Object(v) => {
                let _uav_arr = v;
                let _cnt_uav = _uav_arr.len();
                let _bef_uav = b.cursor();
                for _e in _uav_arr.iter().rev() {
                    _e.store_packed(b)?;
                }
                b.store_leb(_cnt_uav as u64);
                b.store_leb((b.cursor() - _bef_uav) as u64);
                (4u64, 6u64)
            },
                Json::Data(v) => { b.store_raw(&v); b.store_leb(v.len() as u64); (5u64, 6u64) },
                Json::Unknown(id) => (id as u64, 1u64),
            };
            b.store_leb((_tid_custom << 3) | _code_custom);
        }
        {
            let _scopes_arr = &_pr.scopes;
            if !_scopes_arr.is_empty() {
                let _cnt_scopes = _scopes_arr.len();
                let _bef_scopes = b.cursor();
                for _e in _scopes_arr.iter().rev() { b.store_blob(_e.as_bytes()); }
                b.store_leb(_cnt_scopes as u64);
                b.store_leb((b.cursor() - _bef_scopes) as u64);
            }
        }
        if _ebs0 & 2 != 0 { b.store_u64(self.expires_at()); } else { b.store_leb(self.expires_at() as u64); }
        if _ebs0 & 1 != 0 { b.store_u64(self.issued_at()); } else { b.store_leb(self.issued_at() as u64); }
        if let Some(_s_audience) = _pr.audience.as_deref() {
            let _bs_audience = _s_audience.as_bytes();
            b.store_raw(_bs_audience);
            b.store_leb(_bs_audience.len() as u64);
        }
        if let Some(_s_issuer) = _pr.issuer.as_deref() {
            let _bs_issuer = _s_issuer.as_bytes();
            b.store_raw(_bs_issuer);
            b.store_leb(_bs_issuer.len() as u64);
        }
        if let Some(_s_subject) = _pr.subject.as_deref() {
            let _bs_subject = _s_subject.as_bytes();
            b.store_raw(_bs_subject);
            b.store_leb(_bs_subject.len() as u64);
        }
        b.store_u8(_ebs0);
        b.store_u8(_obs0);
        b.store_leb((b.cursor() - _before) as u64);
        b.record_node_offset(_id, b.cursor());
        Ok(NodeStoreRef::Offset(b.cursor()))
    }
}

// ── JsonMember serde ──────────────────────────────────────────────────────────
impl<'arena, G: TokenGraph> JsonMember<'arena, G> {
    pub fn store(&self, b: &mut DagrBuilder) -> Result<NodeStoreRef, DagrError> {
        let _id = CycleId { type_id: G::JSONMEMBER_TYPE_ID, index: self.index as usize };
        if let Some(r) = b.begin_storing(_id) { return Ok(r); }
        let _ = self.store_packed(b)?;
        let _offset = b.cursor();
        b.finish_storing(_id, _offset);
        Ok(NodeStoreRef::Offset(_offset))
    }

    pub fn store_packed(&self, b: &mut DagrBuilder) -> Result<NodeStoreRef, DagrError> {
        let _id = CycleId { type_id: G::JSONMEMBER_TYPE_ID, index: self.index as usize };
        let _before = b.begin_packed_storing(_id).ok_or(DagrError::CycleWhilePackedStoring)?;
        let mut _obs0 = 0u8;
        _obs0 |= u8::from(self.value().is_some()) << 0;
        if let Some(_u_value) = self.value() {
            let (_tid_value, _code_value): (u64, u64) = match _u_value {
                Json::String(v) => { let _bs = v.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); (0u64, 6u64) },
                Json::Number(v) => { b.store_always_packed_f64(v); (1u64, 5u64) },
                Json::Bool(v) => { b.store_bool(v); (2u64, 1u64) },
                Json::Array(v) => {
                let _uav_arr = v;
                let _cnt_uav = _uav_arr.len();
                let _bef_uav = b.cursor();
                let _is_nil_uav: Vec<bool> = _uav_arr.iter().map(|x| x.is_none()).collect();
                let mut _tids_uav: Vec<u64> = Vec::new();
                let mut _codes_uav: Vec<u64> = Vec::new();
                for _e in _uav_arr.into_iter().rev() {
                    if let Some(_u) = _e {
                        let (_tid, _code): (u64, u64) = _supp_json(_u, b)?;
                        _tids_uav.push(_tid); _codes_uav.push(_code);
                    }
                }
                let _hbef_uav = b.cursor();
                for _i in 0.._tids_uav.len() { b.store_leb((_tids_uav[_i] << 3) | _codes_uav[_i]); }
                b.store_leb((b.cursor() - _hbef_uav) as u64);
                let _bs_uav = (_cnt_uav + 7) / 8;
                for _bi in (0.._bs_uav).rev() {
                    let mut _byte = 0u8;
                    for _bit in 0usize..8 {
                        let _idx = _bi * 8 + _bit;
                        if _idx < _cnt_uav && _is_nil_uav[_idx] { _byte |= 1u8 << _bit; }
                    }
                    b.store_u8(_byte);
                }
                b.store_leb(_cnt_uav as u64);
                b.store_leb((b.cursor() - _bef_uav) as u64);
                (3u64, 6u64)
            },
                Json::Object(v) => {
                let _uav_arr = v;
                let _cnt_uav = _uav_arr.len();
                let _bef_uav = b.cursor();
                for _e in _uav_arr.iter().rev() {
                    _e.store_packed(b)?;
                }
                b.store_leb(_cnt_uav as u64);
                b.store_leb((b.cursor() - _bef_uav) as u64);
                (4u64, 6u64)
            },
                Json::Data(v) => { b.store_raw(&v); b.store_leb(v.len() as u64); (5u64, 6u64) },
                Json::Unknown(id) => (id as u64, 1u64),
            };
            b.store_leb((_tid_value << 3) | _code_value);
        }
        { let _s_key = self.key();
          let _bs_key = _s_key.as_bytes();
          b.store_raw(_bs_key); b.store_leb(_bs_key.len() as u64); }
        b.store_u8(_obs0);
        b.store_leb((b.cursor() - _before) as u64);
        b.finish_packed_storing(_id);
        Ok(NodeStoreRef::Offset(b.cursor()))
    }
}

fn _restore_union_noderef_json<'arena, G: TokenGraph>(
    data: &'arena [u8], at: usize, tid: u8, _arena: &'arena G,
    _cache: &mut std::collections::HashMap<(u64, usize), u32>,
) -> Result<Json<'arena, G>, DagrError> {
    match tid {
        0 => Ok(Json::String(crate::dagr_runtime::read_string(data, at)?)),
        1 => Ok(Json::Number(crate::dagr_runtime::read_f64(data, at)? as f64)),
        2 => Ok(Json::Bool(crate::dagr_runtime::read_bool(data, at)?)),
        3 => Err(DagrError::InvalidData),  // unsupported variant arrayWithOptionals
        4 => Err(DagrError::InvalidData),  // unsupported variant array
        5 => Ok(Json::Data(crate::dagr_runtime::read_blob(data, at)?)),
        id => Ok(Json::Unknown(id)),
    }
}

fn _restore_union_arr_json<'arena, G: TokenGraph>(data: &'arena [u8], at: usize, arena: &'arena G,
    cache: &mut std::collections::HashMap<(u64, usize), u32>) -> Result<Vec<Json<'arena, G>>, DagrError> {
    let (_slots, _base) = dagr_runtime::read_union_array(data, at, 4)?;
    _slots.into_iter().map(|(_tid, _raw)| -> Result<Json<'arena, G>, DagrError> { Ok(match _tid {
        0u8 => Json::String(dagr_runtime::read_string(data, _base + _raw as usize)?),
        1u8 => Json::Number(f64::from_bits(_raw)),
        2u8 => Json::Bool(_raw != 0),
        3u8 => { let _p = _base + _raw as usize; Json::Array(_restore_union_arr_opt_json(data, _p, arena, cache)?) },
        4u8 => { let _p = _base + _raw as usize; let _refs = crate::dagr_runtime::read_node_ref_array(data, _p)?; let mut _out = Vec::new(); for _r in _refs { if let Some(_o) = _r { _out.push(_restore_json_member(data, _o, arena, cache)?); } } Json::Object(_out) },
        5u8 => Json::Data(dagr_runtime::read_blob(data, _base + _raw as usize)?),
        _id => Json::Unknown(_id),
    }) }).collect()
}

fn _restore_union_arr_opt_json<'arena, G: TokenGraph>(data: &'arena [u8], at: usize, arena: &'arena G,
    cache: &mut std::collections::HashMap<(u64, usize), u32>) -> Result<Vec<Option<Json<'arena, G>>>, DagrError> {
    let (_slots, _base) = dagr_runtime::read_union_optional_array(data, at, 4)?;
    _slots.into_iter().map(|_slot_opt| -> Result<Option<Json<'arena, G>>, DagrError> { match _slot_opt {
        None => Ok(None),
        Some((_tid, _raw)) => Ok(Some(match _tid {
            0u8 => Json::String(dagr_runtime::read_string(data, _base + _raw as usize)?),
            1u8 => Json::Number(f64::from_bits(_raw)),
            2u8 => Json::Bool(_raw != 0),
            3u8 => { let _p = _base + _raw as usize; Json::Array(_restore_union_arr_opt_json(data, _p, arena, cache)?) },
            4u8 => { let _p = _base + _raw as usize; let _refs = crate::dagr_runtime::read_node_ref_array(data, _p)?; let mut _out = Vec::new(); for _r in _refs { if let Some(_o) = _r { _out.push(_restore_json_member(data, _o, arena, cache)?); } } Json::Object(_out) },
            5u8 => Json::Data(dagr_runtime::read_blob(data, _base + _raw as usize)?),
            _id => Json::Unknown(_id),
        })),
    } }).collect()
}

fn _restore_union_noderef_vtable_json<'arena, G: TokenGraph>(
    data: &'arena [u8], at: usize, tid: u8, arena: &'arena G,
    cache: &mut std::collections::HashMap<(u64, usize), u32>,
) -> Result<Json<'arena, G>, DagrError> {
    match tid {
        0 => { let _p = crate::dagr_runtime::read_forward_pointer(data, at)?; Ok(Json::String(crate::dagr_runtime::read_string(data, _p)?)) },
        1 => Ok(Json::Number(crate::dagr_runtime::read_f64(data, at)? as f64)),
        2 => Ok(Json::Bool(crate::dagr_runtime::read_bool(data, at)?)),
        3 => {
            let _p = crate::dagr_runtime::read_forward_pointer(data, at)?;
            Ok(Json::Array(_restore_union_arr_opt_json(data, _p, arena, cache)?))
        }
        4 => {
            let _p = crate::dagr_runtime::read_forward_pointer(data, at)?;
            let _refs = crate::dagr_runtime::read_node_ref_array(data, _p)?;
            let mut _out = Vec::new();
            for _r in _refs { if let Some(_o) = _r { _out.push(_restore_json_member(data, _o, arena, cache)?); } }
            Ok(Json::Object(_out))
        }
        5 => { let _p = crate::dagr_runtime::read_forward_pointer(data, at)?; Ok(Json::Data(crate::dagr_runtime::read_blob(data, _p)?)) },
        id => Ok(Json::Unknown(id)),
    }
}

fn _rpup_json<'arena, G: TokenGraph>(
    data: &'arena [u8], mut _pos: usize, _utid: u8, _ucode: u8,
    arena: &'arena G, cache: &mut std::collections::HashMap<(u64, usize), u32>,
) -> Result<(Json<'arena, G>, usize), DagrError> {
    let _ = (&arena, &cache);
    let mut _uo: Vec<Json<'arena, G>> = Vec::with_capacity(1);
    match _utid {
        0 => {
            let (_sl_0, _sb_0) = crate::dagr_runtime::read_leb(data, _pos)?;
            let _ss_0 = String::from_utf8_lossy(data.get(_pos+_sb_0.._pos+_sb_0+_sl_0 as usize).ok_or(DagrError::InvalidData)?).into_owned();
            _uo.push(Json::String(_ss_0));
            _pos += _sb_0 + _sl_0 as usize;
        }
        1 => {
            let (_v_1, _vb_1) = crate::dagr_runtime::read_packed_f64(data, _pos)?;
            _uo.push(Json::Number(_v_1));
            _pos += _vb_1;
        }
        2 => {
            _uo.push(Json::Bool(crate::dagr_runtime::read_bool(data, _pos)?));
            _pos += 1;
        }
        3 => {
            let (_bsz_3, _blb_3) = crate::dagr_runtime::read_leb(data, _pos)?;
            let _cntpos_3 = _pos + _blb_3;
            let _blkend_3 = _cntpos_3 + _bsz_3 as usize;
            let (_uacnt_3, _uaclb_3) = crate::dagr_runtime::read_leb(data, _cntpos_3)?;
            let _uacount_3 = _uacnt_3 as usize;
            let _ubs_3 = _cntpos_3 + _uaclb_3;
            let _ubsc_3 = (_uacount_3 + 7) / 8;
            let mut _uap_3 = _ubs_3 + _ubsc_3;
            let (_uhss_3, _uhssb_3) = crate::dagr_runtime::read_leb(data, _uap_3)?; _uap_3 += _uhssb_3;
            let _uhend_3 = _uap_3 + _uhss_3 as usize;
            let mut _uhdrs_3: Vec<u64> = Vec::new();
            while _uap_3 < _uhend_3 { let (_h, _hb) = crate::dagr_runtime::read_leb(data, _uap_3)?; _uhdrs_3.push(_h); _uap_3 += _hb; }
            let mut _av_3 = Vec::with_capacity(_uacount_3);
            let mut _upp_3 = _uap_3;
            let mut _uhi_3 = 0usize;
            for _uei_3 in 0.._uacount_3 {
                if (data.get(_ubs_3 + _uei_3/8).copied().unwrap_or(0) >> (_uei_3%8) & 1) != 0 { _av_3.push(None); continue; }
                let _uhdr = _uhdrs_3.get(_uhi_3).copied().ok_or(DagrError::InvalidData)?; _uhi_3 += 1;
                let _utid = (_uhdr >> 3) as u8;
                let _ucode = (_uhdr & 7) as u8;
                let (_uitem, _unp) = _rpup_json(data, _upp_3, _utid, _ucode, arena, cache)?;
                _upp_3 = _unp;
                _av_3.push(Some(_uitem));
            }
            _pos = _blkend_3;
            _uo.push(Json::Array(_av_3));
        }
        4 => {
            let (_bsz_4, _blb_4) = crate::dagr_runtime::read_leb(data, _pos)?;
            let _cntpos_4 = _pos + _blb_4;
            let _blkend_4 = _cntpos_4 + _bsz_4 as usize;
            let (_acnt_4, _aclb_4) = crate::dagr_runtime::read_leb(data, _cntpos_4)?;
            let mut _ep_4 = _cntpos_4 + _aclb_4;
            let mut _av_4 = Vec::with_capacity(_acnt_4 as usize);
            for _ in 0.._acnt_4 { let (_esz, _elb) = crate::dagr_runtime::read_leb(data, _ep_4)?; let _eat = _ep_4; _ep_4 += _elb + _esz as usize; _av_4.push(_restore_json_member(data, _eat, arena, cache)?); }
            _pos = _blkend_4;
            _uo.push(Json::Object(_av_4));
        }
        5 => {
            let (_dl_5, _db_5) = crate::dagr_runtime::read_leb(data, _pos)?;
            let _dd_5 = data.get(_pos+_db_5.._pos+_db_5+_dl_5 as usize).ok_or(DagrError::InvalidData)?.to_vec();
            _uo.push(Json::Data(_dd_5));
            _pos += _db_5 + _dl_5 as usize;
        }
        id if (id as u64) < 16 as u64 => _uo.push(Json::Unknown(id)),
        _ => return Err(DagrError::InvalidData),
    }
    Ok((_uo.pop().ok_or(DagrError::InvalidData)?, _pos))
}

fn _restore_claims<'arena, G: TokenGraph>(
    data: &'arena [u8], at: usize, arena: &'arena G,
    cache: &mut std::collections::HashMap<(u64, usize), u32>,
) -> Result<Claims<'arena, G>, DagrError> {
    if at >= data.len() { return Err(DagrError::InvalidData); }
    let _cache_key = (G::CLAIMS_TYPE_ID, at);
    if let Some(&idx) = cache.get(&_cache_key) {
        let a = arena.arena_of_claims().borrow();
        let _ = &a;
        return Ok(Claims { index: idx, graph: arena });
    }
    let (_, _fp_leb_sz) = crate::dagr_runtime::read_leb(data, at)?;
    let _obs0 = *data.get(at + _fp_leb_sz + 0).ok_or(DagrError::InvalidData)?;
    let _ebs0 = *data.get(at + _fp_leb_sz + 1).ok_or(DagrError::InvalidData)?;
    let _blank = ClaimsValues { subject: None, issuer: None, audience: None, issued_at: 0u64, expires_at: 0u64, scopes: vec![], custom: None };
    let _idx = {
        let mut _arr = arena.arena_of_claims().borrow_mut();
        let idx = _arr.len() as u32;
        _arr.push(_blank);
        idx
    };
    let _node = Claims { index: _idx, graph: arena };
    cache.insert(_cache_key, _node.index);
    let mut _cur = at + _fp_leb_sz + 2;
    let _subject_val = if _obs0 & 1 != 0 {
        let (_sv_subject, _slb_subject) = crate::dagr_runtime::read_leb(data, _cur)?;
        _cur += _slb_subject;
        let _s_subject = String::from_utf8_lossy(data.get(_cur.._cur + _sv_subject as usize).ok_or(DagrError::InvalidData)?).into_owned();
        _cur += _sv_subject as usize;
        Some(_s_subject)
    } else { None };
    let _issuer_val = if _obs0 & 2 != 0 {
        let (_sv_issuer, _slb_issuer) = crate::dagr_runtime::read_leb(data, _cur)?;
        _cur += _slb_issuer;
        let _s_issuer = String::from_utf8_lossy(data.get(_cur.._cur + _sv_issuer as usize).ok_or(DagrError::InvalidData)?).into_owned();
        _cur += _sv_issuer as usize;
        Some(_s_issuer)
    } else { None };
    let _audience_val = if _obs0 & 4 != 0 {
        let (_sv_audience, _slb_audience) = crate::dagr_runtime::read_leb(data, _cur)?;
        _cur += _slb_audience;
        let _s_audience = String::from_utf8_lossy(data.get(_cur.._cur + _sv_audience as usize).ok_or(DagrError::InvalidData)?).into_owned();
        _cur += _sv_audience as usize;
        Some(_s_audience)
    } else { None };
    let _issued_at_val = if _ebs0 & 1 != 0 {
        let _rv = crate::dagr_runtime::read_u64(data, _cur)? as u64; _cur += 8; _rv
    } else {
        let (_lv, _lb) = crate::dagr_runtime::read_leb(data, _cur)?; _cur += _lb; _lv as u64
    };
    let _expires_at_val = if _ebs0 & 2 != 0 {
        let _rv = crate::dagr_runtime::read_u64(data, _cur)? as u64; _cur += 8; _rv
    } else {
        let (_lv, _lb) = crate::dagr_runtime::read_leb(data, _cur)?; _cur += _lb; _lv as u64
    };
    let _scopes_val = if _obs0 & 8 != 0 {
        let (_bsz_scopes, _blb_scopes) = crate::dagr_runtime::read_leb(data, _cur)?;
        _cur += _blb_scopes;
        let _arr_end_scopes = _cur + _bsz_scopes as usize;
        let (_cnt_scopes, _clb_scopes) = crate::dagr_runtime::read_leb(data, _cur)?;
        _cur += _clb_scopes;
        let mut _arr_scopes = Vec::with_capacity(_cnt_scopes as usize);
        _arr_scopes = crate::dagr_runtime::PackedStrArray::new(data, _cur - _clb_scopes)?.iter().map(|r| r.map(|s| s.to_string())).collect::<Result<Vec<_>, _>>()?;
        _cur = _arr_end_scopes;
        _cur = _arr_end_scopes;
        _arr_scopes
    } else { vec![] };
    let _custom_val = if _obs0 & 16 != 0 {
        let (_comb_custom, _comb_b_custom) = crate::dagr_runtime::read_leb(data, _cur)?;
        _cur += _comb_b_custom;
        let _type_custom = (_comb_custom >> 3) as u8;
        let _enc_custom = (_comb_custom & 7) as u8;
        let mut _evp_custom = _cur;
        let mut _tmp_custom = Vec::with_capacity(1);
        match _type_custom {
            0 => {
                let (_sl_0, _sb_0) = crate::dagr_runtime::read_leb(data, _evp_custom)?;
                let _ss_0 = String::from_utf8_lossy(data.get(_evp_custom+_sb_0.._evp_custom+_sb_0+_sl_0 as usize).ok_or(DagrError::InvalidData)?).into_owned();
                _tmp_custom.push(Some(Json::String(_ss_0)));
                _evp_custom += _sb_0 + _sl_0 as usize;
            }
            1 => {
                let (_v_1, _vb_1) = crate::dagr_runtime::read_packed_f64(data, _evp_custom)?;
                _tmp_custom.push(Some(Json::Number(_v_1)));
                _evp_custom += _vb_1;
            }
            2 => {
                _tmp_custom.push(Some(Json::Bool(crate::dagr_runtime::read_bool(data, _evp_custom)?)));
                _evp_custom += 1;
            }
            3 => {
                let (_bsz_3, _blb_3) = crate::dagr_runtime::read_leb(data, _evp_custom)?;
                let _cntpos_3 = _evp_custom + _blb_3;
                let _blkend_3 = _cntpos_3 + _bsz_3 as usize;
                let (_uacnt_3, _uaclb_3) = crate::dagr_runtime::read_leb(data, _cntpos_3)?;
                let _uacount_3 = _uacnt_3 as usize;
                let _ubs_3 = _cntpos_3 + _uaclb_3;
                let _ubsc_3 = (_uacount_3 + 7) / 8;
                let mut _uap_3 = _ubs_3 + _ubsc_3;
                let (_uhss_3, _uhssb_3) = crate::dagr_runtime::read_leb(data, _uap_3)?; _uap_3 += _uhssb_3;
                let _uhend_3 = _uap_3 + _uhss_3 as usize;
                let mut _uhdrs_3: Vec<u64> = Vec::new();
                while _uap_3 < _uhend_3 { let (_h, _hb) = crate::dagr_runtime::read_leb(data, _uap_3)?; _uhdrs_3.push(_h); _uap_3 += _hb; }
                let mut _av_3 = Vec::with_capacity(_uacount_3);
                let mut _upp_3 = _uap_3;
                let mut _uhi_3 = 0usize;
                for _uei_3 in 0.._uacount_3 {
                    if (data.get(_ubs_3 + _uei_3/8).copied().unwrap_or(0) >> (_uei_3%8) & 1) != 0 { _av_3.push(None); continue; }
                    let _uhdr = _uhdrs_3.get(_uhi_3).copied().ok_or(DagrError::InvalidData)?; _uhi_3 += 1;
                    let _utid = (_uhdr >> 3) as u8;
                    let _ucode = (_uhdr & 7) as u8;
                    let (_uitem, _unp) = _rpup_json(data, _upp_3, _utid, _ucode, arena, cache)?;
                    _upp_3 = _unp;
                    _av_3.push(Some(_uitem));
                }
                _evp_custom = _blkend_3;
                _tmp_custom.push(Some(Json::Array(_av_3)));
            }
            4 => {
                let (_bsz_4, _blb_4) = crate::dagr_runtime::read_leb(data, _evp_custom)?;
                let _cntpos_4 = _evp_custom + _blb_4;
                let _blkend_4 = _cntpos_4 + _bsz_4 as usize;
                let (_acnt_4, _aclb_4) = crate::dagr_runtime::read_leb(data, _cntpos_4)?;
                let mut _ep_4 = _cntpos_4 + _aclb_4;
                let mut _av_4 = Vec::with_capacity(_acnt_4 as usize);
                for _ in 0.._acnt_4 { let (_esz, _elb) = crate::dagr_runtime::read_leb(data, _ep_4)?; let _eat = _ep_4; _ep_4 += _elb + _esz as usize; _av_4.push(_restore_json_member(data, _eat, arena, cache)?); }
                _evp_custom = _blkend_4;
                _tmp_custom.push(Some(Json::Object(_av_4)));
            }
            5 => {
                let (_dl_5, _db_5) = crate::dagr_runtime::read_leb(data, _evp_custom)?;
                let _dd_5 = data.get(_evp_custom+_db_5.._evp_custom+_db_5+_dl_5 as usize).ok_or(DagrError::InvalidData)?.to_vec();
                _tmp_custom.push(Some(Json::Data(_dd_5)));
                _evp_custom += _db_5 + _dl_5 as usize;
            }
            _ => return Err(DagrError::InvalidData),
        }
        _cur = _evp_custom;
        _tmp_custom.pop().flatten()
    } else { None };
    _node.set_subject(_subject_val.as_deref());
    _node.set_issuer(_issuer_val.as_deref());
    _node.set_audience(_audience_val.as_deref());
    _node.set_issued_at(_issued_at_val);
    _node.set_expires_at(_expires_at_val);
    _node.set_scopes(_scopes_val);
    _node.set_custom(_custom_val);
    Ok(_node)
}

fn _restore_json_member<'arena, G: TokenGraph>(
    data: &'arena [u8], at: usize, arena: &'arena G,
    cache: &mut std::collections::HashMap<(u64, usize), u32>,
) -> Result<JsonMember<'arena, G>, DagrError> {
    if at >= data.len() { return Err(DagrError::InvalidData); }
    let _cache_key = (G::JSONMEMBER_TYPE_ID, at);
    if let Some(&idx) = cache.get(&_cache_key) {
        let a = arena.arena_of_json_member().borrow();
        let _ = &a;
        return Ok(JsonMember { index: idx, graph: arena });
    }
    let (_, _fp_leb_sz) = crate::dagr_runtime::read_leb(data, at)?;
    let _obs0 = *data.get(at + _fp_leb_sz + 0).ok_or(DagrError::InvalidData)?;
    let _blank = JsonMemberValues { key: None, value: None };
    let _idx = {
        let mut _arr = arena.arena_of_json_member().borrow_mut();
        let idx = _arr.len() as u32;
        _arr.push(_blank);
        idx
    };
    let _node = JsonMember { index: _idx, graph: arena };
    cache.insert(_cache_key, _node.index);
    let mut _cur = at + _fp_leb_sz + 1;
    let _key_val = if _cur < data.len() {
        let (_sv_key, _slb_key) = crate::dagr_runtime::read_leb(data, _cur)?;
        _cur += _slb_key;
        let _s_key = String::from_utf8_lossy(data.get(_cur.._cur + _sv_key as usize).ok_or(DagrError::InvalidData)?).into_owned();
        _cur += _sv_key as usize;
        Some(_s_key)
    } else { None };
    let _value_val = if _obs0 & 1 != 0 {
        let (_comb_value, _comb_b_value) = crate::dagr_runtime::read_leb(data, _cur)?;
        _cur += _comb_b_value;
        let _type_value = (_comb_value >> 3) as u8;
        let _enc_value = (_comb_value & 7) as u8;
        let mut _evp_value = _cur;
        let mut _tmp_value = Vec::with_capacity(1);
        match _type_value {
            0 => {
                let (_sl_0, _sb_0) = crate::dagr_runtime::read_leb(data, _evp_value)?;
                let _ss_0 = String::from_utf8_lossy(data.get(_evp_value+_sb_0.._evp_value+_sb_0+_sl_0 as usize).ok_or(DagrError::InvalidData)?).into_owned();
                _tmp_value.push(Some(Json::String(_ss_0)));
                _evp_value += _sb_0 + _sl_0 as usize;
            }
            1 => {
                let (_v_1, _vb_1) = crate::dagr_runtime::read_packed_f64(data, _evp_value)?;
                _tmp_value.push(Some(Json::Number(_v_1)));
                _evp_value += _vb_1;
            }
            2 => {
                _tmp_value.push(Some(Json::Bool(crate::dagr_runtime::read_bool(data, _evp_value)?)));
                _evp_value += 1;
            }
            3 => {
                let (_bsz_3, _blb_3) = crate::dagr_runtime::read_leb(data, _evp_value)?;
                let _cntpos_3 = _evp_value + _blb_3;
                let _blkend_3 = _cntpos_3 + _bsz_3 as usize;
                let (_uacnt_3, _uaclb_3) = crate::dagr_runtime::read_leb(data, _cntpos_3)?;
                let _uacount_3 = _uacnt_3 as usize;
                let _ubs_3 = _cntpos_3 + _uaclb_3;
                let _ubsc_3 = (_uacount_3 + 7) / 8;
                let mut _uap_3 = _ubs_3 + _ubsc_3;
                let (_uhss_3, _uhssb_3) = crate::dagr_runtime::read_leb(data, _uap_3)?; _uap_3 += _uhssb_3;
                let _uhend_3 = _uap_3 + _uhss_3 as usize;
                let mut _uhdrs_3: Vec<u64> = Vec::new();
                while _uap_3 < _uhend_3 { let (_h, _hb) = crate::dagr_runtime::read_leb(data, _uap_3)?; _uhdrs_3.push(_h); _uap_3 += _hb; }
                let mut _av_3 = Vec::with_capacity(_uacount_3);
                let mut _upp_3 = _uap_3;
                let mut _uhi_3 = 0usize;
                for _uei_3 in 0.._uacount_3 {
                    if (data.get(_ubs_3 + _uei_3/8).copied().unwrap_or(0) >> (_uei_3%8) & 1) != 0 { _av_3.push(None); continue; }
                    let _uhdr = _uhdrs_3.get(_uhi_3).copied().ok_or(DagrError::InvalidData)?; _uhi_3 += 1;
                    let _utid = (_uhdr >> 3) as u8;
                    let _ucode = (_uhdr & 7) as u8;
                    let (_uitem, _unp) = _rpup_json(data, _upp_3, _utid, _ucode, arena, cache)?;
                    _upp_3 = _unp;
                    _av_3.push(Some(_uitem));
                }
                _evp_value = _blkend_3;
                _tmp_value.push(Some(Json::Array(_av_3)));
            }
            4 => {
                let (_bsz_4, _blb_4) = crate::dagr_runtime::read_leb(data, _evp_value)?;
                let _cntpos_4 = _evp_value + _blb_4;
                let _blkend_4 = _cntpos_4 + _bsz_4 as usize;
                let (_acnt_4, _aclb_4) = crate::dagr_runtime::read_leb(data, _cntpos_4)?;
                let mut _ep_4 = _cntpos_4 + _aclb_4;
                let mut _av_4 = Vec::with_capacity(_acnt_4 as usize);
                for _ in 0.._acnt_4 { let (_esz, _elb) = crate::dagr_runtime::read_leb(data, _ep_4)?; let _eat = _ep_4; _ep_4 += _elb + _esz as usize; _av_4.push(_restore_json_member(data, _eat, arena, cache)?); }
                _evp_value = _blkend_4;
                _tmp_value.push(Some(Json::Object(_av_4)));
            }
            5 => {
                let (_dl_5, _db_5) = crate::dagr_runtime::read_leb(data, _evp_value)?;
                let _dd_5 = data.get(_evp_value+_db_5.._evp_value+_db_5+_dl_5 as usize).ok_or(DagrError::InvalidData)?.to_vec();
                _tmp_value.push(Some(Json::Data(_dd_5)));
                _evp_value += _db_5 + _dl_5 as usize;
            }
            _ => return Err(DagrError::InvalidData),
        }
        _cur = _evp_value;
        _tmp_value.pop().flatten()
    } else { None };
    _node.set_key(_key_val.as_deref());
    _node.set_value(_value_val);
    Ok(_node)
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Jws {
    pub algorithm: String,
    pub key_id: Option<String>,
    pub signature: Vec<u8>,
}

impl Jws {
    pub fn store_packed(&self, b: &mut crate::dagr_runtime::DagrBuilder) {
        let _before = b.cursor();
        { let _bs: &[u8] = self.signature.as_slice(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((2u64 << 1) | 1); }
        if let Some(ref _v) = self.key_id {
            { let _bs = _v.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((1u64 << 1) | 1); }
        }
        { let _bs = self.algorithm.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); b.store_leb((0u64 << 1) | 1); }
        b.store_leb((b.cursor() - _before) as u64);
    }

    pub fn restore(data: &[u8], at: usize) -> Self {
        use crate::dagr_runtime::*;
        let mut values = Jws::default();
        let (_bl, _blb) = read_leb(data, at).unwrap_or((0, 1));
        let mut _cursor = at + _blb;
        let _end = _cursor + _bl as usize;
        if _cursor < _end {
            let (_tag, _tagb) = read_leb(data, _cursor).unwrap_or((0, 1));
            if (_tag >> 1) as usize == 0 {
                _cursor += _tagb;
                let (_sv, _sb) = read_leb(data, _cursor).unwrap_or((0, 1)); _cursor += _sb;
                values.algorithm = String::from_utf8_lossy(&data[_cursor.._cursor + _sv as usize]).into_owned(); _cursor += _sv as usize;
            }
        }
        if _cursor < _end {
            let (_tag, _tagb) = read_leb(data, _cursor).unwrap_or((0, 1));
            if (_tag >> 1) as usize == 1 {
                _cursor += _tagb;
                let (_sv, _sb) = read_leb(data, _cursor).unwrap_or((0, 1)); _cursor += _sb;
                values.key_id = Some(String::from_utf8_lossy(&data[_cursor.._cursor + _sv as usize]).into_owned()); _cursor += _sv as usize;
            }
        }
        if _cursor < _end {
            let (_tag, _tagb) = read_leb(data, _cursor).unwrap_or((0, 1));
            if (_tag >> 1) as usize == 2 {
                _cursor += _tagb;
                let (_dv, _db) = read_leb(data, _cursor).unwrap_or((0, 1)); _cursor += _db;
                values.signature = data[_cursor.._cursor + _dv as usize].to_vec(); _cursor += _dv as usize;
            }
        }
        values
    }
}

// ── Arena serde ─────────────────────────────────────────────────────────────
impl<const ID: u64> TokenArena<ID> {
    pub fn to_bytes_with_header<F>(&self, header_fn: F) -> Result<Vec<u8>, DagrError>
    where F: FnOnce(usize, &[u8]) -> Jws {
        let root = self.get_root().ok_or(DagrError::StaleReference)?;
        let mut b = DagrBuilder::with_hint(self.arena_of_claims().borrow().len() + self.arena_of_json_member().borrow().len());
        let root_ref = root.store(&mut b)?;
        let root_off = root_ref.to_offset().unwrap_or(0);
        let original_offset = b.cursor() - root_off;
        let body = b.finalize();
        let header_value = header_fn(original_offset, &body);
        let mut hb = DagrBuilder::new();
        header_value.store_packed(&mut hb);
        let header_bytes = hb.finalize();
        let h = header_bytes.len();
        let stored_offset = (((original_offset + h) as u64) << 2) | 0b01;
        let mut fb = DagrBuilder::new();
        fb.store_leb(stored_offset);
        let framing = fb.finalize();
        let mut out = Vec::with_capacity(framing.len() + header_bytes.len() + body.len());
        out.extend_from_slice(&framing);
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn from_bytes_with_header<F>(data: &[u8], gate: F) -> Result<Self, DagrError>
    where F: FnOnce(&Jws, usize, &[u8]) -> Result<(), DagrError> {
        if data.is_empty() { return Ok(Self::new()); }
        let (framing, rl) = dagr_runtime::read_leb(data, 0)?;
        if (framing & 1) != 1 { return Err(DagrError::InvalidData); }
        if ((framing >> 1) & 1) != 0 { return Err(DagrError::InvalidData); }
        let stored_offset = (framing >> 2) as usize;
        let header_start = rl;
        let (hcs, hcsb) = dagr_runtime::read_leb(data, header_start)?;
        let h = hcsb + hcs as usize;
        let header = Jws::restore(data, header_start);
        let body_start = header_start + h;
        let body = &data[body_start..];
        gate(&header, stored_offset - h, body)?;
        let root_at = rl + stored_offset;
        let arena = Self::new();
        let mut cache = std::collections::HashMap::new();
        let root = _restore_claims(data, root_at, &arena, &mut cache)?;
        arena.set_root(Some(root));
        Ok(arena)
    }
}


// ── Direct Graph Builder ("31 Direct Graph Builder.md") ─────────────────────
// Arena-free construction for this packed-rooted tree: plain value structs in,
// byte-identical graph buffer out. `direct::to_bytes*(v) == arena.to_bytes*()`.
pub mod direct {
    use crate::dagr_runtime::{DagrBuilder, NodeStoreRef, DagrError};
    use super::Jws;

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

    fn _supp_json<'a>(u: Json<'a>, b: &mut DagrBuilder) -> Result<(u64, u64), DagrError> {
        let (_tid, _code): (u64, u64) = match u {
            Json::String(v) => { let _bs = v.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); (0u64, 6u64) },
            Json::Number(v) => { b.store_always_packed_f64(v); (1u64, 5u64) },
            Json::Bool(v) => { b.store_bool(v); (2u64, 1u64) },
            Json::Array(v) => {
                let _uav_arr = v;
                let _cnt_uav = _uav_arr.len();
                let _bef_uav = b.cursor();
                let _is_nil_uav: Vec<bool> = _uav_arr.iter().map(|x| x.is_none()).collect();
                let mut _tids_uav: Vec<u64> = Vec::new();
                let mut _codes_uav: Vec<u64> = Vec::new();
                for _e in _uav_arr.into_iter().rev() {
                    if let Some(_u) = _e {
                        let (_tid, _code): (u64, u64) = _supp_json(_u.clone(), b)?;
                        _tids_uav.push(_tid); _codes_uav.push(_code);
                    }
                }
                let _hbef_uav = b.cursor();
                for _i in 0.._tids_uav.len() { b.store_leb((_tids_uav[_i] << 3) | _codes_uav[_i]); }
                b.store_leb((b.cursor() - _hbef_uav) as u64);
                let _bs_uav = (_cnt_uav + 7) / 8;
                for _bi in (0.._bs_uav).rev() {
                    let mut _byte = 0u8;
                    for _bit in 0usize..8 {
                        let _idx = _bi * 8 + _bit;
                        if _idx < _cnt_uav && _is_nil_uav[_idx] { _byte |= 1u8 << _bit; }
                    }
                    b.store_u8(_byte);
                }
                b.store_leb(_cnt_uav as u64);
                b.store_leb((b.cursor() - _bef_uav) as u64);
                (3u64, 6u64)
            },
            Json::Object(v) => {
                let _uav_arr = v;
                let _cnt_uav = _uav_arr.len();
                let _bef_uav = b.cursor();
                for _e in _uav_arr.iter().rev() {
                    _e.store_packed(b)?;
                }
                b.store_leb(_cnt_uav as u64);
                b.store_leb((b.cursor() - _bef_uav) as u64);
                (4u64, 6u64)
            },
            Json::Data(v) => { b.store_raw(&v); b.store_leb(v.len() as u64); (5u64, 6u64) },
            Json::Unknown(id) => (id as u64, 1u64),
        };
        Ok((_tid, _code))
    }

    impl<'a> Claims<'a> {
        pub fn store_packed(&self, b: &mut DagrBuilder) -> Result<NodeStoreRef, DagrError> {
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
            if let Some(_u) = self.custom.clone() {
                let (_tid, _code) = _supp_json(_u, b)?;
                b.store_leb((_tid << 3) | _code);
            }
            {
                let _scopes_arr = &self.scopes;
                if !_scopes_arr.is_empty() {
                let _cnt_scopes = _scopes_arr.len();
                let _bef_scopes = b.cursor();
                for _e in _scopes_arr.iter().rev() { b.store_blob(_e.as_bytes()); }
                b.store_leb(_cnt_scopes as u64);
                b.store_leb((b.cursor() - _bef_scopes) as u64);
                }
            }
            { let _v = self.expires_at; if _ebs0 & 2 != 0 { b.store_u64(_v); } else { b.store_leb(_v as u64); } }
            { let _v = self.issued_at; if _ebs0 & 1 != 0 { b.store_u64(_v); } else { b.store_leb(_v as u64); } }
            if let Some(_s) = self.audience.as_deref() { let _bs = _s.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); }
            if let Some(_s) = self.issuer.as_deref() { let _bs = _s.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); }
            if let Some(_s) = self.subject.as_deref() { let _bs = _s.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); }
            b.store_u8(_ebs0);
            b.store_u8(_obs0);
            b.store_leb((b.cursor() - _before) as u64);
            Ok(NodeStoreRef::Offset(b.cursor()))
        }
    }

    impl<'a> JsonMember<'a> {
        pub fn store_packed(&self, b: &mut DagrBuilder) -> Result<NodeStoreRef, DagrError> {
            let _before = b.cursor();
            let mut _obs0 = 0u8;
            _obs0 |= u8::from(self.value.is_some()) << 0;
            if let Some(_u) = self.value.clone() {
                let (_tid, _code) = _supp_json(_u, b)?;
                b.store_leb((_tid << 3) | _code);
            }
            { let _bs = self.key.as_bytes(); b.store_raw(_bs); b.store_leb(_bs.len() as u64); }
            b.store_u8(_obs0);
            b.store_leb((b.cursor() - _before) as u64);
            Ok(NodeStoreRef::Offset(b.cursor()))
        }
    }

    pub fn to_bytes_with_header<F>(root: &Claims<'_>, header_fn: F) -> Result<Vec<u8>, DagrError>
    where F: FnOnce(usize, &[u8]) -> Jws {
        let mut b = DagrBuilder::with_capacity(4096);   // direct = tree → small buffer, grows if needed
        let root_ref = root.store_packed(&mut b)?;
        let root_off = root_ref.to_offset().unwrap_or(0);
        let body_len = b.cursor();
        let original_offset = body_len - root_off;
        let header_value = header_fn(original_offset, b.record_bytes());
        header_value.store_packed(&mut b);
        let h = b.cursor() - body_len;
        let stored_offset = (((original_offset + h) as u64) << 2) | 0b01;
        b.store_leb(stored_offset);
        Ok(b.finalize())
    }

    pub struct Writer;
    impl Writer {
        pub fn new() -> Self { Writer }
        pub fn to_bytes_with_header<F>(&mut self, root: &Claims<'_>, header_fn: F) -> Result<Vec<u8>, DagrError>
        where F: FnOnce(usize, &[u8]) -> Jws { to_bytes_with_header(root, header_fn) }
    }
    impl Default for Writer { fn default() -> Self { Writer::new() } }
}

pub struct Token;
impl Token {
    pub fn to_bytes_with_header<F>(root: &direct::Claims<'_>, header_fn: F) -> Result<Vec<u8>, DagrError>
    where F: FnOnce(usize, &[u8]) -> Jws { direct::to_bytes_with_header(root, header_fn) }
}