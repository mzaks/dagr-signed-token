// Dagr serializer runtime (Odin) — plan 29 Track (write side).
// A BACKWARD-growing builder: every store appends a chunk and returns the cursor (total
// bytes stored so far). `make_data()` concatenates the chunks in REVERSE store order, so
// the effective layout grows from the far end downward. A buffer offset is the cursor
// value at store time; the forward distance between two stored things is `cursor - offset`.
// Hand-ported from RethinkingDagrMojo/src/dagr_writer.mojo (byte-exact reference).
package dagr_reader

import "core:strings"

// A deferred back-edge slot for a node-ref to a node still being stored (a CYCLE), patched by
// `finish_storing` once the target is placed. `chunk` = the placeholder chunk's index.
//   kind 0 (bidir single ref): a fixed 8-byte u64-V62; `pos` = cursor just after it (start=pos-8);
//                              patched with ZigZag(pos-8 - target).
//   kind 1 (node-ref array slot): an `elem_size`-byte signed slot; patched with
//                              (array_end - target + 1) two's-complement.
Dagr_LateBind :: struct { kind: int, id: int, chunk: int, pos: int, array_end: int, elem_size: int }

// Slot byte width for a signed width-code (0/1/2/3 → 1/2/4/8).
dagr_wc_bytes :: proc(wc: int) -> int { return wc == 0 ? 1 : wc == 1 ? 2 : wc == 2 ? 4 : 8 }

Builder :: struct {
	chunks:        [dynamic][dynamic]u8,
	cursor:        int,
	vt_lookup:     map[string]int,   // vtable norm-key → header offset (dedup)
	string_lookup: map[string]int,   // utf8 content → offset (dedup)
	node_lookup:   map[int]int,      // node identity (restore pos / arena handle) → stored offset
	in_progress:   map[int]bool,     // node ids currently being stored (cycle detection)
	late_bindings: [dynamic]Dagr_LateBind,  // deferred back-edge placeholders to patch
	reserve_bytes: int,   // back-reference placeholder width, derived from max_size (2 MiB→4, 1024→2)
}

// max_size sets the back-reference placeholder width: bits = bitlen(max_size)+3;
// width = nextPow2(ceil(bits/8)). 2 MiB -> 4 B (V62 code 2); 1024 -> 2 B (code 1). Must match producers.
builder_make :: proc(max_size: int = 2 * 1024 * 1024) -> Builder {
	bits := 3
	m := max_size
	for m > 0 { bits += 1; m >>= 1 }
	nbytes := (bits >> 3) + (bits & 7 != 0 ? 1 : 0)
	w := 1
	for w < nbytes { w <<= 1 }
	return Builder{reserve_bytes = w}
}

builder_destroy :: proc(b: ^Builder) {
	for &c in b.chunks { delete(c) }
	delete(b.chunks)
	for k in b.vt_lookup { delete(k) }
	delete(b.vt_lookup)
	for k in b.string_lookup { delete(k) }
	delete(b.string_lookup)
	delete(b.node_lookup)
	delete(b.in_progress)
	delete(b.late_bindings)
}

// Reset a Builder for reuse across serializations ("31 Direct Graph Builder.md" §4.3 —
// the reusable-writer form): free owned inner allocations (chunk buffers + dedup-map string
// keys) but `clear` the Builder's own maps/arrays so their backing storage is reused rather
// than re-allocated on the next mint. `reserve_bytes` depends on max_size, not content, so
// it is preserved. Output is byte-identical to a fresh `builder_make`.
builder_reset :: proc(b: ^Builder) {
	for &c in b.chunks { delete(c) }
	clear(&b.chunks)
	b.cursor = 0
	for k in b.vt_lookup { delete(k) }
	clear(&b.vt_lookup)
	for k in b.string_lookup { delete(k) }
	clear(&b.string_lookup)
	clear(&b.node_lookup)
	clear(&b.in_progress)
	clear(&b.late_bindings)
}

// ── Cyclic serialization (begin/finish late-binding, plan 29 §8.6 / spec 05 V62) ──────────────
// `begin_storing` classifies a node id: status 0 = already stored (return its offset for dedup),
// 1 = in progress (a cycle back-edge — the caller writes a placeholder, does NOT recurse), 2 =
// proceed (marked in-progress). The placeholder is a fixed 8-byte u64 V62 (code 3), so its slot
// width never changes; only the encoded distance is patched in place once the target is placed.
begin_storing :: proc(b: ^Builder, id: int) -> (int, int) {
	if off, ok := b.node_lookup[id]; ok { return off, 0 }
	if b.in_progress[id] { return 0, 1 }
	b.in_progress[id] = true
	return 0, 2
}

store_bidir_placeholder :: proc(b: ^Builder, id: int) -> int {
	c := make([dynamic]u8, b.reserve_bytes)   // zero placeholder = an as-yet-unresolved V62 whose width
	                                          // is the max_size-derived reserve (spec 05 "dummy references")
	pos := _push(b, c)
	append(&b.late_bindings, Dagr_LateBind{kind = 0, id = id, chunk = len(b.chunks) - 1, pos = pos})
	return pos
}

// A cycle-aware node-ref array (spec 04 signed slot table): each element's target offset (or -1
// for nil / not-yet-known). `ready[i]` is false when element i is a back-edge (its target is still
// in progress) → a fixed-width placeholder slot is written and a late binding recorded against
// `ids[i]`. Any back-edge forces width-code 3 (8-byte slots) so placeholder widths are stable.
store_node_ref_array_cyc :: proc(b: ^Builder, offs: []int, ready: []bool, ids: []int) -> int {
	cur := b.cursor
	wc := 0
	any_back := false
	for r in ready { if !r { any_back = true } }
	for o in offs { if o >= 0 { c := signed_width_code(cur - o + 1); if c > wc { wc = c } } }
	// Back-edges are patched in place at an unknown distance → reserve the max_size-derived
	// worst-case width (code 2 = 4 B at 2 MiB, code 1 = 2 B at 1024), matching the other languages.
	reserve_wc := b.reserve_bytes == 1 ? 0 : b.reserve_bytes == 2 ? 1 : b.reserve_bytes == 4 ? 2 : 3
	if any_back && wc < reserve_wc { wc = reserve_wc }
	esz := dagr_wc_bytes(wc)
	for i in 0 ..< len(offs) {
		if !ready[i] {
			ph := make([dynamic]u8, esz)   // zero placeholder slot
			_push(b, ph)
			append(&b.late_bindings, Dagr_LateBind{kind = 1, id = ids[i],
				chunk = len(b.chunks) - 1, array_end = cur, elem_size = esz})
		} else {
			_ = _store_int_wc(b, offs[i] < 0 ? 0 : cur - offs[i] + 1, wc)
		}
	}
	return store_leb(b, (u64(len(offs)) << 2) | u64(wc))
}

finish_storing :: proc(b: ^Builder, id: int, offset: int) {
	for lb in b.late_bindings {
		if lb.id != id { continue }
		if lb.kind == 0 {
			// bidir single ref: ZigZag(pointer_start - target), V62 at the max_size-derived reserve width.
			reserve_wc := b.reserve_bytes == 1 ? 0 : b.reserve_bytes == 2 ? 1 : b.reserve_bytes == 4 ? 2 : 3
			v := (to_zigzag((lb.pos - b.reserve_bytes) - offset) << 2) | u64(reserve_wc)
			for i in 0 ..< b.reserve_bytes { b.chunks[lb.chunk][i] = u8((v >> uint(i * 8)) & 0xff) }
		} else {
			// node-ref array slot: signed (array_end - target + 1) at the slot width.
			rel := u64(lb.array_end - offset + 1)
			for i in 0 ..< lb.elem_size { b.chunks[lb.chunk][i] = u8((rel >> uint(i * 8)) & 0xff) }
		}
	}
	b.node_lookup[id] = offset
	delete_key(&b.in_progress, id)
}

// LEB128 byte length of `v`.
leb_length :: proc(v: u64) -> int {
	if v == 0 { return 1 }
	n, x := 0, v
	for x > 0 { n += 1; x >>= 7 }
	return n
}

// ZigZag encode a signed distance.
to_zigzag :: proc(v: int) -> u64 {
	return u64((v << 1) ~ (v >> 63))
}

// Vtable-size marker: v==0 → 0, else ((v-1)<<1)|1 (= ZigZag of -v, always odd/"negative").
to_negativ_zigzag :: proc(v: u64) -> u64 {
	return v == 0 ? 0 : ((v - 1) << 1) | 1
}

// ── core: append a chunk, return the new cursor ──────────────────────────────
_push :: proc(b: ^Builder, chunk: [dynamic]u8) -> int {
	b.cursor += len(chunk)
	append(&b.chunks, chunk)
	return b.cursor
}

store_bytes :: proc(b: ^Builder, bytes: []u8) -> int {
	c := make([dynamic]u8, 0, len(bytes))
	append(&c, ..bytes)
	return _push(b, c)
}

store_u8 :: proc(b: ^Builder, v: u8) -> int {
	c := make([dynamic]u8, 0, 1); append(&c, v); return _push(b, c)
}
store_u16 :: proc(b: ^Builder, v: u16) -> int {
	c := make([dynamic]u8, 0, 2)
	append(&c, u8(v & 0xff), u8((v >> 8) & 0xff))
	return _push(b, c)
}
store_u32 :: proc(b: ^Builder, v: u32) -> int {
	c := make([dynamic]u8, 0, 4)
	for i in 0 ..< 4 { append(&c, u8((v >> uint(i * 8)) & 0xff)) }
	return _push(b, c)
}
store_u64 :: proc(b: ^Builder, v: u64) -> int {
	c := make([dynamic]u8, 0, 8)
	for i in 0 ..< 8 { append(&c, u8((v >> uint(i * 8)) & 0xff)) }
	return _push(b, c)
}

// Signed integers share the LE two's-complement layout of the unsigned store.
store_i8 :: proc(b: ^Builder, v: i8) -> int { return store_u8(b, u8(v)) }
store_i16 :: proc(b: ^Builder, v: i16) -> int { return store_u16(b, u16(v)) }
store_i32 :: proc(b: ^Builder, v: i32) -> int { return store_u32(b, u32(v)) }
store_i64 :: proc(b: ^Builder, v: i64) -> int { return store_u64(b, u64(v)) }

store_f16 :: proc(b: ^Builder, v: f16) -> int { return store_u16(b, transmute(u16)v) }
store_f32 :: proc(b: ^Builder, v: f32) -> int { return store_u32(b, transmute(u32)v) }
store_f64 :: proc(b: ^Builder, v: f64) -> int { return store_u64(b, transmute(u64)v) }
// bf16 API type is f32 (widened bits): store the high 16 bits.
store_bf16 :: proc(b: ^Builder, v: f32) -> int { return store_u16(b, u16(transmute(u32)v >> 16)) }
store_bool :: proc(b: ^Builder, v: bool) -> int { return store_u8(b, v ? 1 : 0) }

// LEB128 unsigned varint.
store_leb :: proc(b: ^Builder, value: u64) -> int {
	if value == 0 {
		c := make([dynamic]u8, 0, 1); append(&c, 0); return _push(b, c)
	}
	x := value
	out := make([dynamic]u8, 0, 4)
	for x > 0 {
		by := u8(x & 0x7f)
		x >>= 7
		append(&out, x > 0 ? by | 0x80 : by)
	}
	return _push(b, out)
}

// V62 fixed-width pointer: value<<2 | widthCode (width by magnitude), min_code floor.
store_v62 :: proc(b: ^Builder, value: u64, min_code := 0) -> int {
	if value < (u64(1) << 6) && min_code == 0 {
		return store_u8(b, u8((value << 2) | 0))
	}
	if value < (u64(1) << 14) && min_code <= 1 {
		return store_u16(b, u16((value << 2) | u64(max(1, min_code))))
	}
	if value < (u64(1) << 30) && min_code <= 2 {
		return store_u32(b, u32((value << 2) | u64(max(2, min_code))))
	}
	return store_u64(b, (value << 2) | u64(max(3, min_code)))
}

store_forward_pointer :: proc(b: ^Builder, offset: int) -> int {
	return store_v62(b, u64(b.cursor - offset))
}

// Bidirectional (ZigZag) V62 node-ref pointer to an already-stored node at `off` (the
// backward distance is positive; ZigZag lets a forward/back-edge use the same slot).
store_bidir :: proc(b: ^Builder, off: int) -> int {
	return store_v62(b, to_zigzag(b.cursor - off))
}

// ── union field slots (04 Union Types.md) ────────────────────────────────────
// A pass-1 apply descriptor: `tag` = variant index; `off` = out-of-line content offset
// (utf8/data/nested-union pointer variants, -1 = none); `nref` = stored node offset
// (node variant, -1 = none). Pass 2 re-dispatches on `tag` to emit the inline value or the
// forward/bidir pointer, then writes the header `[LEB (tag<<2)|wc]`.
USlot :: struct { tag: u8, off: int, nref: int }

// Cyclic node-variant union slot descriptor (plan 29 §8.6 + §8.7). Like USlot but a node variant
// carries the late-binding state: `off` = the child's stored offset (when `ready`), else the child
// id for a placeholder patched by `finish_storing`. Value variants use `off` as the utf8/data
// content offset (-1 for an inline scalar/enum).
UCycSlot :: struct { tag: u8, off: int, ready: bool, id: int }

// Union field-slot width code from the payload byte count (1→0, 2→1, 4→2, else 3).
union_slot_wc :: proc(payload_bytes: int) -> int {
	switch payload_bytes {
	case 1: return 0
	case 2: return 1
	case 4: return 2
	}
	return 3
}

// One applied element of a regular/frozen union array (§4.9). `kind`: 0 value (val = raw
// bit-pattern), 1 pointer (val = content offset → slot `contentEnd-val`), 2 bidir node
// (slot `(contentEnd-val)<<1`). `is_nil` = an AWO absent element.
UArrElem :: struct { kind: u8, val: u64, tid: u8, is_nil: bool }

// Regular/frozen union array (§4.9): element content already stored (pass 1); `applied` in
// REVERSED element order (applied[j] = element count-1-j), nil-marked for AWO absent. Stores
// [slot table][nil bitset (opt)][typeId section][header (count<<2)|wc].
store_union_array :: proc(b: ^Builder, count: int, applied: []UArrElem, bp: int, opt: bool) -> int {
	content_end := b.cursor
	slots := make([]u64, len(applied)); defer delete(slots)
	wc := 0
	for a, j in applied {
		v: u64 = 0
		if !a.is_nil {
			switch a.kind {
			case 0: v = a.val
			case 1: v = u64(content_end - int(a.val))
			case:   v = u64(content_end - int(a.val)) << 1
			}
			c := offset_width_code(v)
			if c > wc { wc = c }
		}
		slots[j] = v
	}
	for v in slots { _ = _store_uint_wc(b, v, wc) }
	if opt {
		nilb := _zeros((count + 7) >> 3)
		for j in 0 ..< count {
			idx := count - 1 - j
			if applied[j].is_nil { nilb[idx >> 3] |= u8(1) << u8(idx & 7) }
		}
		_ = _push(b, nilb)
	}
	if bp < 8 {                                       // sub-byte typeId bitset
		per := 8 / bp
		mask := u8((1 << uint(bp)) - 1)
		bs := _zeros((count * bp + 7) / 8)
		for j in 0 ..< count {
			idx := count - 1 - j
			tid := applied[j].is_nil ? u8(0) : applied[j].tid
			bs[idx / per] |= (tid & mask) << u8((idx % per) * bp)
		}
		_ = _push(b, bs)
	} else {                                          // one byte per typeId (cap ≤ 255)
		for a in applied { _ = store_u8(b, a.is_nil ? 0 : a.tid) }
	}
	return store_leb(b, (u64(count) << 2) | u64(wc))
}

// ── packed-float scalar/element encoders (06 §12) ────────────────────────────
// Store a packed float; return true if stored RAW (fixed-width bytes), false if a
// compressed / special form (leading 1-byte sub-tag). `elem`=true also emits the raw
// sub-tag (0x07/0x08) so an array element is self-delimiting; a scalar (elem=false)
// signals raw via the field tag's low bit instead. Backward order: payload then sub-tag
// → the reader sees [sub-tag][payload]. Bit patterns match decode_packed_f32/f64/f16/bf16.
store_packed_float32 :: proc(b: ^Builder, v: f32, elem: bool) -> bool {
	bits := transmute(u32)v
	if bits == 0 { _ = store_u8(b, 0x00); return false }
	if bits == 0x80000000 { _ = store_u8(b, 0x01); return false }
	exp := (bits >> 23) & 0xff
	if exp == 0xff {
		if (bits & 0x7fffff) != 0 { _ = store_u8(b, 0x04); return false }
		_ = store_u8(b, (bits >> 31) != 0 ? 0x03 : 0x02); return false
	}
	av := v < 0 ? -v : v
	if av < f32(1 << 21) && v == f32(i64(v)) {          // small integer
		zz := to_zigzag(int(i64(v)))
		if leb_length(zz) <= 3 { _ = store_leb(b, zz); _ = store_u8(b, 0x05); return false }
	}
	h := f16(v)                                          // f16-exact?
	if f32(h) == v { _ = store_u16(b, transmute(u16)h); _ = store_u8(b, 0x06); return false }
	_ = store_f32(b, v)
	if elem { _ = store_u8(b, 0x07) }
	return true
}
store_packed_float64 :: proc(b: ^Builder, v: f64, elem: bool) -> bool {
	bits := transmute(u64)v
	if bits == 0 { _ = store_u8(b, 0x00); return false }
	if bits == 0x8000000000000000 { _ = store_u8(b, 0x01); return false }
	exp := (bits >> 52) & 0x7ff
	if exp == 0x7ff {
		if (bits & 0xfffffffffffff) != 0 { _ = store_u8(b, 0x04); return false }
		_ = store_u8(b, (bits >> 63) != 0 ? 0x03 : 0x02); return false
	}
	av := v < 0 ? -v : v
	if av < f64(1 << 48) && v == f64(i64(v)) {
		zz := to_zigzag(int(i64(v)))
		if leb_length(zz) <= 7 { _ = store_leb(b, zz); _ = store_u8(b, 0x05); return false }
	}
	f := f32(v)                                          // f32-exact → f16/f32
	if f64(f) == v {
		h := f16(f)
		if f32(h) == f { _ = store_u16(b, transmute(u16)h); _ = store_u8(b, 0x06); return false }
		_ = store_f32(b, f); _ = store_u8(b, 0x07); return false
	}
	_ = store_f64(b, v)
	if elem { _ = store_u8(b, 0x08) }
	return true
}
store_packed_f16_scalar :: proc(b: ^Builder, v: f16) -> bool {
	bits := transmute(u16)v
	if bits == 0 { _ = store_u8(b, 0x00); return false }
	if bits == 0x8000 { _ = store_u8(b, 0x01); return false }
	if ((bits >> 10) & 0x1f) == 0x1f {
		if (bits & 0x3ff) != 0 { _ = store_u8(b, 0x04); return false }
		_ = store_u8(b, (bits >> 15) != 0 ? 0x03 : 0x02); return false
	}
	_ = store_u16(b, bits); return true
}
// bf16 API type is f32 (widened bits): operate on the high 16 bits.
store_packed_bf16_scalar :: proc(b: ^Builder, v: f32) -> bool {
	bits := u16(transmute(u32)v >> 16)
	if bits == 0 { _ = store_u8(b, 0x00); return false }
	if bits == 0x8000 { _ = store_u8(b, 0x01); return false }
	if ((bits >> 7) & 0xff) == 0xff {
		if (bits & 0x7f) != 0 { _ = store_u8(b, 0x04); return false }
		_ = store_u8(b, (bits >> 15) != 0 ? 0x03 : 0x02); return false
	}
	_ = store_u16(b, bits); return true
}

// utf8 / data content: raw bytes then the length LEB (backward order → [LEB][bytes]).
// utf8 dedups identical content on the offset of its length LEB.
store_utf8 :: proc(b: ^Builder, s: string, dedup: bool) -> int {
	if dedup {
		if off, ok := b.string_lookup[s]; ok { return off }
	}
	n := len(s)
	_ = store_bytes(b, transmute([]u8)s)
	off := store_leb(b, u64(n))
	if dedup { b.string_lookup[strings.clone(s)] = off }
	return off
}
store_data :: proc(b: ^Builder, bytes: []u8) -> int {
	n := len(bytes)
	_ = store_bytes(b, bytes)
	return store_leb(b, u64(n))
}
// aligned(N) data (§11): leading pad so the element region lands N-aligned, then bytes + LEB.
store_aligned_data :: proc(b: ^Builder, bytes: []u8, N: int) -> int {
	pad := (-(b.cursor + len(bytes))) & (N - 1)
	if pad != 0 { _ = _push(b, _zeros(pad)) }
	for i := len(bytes) - 1; i >= 0; i -= 1 { _ = store_u8(b, bytes[i]) }
	return store_leb(b, u64(len(bytes)))
}
store_aligned_utf8 :: proc(b: ^Builder, s: string, N: int) -> int {
	pad := (-(b.cursor + len(s))) & (N - 1)
	if pad != 0 { _ = _push(b, _zeros(pad)) }
	bytes := transmute([]u8)s
	for i := len(bytes) - 1; i >= 0; i -= 1 { _ = store_u8(b, bytes[i]) }
	return store_leb(b, u64(len(s)))
}

// ── array framing (element content pre-stored inline by the generator) ───────
// Minimum unsigned/signed fixed-width slot code for a pointer-table / node-ref array.
offset_width_code :: proc(v: u64) -> int {
	if v <= 0xff { return 0 }
	if v <= 0xffff { return 1 }
	if v <= 0xffffffff { return 2 }
	return 3
}
signed_width_code :: proc(d: int) -> int {
	if d >= -128 && d <= 127 { return 0 }
	if d >= -32768 && d <= 32767 { return 1 }
	if d >= -2147483648 && d <= 2147483647 { return 2 }
	return 3
}
_store_uint_wc :: proc(b: ^Builder, v: u64, wc: int) -> int {
	switch wc {
	case 0: return store_u8(b, u8(v & 0xff))
	case 1: return store_u16(b, u16(v & 0xffff))
	case 2: return store_u32(b, u32(v & 0xffffffff))
	}
	return store_u64(b, v)
}
// Two's-complement in the low `1<<wc` bytes (same LE layout as unsigned).
_store_int_wc :: proc(b: ^Builder, v: int, wc: int) -> int {
	mask: u64 = wc < 3 ? (u64(1) << uint((1 << uint(wc)) * 8)) - 1 : ~u64(0)
	return _store_uint_wc(b, u64(v) & mask, wc)
}

_zeros :: proc(n: int) -> [dynamic]u8 {
	c := make([dynamic]u8, 0, n)
	for _ in 0 ..< n { append(&c, 0) }
	return c
}
// `n` zero bytes (absent AWO element slots).
store_zeros :: proc(b: ^Builder, n: int) -> int {
	return _push(b, _zeros(n))
}
// A nil bitset (⌈count/8⌉ bytes) with bit i set when `absent[i]`.
store_nil_bits :: proc(b: ^Builder, absent: []bool) -> int {
	bs := _zeros((len(absent) + 7) >> 3)
	for i in 0 ..< len(absent) {
		if absent[i] { bs[i >> 3] |= u8(1) << u8(i & 7) }
	}
	return _push(b, bs)
}

// Bool array: [LEB count][value bitset], bit i = elem i.
store_bool_array :: proc(b: ^Builder, elems: []bool) -> int {
	bs := _zeros((len(elems) + 7) >> 3)
	for i in 0 ..< len(elems) {
		if elems[i] { bs[i >> 3] |= u8(1) << u8(i & 7) }
	}
	_ = _push(b, bs)
	return store_leb(b, u64(len(elems)))
}
// Bool arrayWithOptionals (uncompacted): [count][nil bitset][value bitset], by i.
store_opt_bool_array :: proc(b: ^Builder, elems: []Maybe(bool)) -> int {
	nb := (len(elems) + 7) >> 3
	val := _zeros(nb)
	nilb := _zeros(nb)
	for i in 0 ..< len(elems) {
		if v, ok := elems[i].?; ok {
			if v { val[i >> 3] |= u8(1) << u8(i & 7) }
		} else {
			nilb[i >> 3] |= u8(1) << u8(i & 7)
		}
	}
	_ = _push(b, val)
	_ = _push(b, nilb)
	return store_leb(b, u64(len(elems)))
}
// Sub-byte enum array: [LEB count][packed bits] (bits ∈ {1,2,4}).
store_enum_bit_array :: proc(b: ^Builder, elems: []u8, bits: int) -> int {
	per := 8 / bits
	mask := u8((1 << uint(bits)) - 1)
	bs := _zeros((len(elems) * bits + 7) / 8)
	for i in 0 ..< len(elems) {
		bs[i / per] |= (elems[i] & mask) << u8((i % per) * bits)
	}
	_ = _push(b, bs)
	return store_leb(b, u64(len(elems)))
}
// Sub-byte enum awo (uncompacted): [count][nil bitset][value bitset], by i.
store_opt_enum_bit_array :: proc(b: ^Builder, elems: []Maybe(u8), bits: int) -> int {
	per := 8 / bits
	mask := u8((1 << uint(bits)) - 1)
	nilb := _zeros((len(elems) + 7) >> 3)
	val := _zeros((len(elems) * bits + 7) / 8)
	for i in 0 ..< len(elems) {
		if v, ok := elems[i].?; ok {
			val[i / per] |= (v & mask) << u8((i % per) * bits)
		} else {
			nilb[i >> 3] |= u8(1) << u8(i & 7)
		}
	}
	_ = _push(b, val)
	_ = _push(b, nilb)
	return store_leb(b, u64(len(elems)))
}
// Pointer-table array (utf8/data elements): content already stored (offsets in `offs`,
// REVERSED element order, -1 = nil). Writes the [count×es] slot table (slot =
// cur - off + 1, 0 = nil) then the header (count<<2)|widthCode. Unsigned slots.
store_ptr_table :: proc(b: ^Builder, offs: []int) -> int {
	cur := b.cursor
	wc := 0
	for o in offs {
		if o >= 0 {
			c := offset_width_code(u64(cur - o + 1))
			if c > wc { wc = c }
		}
	}
	for o in offs {
		d: u64 = o < 0 ? 0 : u64(cur - o + 1)
		_ = _store_uint_wc(b, d, wc)
	}
	return store_leb(b, (u64(len(offs)) << 2) | u64(wc))
}
// ── packed-node array bodies: [blockLen][count-tag][elems] (self-sizing) ─────
// The generator precomputes value lists (forward order); these store the reversed
// elements + framing and return the blockLen offset. Bit patterns mirror the reader's
// packed array getters. `present` (AWO) is full-length; absent entries are compacted out.
_wcw :: proc(width: int) -> int {
	return width == 1 ? 0 : (width == 2 ? 1 : (width == 4 ? 2 : 3))
}
_nil_from_present :: proc(present: []bool) -> [dynamic]u8 {
	bs := _zeros((len(present) + 7) >> 3)
	for i in 0 ..< len(present) {
		if !present[i] { bs[i >> 3] |= u8(1) << u8(i & 7) }
	}
	return bs
}

// Packed int array (width ≥ 2): count-tag=(count<<2)|tag, tag 0 all-LEB / 1 all-raw /
// 2 mixed (enc bitset). `vals` = sign-extended bits for signed.
store_packed_int_array :: proc(b: ^Builder, vals: []u64, width: int, signed: bool) -> int {
	before := b.cursor
	n := len(vals)
	enc := _zeros((n + 7) >> 3)
	raw_count := 0
	for i := n - 1; i >= 0; i -= 1 {
		lebv := signed ? to_zigzag(int(i64(vals[i]))) : vals[i]
		if leb_length(lebv) < width {
			_ = store_leb(b, lebv)
		} else {
			_ = _store_uint_wc(b, vals[i], _wcw(width))
			enc[i >> 3] |= u8(1) << u8(i & 7)
			raw_count += 1
		}
	}
	tag := 0
	if raw_count == n && n > 0 { tag = 1; delete(enc) }
	else if raw_count > 0 { tag = 2; _ = _push(b, enc) }
	else { delete(enc) }
	_ = store_leb(b, (u64(n) << 2) | u64(tag))
	return store_leb(b, u64(b.cursor - before))
}
// Packed u8/i8 array: plain [count][raw bytes] (no count-tag).
store_packed_byte_array :: proc(b: ^Builder, vals: []u64) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 { _ = store_u8(b, u8(vals[i] & 0xff)) }
	_ = store_leb(b, u64(len(vals)))
	return store_leb(b, u64(b.cursor - before))
}
// Packed bool array: [count][value bitset], wrapped in blockLen.
store_packed_bool_array :: proc(b: ^Builder, elems: []bool) -> int {
	before := b.cursor
	bs := _zeros((len(elems) + 7) >> 3)
	for i in 0 ..< len(elems) { if elems[i] { bs[i >> 3] |= u8(1) << u8(i & 7) } }
	_ = _push(b, bs)
	_ = store_leb(b, u64(len(elems)))
	return store_leb(b, u64(b.cursor - before))
}
// Packed sub-byte enum array: [blockLen][count][packed bits].
store_packed_enum_bit_array :: proc(b: ^Builder, elems: []u8, bits: int) -> int {
	before := b.cursor
	per := 8 / bits
	mask := u8((1 << uint(bits)) - 1)
	bs := _zeros((len(elems) * bits + 7) / 8)
	for i in 0 ..< len(elems) { bs[i / per] |= (elems[i] & mask) << u8((i % per) * bits) }
	_ = _push(b, bs)
	_ = store_leb(b, u64(len(elems)))
	return store_leb(b, u64(b.cursor - before))
}
// Packed byte-aligned enum array: [blockLen][count][LEB(rawValue) per element].
store_packed_enum_raw_array :: proc(b: ^Builder, vals: []u64) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 { _ = store_leb(b, vals[i]) }
	_ = store_leb(b, u64(len(vals)))
	return store_leb(b, u64(b.cursor - before))
}
// Packed f32/f64 array: [blockLen][(count<<2)|mode][elems] — mode 0 packed / 1 raw.
store_packed_float32_array :: proc(b: ^Builder, vals: []f32, raw: bool) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 {
		if raw { _ = store_f32(b, vals[i]) } else { _ = store_packed_float32(b, vals[i], true) }
	}
	_ = store_leb(b, (u64(len(vals)) << 2) | (raw ? 1 : 0))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_float64_array :: proc(b: ^Builder, vals: []f64, raw: bool) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 {
		if raw { _ = store_f64(b, vals[i]) } else { _ = store_packed_float64(b, vals[i], true) }
	}
	_ = store_leb(b, (u64(len(vals)) << 2) | (raw ? 1 : 0))
	return store_leb(b, u64(b.cursor - before))
}
// Packed f16/bf16 array: [blockLen][count][enc bitset][elems]; enc bit 1 = raw.
store_packed_f16_array :: proc(b: ^Builder, vals: []f16) -> int {
	before := b.cursor
	enc := _zeros((len(vals) + 7) >> 3)
	for i := len(vals) - 1; i >= 0; i -= 1 {
		if store_packed_f16_scalar(b, vals[i]) { enc[i >> 3] |= u8(1) << u8(i & 7) }
	}
	_ = _push(b, enc)
	_ = store_leb(b, u64(len(vals)))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_bf16_array :: proc(b: ^Builder, vals: []f32) -> int {
	before := b.cursor
	enc := _zeros((len(vals) + 7) >> 3)
	for i := len(vals) - 1; i >= 0; i -= 1 {
		if store_packed_bf16_scalar(b, vals[i]) { enc[i >> 3] |= u8(1) << u8(i & 7) }
	}
	_ = _push(b, enc)
	_ = store_leb(b, u64(len(vals)))
	return store_leb(b, u64(b.cursor - before))
}

// Packed arrayWithOptionals (compacted present elems + leading nil bitset).
store_packed_int_opt_array :: proc(b: ^Builder, vals: []u64, present: []bool, width: int, signed: bool) -> int {
	before := b.cursor
	n := len(vals)
	enc := _zeros((n + 7) >> 3)
	raw_count, pres_count := 0, 0
	for i := n - 1; i >= 0; i -= 1 {
		if !present[i] { continue }
		pres_count += 1
		lebv := signed ? to_zigzag(int(i64(vals[i]))) : vals[i]
		if leb_length(lebv) < width {
			_ = store_leb(b, lebv)
		} else {
			_ = _store_uint_wc(b, vals[i], _wcw(width))
			enc[i >> 3] |= u8(1) << u8(i & 7)
			raw_count += 1
		}
	}
	tag := 0
	if raw_count == pres_count && pres_count > 0 { tag = 1; delete(enc) }
	else if raw_count > 0 { tag = 2; _ = _push(b, enc) }
	else { delete(enc) }
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, (u64(n) << 2) | u64(tag))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_byte_opt_array :: proc(b: ^Builder, vals: []u64, present: []bool) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 { if present[i] { _ = store_u8(b, u8(vals[i] & 0xff)) } }
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, u64(len(vals)))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_bool_opt_array :: proc(b: ^Builder, elems: []bool, present: []bool) -> int {
	before := b.cursor
	pc := 0
	for p in present { if p { pc += 1 } }
	val := _zeros((pc + 7) >> 3)
	ci := 0
	for i in 0 ..< len(elems) {
		if !present[i] { continue }
		if elems[i] { val[ci >> 3] |= u8(1) << u8(ci & 7) }
		ci += 1
	}
	_ = _push(b, val)
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, u64(len(elems)))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_enum_bit_opt_array :: proc(b: ^Builder, elems: []u8, present: []bool, bits: int) -> int {
	before := b.cursor
	pc := 0
	for p in present { if p { pc += 1 } }
	per := 8 / bits
	mask := u8((1 << uint(bits)) - 1)
	val := _zeros((pc * bits + 7) / 8)
	ci := 0
	for i in 0 ..< len(elems) {
		if !present[i] { continue }
		val[ci / per] |= (elems[i] & mask) << u8((ci % per) * bits)
		ci += 1
	}
	_ = _push(b, val)
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, u64(len(elems)))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_enum_raw_opt_array :: proc(b: ^Builder, vals: []u64, present: []bool) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 { if present[i] { _ = store_leb(b, vals[i]) } }
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, u64(len(vals)))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_float32_opt_array :: proc(b: ^Builder, vals: []f32, present: []bool, raw: bool) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 {
		if !present[i] { continue }
		if raw { _ = store_f32(b, vals[i]) } else { _ = store_packed_float32(b, vals[i], true) }
	}
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, (u64(len(vals)) << 2) | (raw ? 1 : 0))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_float64_opt_array :: proc(b: ^Builder, vals: []f64, present: []bool, raw: bool) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 {
		if !present[i] { continue }
		if raw { _ = store_f64(b, vals[i]) } else { _ = store_packed_float64(b, vals[i], true) }
	}
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, (u64(len(vals)) << 2) | (raw ? 1 : 0))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_f16_opt_array :: proc(b: ^Builder, vals: []f16, present: []bool) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 { if present[i] { _ = store_u16(b, transmute(u16)vals[i]) } }
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, u64(len(vals)))
	return store_leb(b, u64(b.cursor - before))
}
store_packed_bf16_opt_array :: proc(b: ^Builder, vals: []f32, present: []bool) -> int {
	before := b.cursor
	for i := len(vals) - 1; i >= 0; i -= 1 { if present[i] { _ = store_u16(b, u16(transmute(u32)vals[i] >> 16)) } }
	nb := _nil_from_present(present); _ = _push(b, nb)
	_ = store_leb(b, u64(len(vals)))
	return store_leb(b, u64(b.cursor - before))
}

// Packed array-of-union (§4.9): element headers precomputed (via apply_union_packed →
// (tid<<3)|code), payloads already stored inline (pass 1, REVERSED element order). Lays out
// [blockLen][count][nil bs?][hss?][present headers][payloads]. `before` = cursor before payloads.
store_packed_union_array_frame :: proc(b: ^Builder, hdrs: []u64, present: []bool, count: int, opt: bool, before: int) -> int {
	hdr_start := b.cursor
	for i in 0 ..< len(hdrs) { if present[i] { _ = store_leb(b, hdrs[i]) } }
	if opt {
		hss := b.cursor - hdr_start
		_ = store_leb(b, u64(hss))
		nilb := _zeros((count + 7) >> 3)
		for j in 0 ..< count {
			idx := count - 1 - j
			if !present[j] { nilb[idx >> 3] |= u8(1) << u8(idx & 7) }
		}
		_ = _push(b, nilb)
	}
	_ = store_leb(b, u64(count))
	return store_leb(b, u64(b.cursor - before))
}

// Node-ref array (signed two's-complement slots, §4.5): child content already stored
// (offs in REVERSED element order, -1 = nil). No cycle late-binding (acyclic scope).
store_node_ref_array :: proc(b: ^Builder, offs: []int) -> int {
	cur := b.cursor
	wc := 0
	for o in offs {
		if o < 0 { continue }
		c := signed_width_code(cur - o + 1)
		if c > wc { wc = c }
	}
	for o in offs {
		_ = _store_int_wc(b, o < 0 ? 0 : cur - o + 1, wc)
	}
	return store_leb(b, (u64(len(offs)) << 2) | u64(wc))
}

// Regular-node vtable: entries[i] = field i's stored offset (-1 = absent). Normalises to
// `cursor - off + 1` (0 = absent), dedups on the norm-key (forward-ref if seen), else
// stores the slot table (u8 or u16 wide) + a negative-zigzag size marker + a trailing
// count LEB; returns the size-marker offset (the node's identity / pointer target).
store_vtable :: proc(b: ^Builder, entries: []int) -> int {
	norm := make([dynamic]u64, 0, len(entries)); defer delete(norm)
	is16 := false
	for e in entries {
		n := e < 0 ? u64(0) : u64(b.cursor - e + 1)
		if n > 0xff { is16 = true }
		append(&norm, n)
	}
	kb := strings.builder_make(); defer strings.builder_destroy(&kb)
	if is16 { strings.write_string(&kb, "w:") }
	for i in 0 ..< len(norm) {
		if i > 0 { strings.write_byte(&kb, ',') }
		strings.write_u64(&kb, norm[i])
	}
	key := strings.to_string(kb)
	if hit, ok := b.vt_lookup[key]; ok {
		return store_leb(b, u64((b.cursor - hit) << 1))   // forward-ref (even)
	}
	result, cnt: int
	if is16 {
		cnt = (len(entries) << 1) | 1
		sz := leb_length(u64(cnt)) + len(entries) * 2
		result = store_leb(b, to_negativ_zigzag(u64(sz)))
		for i := len(norm) - 1; i >= 0; i -= 1 { _ = store_u16(b, u16(norm[i])) }
	} else {
		cnt = len(entries) << 1
		sz := cnt == 0 ? 0 : leb_length(u64(cnt)) + len(entries)
		result = store_leb(b, sz == 0 ? 0 : to_negativ_zigzag(u64(sz)))
		for i := len(norm) - 1; i >= 0; i -= 1 { _ = store_u8(b, u8(norm[i])) }
	}
	b.vt_lookup[strings.clone(key)] = store_leb(b, u64(cnt))
	return result
}

// Raw-embedded standalone blob (§17): pad the sub-builder before its framing LEB so the
// target's aligned fields land correctly once the blob is embedded. Finds the minimal pad
// p such that (cursor+p + framingLen) is a multiple of max_n.
store_finish_alignment_padding :: proc(b: ^Builder, root_offset: int, max_n: int) {
	if max_n <= 1 { return }
	for p in 0 ..< max_n {
		after_pad := b.cursor + p
		framing_len := leb_length(u64((after_pad - root_offset) << 2))
		if (after_pad + framing_len) % max_n == 0 {
			if p != 0 { _ = _push(b, _zeros(p)) }
			return
		}
	}
}

// Finished buffer: chunks concatenated in REVERSE store order (owned; caller deletes).
make_data :: proc(b: ^Builder) -> []u8 {
	total := 0
	for c in b.chunks { total += len(c) }
	out := make([]u8, total)
	p := 0
	for i := len(b.chunks) - 1; i >= 0; i -= 1 {
		for k in 0 ..< len(b.chunks[i]) { out[p] = b.chunks[i][k]; p += 1 }
	}
	return out
}
