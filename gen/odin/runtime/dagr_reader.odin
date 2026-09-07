// Dagr lazy-read runtime primitives (Odin) — plan 29 Track B.
// Hand-ported from the TS/Swift/Rust/Mojo generated runtimes. Reader model: a borrowed
// `[]u8` + position-passing free procs (Odin has no origin/borrow system, so a lazy
// view is just a slice — no lifetime annotation). Phase 1 milestone 1 surface: just the
// wire primitives needed to lazily read a regular (vtable) node of fixed scalars.
package dagr_reader

import "base:intrinsics"
import "core:slice"
import "core:strings"

// Convenience: allocate an OWNED copy of a zero-copy utf8/data view (so it can outlive
// the buffer). The lazy accessors return zero-copy views; a caller opts into a heap
// allocation only via the generated `{field}_clone` getters, which call these.
clone_string :: proc(s: string) -> string { return strings.clone(s) }
clone_bytes :: proc(b: []u8) -> []u8 { return slice.clone(b) }

// Resolve V62 forward pointer at `slot` to the payload position it targets.
fwd_target :: proc(buf: []u8, slot: int) -> int {
	fwd, fwdB := read_v62(buf, slot)
	return slot + fwdB + int(fwd)
}

// Parse an array payload `[LEB count][elements]` AT position `ps` (post-deref / direct).
array_payload_at :: proc(buf: []u8, ps: int) -> (base: int, count: int) {
	c, cB := read_leb(buf, ps)
	return ps + cB, int(c)
}

// Resolve a regular-node array field slot (a V62 forward pointer) to the element
// payload: (base = first element / bitset byte, count). Payload = [LEB count][elements].
array_payload :: proc(buf: []u8, slot: int) -> (base: int, count: int) {
	return array_payload_at(buf, fwd_target(buf, slot))
}

// Parse a pointer-table payload `[LEB (count<<2)|wc][count × es-byte slots][data]` AT
// position `ps` (post-deref / direct). es = 1<<wc. Element i at data_base + slot[i] - 1.
ptr_table_at :: proc(buf: []u8, ps: int) -> (table_base: int, data_base: int, count: int, es: int) {
	hdr, hB := read_leb(buf, ps)
	count = int(hdr >> 2)
	es = 1 << uint(hdr & 3)
	table_base = ps + hB
	data_base = table_base + count * es
	return
}

// Pointer-table array (regular/frozen utf8 / data / node-ref): the field slot's V62
// forward pointer targets the payload. Returns (table_base, data_base, count, es).
ptr_table :: proc(buf: []u8, slot: int) -> (table_base: int, data_base: int, count: int, es: int) {
	return ptr_table_at(buf, fwd_target(buf, slot))
}

// Unsigned `es`-byte little-endian slot read (pointer-table utf8/data slots).
read_uint_le :: proc(buf: []u8, at: int, es: int) -> int {
	v: u64 = 0
	for k in 0 ..< es { v |= u64(buf[at + k]) << uint(8 * k) }
	return int(v)
}

// Signed `es`-byte little-endian slot read — node-ref array slots are two's-complement
// so a slot can point backward to a shared/cyclic node.
read_int_le :: proc(buf: []u8, at: int, es: int) -> int {
	v := read_uint_le(buf, at, es)
	bits := uint(8 * es)
	if bits < 64 && (v & (1 << (bits - 1))) != 0 { v -= 1 << bits }
	return v
}

// Inline arrayWithOptionals payload: [LEB count][nil bitset ⌈count/8⌉][value region].
// Returns (base_nil = nil-bitset byte, base_val = value region, count). Element i is
// nil when bit i of the nil bitset is set (UNCOMPACTED: values indexed by i).
awo_payload_at :: proc(buf: []u8, ps: int) -> (base_nil: int, base_val: int, count: int) {
	c, cB := read_leb(buf, ps)
	base_nil = ps + cB
	count = int(c)
	base_val = base_nil + (count + 7) / 8
	return
}

awo_payload :: proc(buf: []u8, slot: int) -> (base_nil: int, base_val: int, count: int) {
	return awo_payload_at(buf, fwd_target(buf, slot))
}

nil_bit :: proc(buf: []u8, base_nil: int, i: int) -> bool {
	return (buf[base_nil + (i >> 3)] >> u8(i & 7)) & 1 != 0
}

// Zero-copy view of a regular-node inline numeric array payload as `[]T` (T a native
// fixed-width scalar). On LE hardware the raw bytes ARE the native little-endian
// values, so this is a reinterpret with no copy and no per-element decode.
num_slice :: proc($T: typeid, buf: []u8, base: int, count: int) -> []T {
	return slice.reinterpret([]T, buf[base : base + count * size_of(T)])
}

// LEB128 unsigned varint -> (value, bytesConsumed).
read_leb :: proc(buf: []u8, at: int) -> (u64, int) {
	pos := at
	result: u64 = 0
	shift: u64 = 0
	for {
		b := buf[pos]
		result += u64(b & 0x7F) << shift
		shift += 7
		pos += 1
		if (b >> 7) == 0 { break }
	}
	return result, pos - at
}

// ZigZag decode (branchless): (n>>1) XOR -(n&1). Odin `~` is binary XOR.
zigzag_decode :: proc(n: u64) -> i64 {
	return i64(n >> 1) ~ -i64(n & 1)
}

// ── Fixed-width native-LE scalar reads (regular-node vtable slots; unaligned) ──
read_u8 :: proc(buf: []u8, at: int) -> u8 { return buf[at] }
// Byte-slice equality (used by default elision §13 to test a `data` field vs its default).
bytes_equal :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) { return false }
	for i in 0 ..< len(a) { if a[i] != b[i] { return false } }
	return true
}
// Element-wise slice equality (default elision §13: a numeric array field vs its default).
slice_eq :: proc(a, b: []$T) -> bool {
	if len(a) != len(b) { return false }
	for i in 0 ..< len(a) { if a[i] != b[i] { return false } }
	return true
}
read_u16 :: proc(buf: []u8, at: int) -> u16 { return u16(intrinsics.unaligned_load((^u16le)(&buf[at]))) }
read_u32 :: proc(buf: []u8, at: int) -> u32 { return u32(intrinsics.unaligned_load((^u32le)(&buf[at]))) }
read_u64 :: proc(buf: []u8, at: int) -> u64 { return u64(intrinsics.unaligned_load((^u64le)(&buf[at]))) }
read_i8 :: proc(buf: []u8, at: int) -> i8 { return i8(buf[at]) }
read_i16 :: proc(buf: []u8, at: int) -> i16 { return i16(intrinsics.unaligned_load((^i16le)(&buf[at]))) }
read_i32 :: proc(buf: []u8, at: int) -> i32 { return i32(intrinsics.unaligned_load((^i32le)(&buf[at]))) }
read_i64 :: proc(buf: []u8, at: int) -> i64 { return i64(intrinsics.unaligned_load((^i64le)(&buf[at]))) }
read_f32 :: proc(buf: []u8, at: int) -> f32 { return f32(intrinsics.unaligned_load((^f32le)(&buf[at]))) }
read_f64 :: proc(buf: []u8, at: int) -> f64 { return f64(intrinsics.unaligned_load((^f64le)(&buf[at]))) }
read_f16 :: proc(buf: []u8, at: int) -> f16 { return intrinsics.unaligned_load((^f16)(&buf[at])) }
read_bool :: proc(buf: []u8, at: int) -> bool { return buf[at] != 0 }

// bf16 has no native Odin type: read the u16 bits and widen to f32 (the API type).
read_bf16 :: proc(buf: []u8, at: int) -> f32 {
	bits := u16(intrinsics.unaligned_load((^u16le)(&buf[at])))
	return transmute(f32)(u32(bits) << 16)
}

// ── Packed-node primitives (06 Packed Nodes.md) ─────────────────────────────
// A packed (tagged) node is `[LEB blockLen][ per-field [LEB tag][payload] ]`, fields
// in ascending index order, absent fields omitted. `tag = (fieldIndex << 1) | isRaw`.
// The reader has no origin/borrow system, so accessors stay plain `{buf, pos}` and a
// getter re-scans from the block start (cheap: few fields) via `{node}_p` locators.

// Block bounds: reads the size LEB at `start`, returns (entries_start, entries_end).
packed_bounds :: proc(buf: []u8, start: int) -> (es: int, ee: int) {
	s, b := read_leb(buf, start)
	es = start + b
	ee = es + int(s)
	return
}

// End position of a LEB at `at` (skip a self-delimiting encoded int/enum payload).
leb_end :: proc(buf: []u8, at: int) -> int {
	_, b := read_leb(buf, at)
	return at + b
}

// End of a size-prefixed blob `[LEB N][N bytes]` at `at` (skip utf8 / data payload).
skip_blob :: proc(buf: []u8, at: int) -> int {
	n, b := read_leb(buf, at)
	return at + b + int(n)
}

// Signed packed ints are ZigZag-LEB. Returns (value, bytesConsumed).
read_zigzag_leb :: proc(buf: []u8, at: int) -> (i64, int) {
	v, b := read_leb(buf, at)
	return zigzag_decode(v), b
}

// Packed float compression (§12): a sub-tag byte selects the encoding.
//   00 +0 · 01 -0 · 02 +inf · 03 -inf · 04 NaN · 05 zigzag-LEB int
//   06 f16 bits (2B) · 07 f32 (4B) · 08 f64 (8B, f64 only). Specials via bit pattern.
// Returns (value, bytesConsumed); the fallback tag (07 f32 / 08 f64) never appears on
// the encoded path (fallback is stored raw), but is decoded for robustness.
decode_packed_f32 :: proc(buf: []u8, at: int) -> (f32, int) {
	switch buf[at] {
	case 0: return 0, 1
	case 1: return transmute(f32)(u32(0x80000000)), 1
	case 2: return transmute(f32)(u32(0x7F800000)), 1
	case 3: return transmute(f32)(u32(0xFF800000)), 1
	case 4: return transmute(f32)(u32(0x7FC00000)), 1
	case 5:
		v, n := read_zigzag_leb(buf, at + 1)
		return f32(v), 1 + n
	case 6:
		return f32(read_f16(buf, at + 1)), 3
	case:  // 7 fallback
		return read_f32(buf, at + 1), 5
	}
}

decode_packed_f64 :: proc(buf: []u8, at: int) -> (f64, int) {
	switch buf[at] {
	case 0: return 0, 1
	case 1: return transmute(f64)(u64(0x8000000000000000)), 1
	case 2: return transmute(f64)(u64(0x7FF0000000000000)), 1
	case 3: return transmute(f64)(u64(0xFFF0000000000000)), 1
	case 4: return transmute(f64)(u64(0x7FF8000000000000)), 1
	case 5:
		v, n := read_zigzag_leb(buf, at + 1)
		return f64(v), 1 + n
	case 6:
		return f64(read_f16(buf, at + 1)), 3
	case 7:
		return f64(read_f32(buf, at + 1)), 5
	case:  // 8 fallback
		return read_f64(buf, at + 1), 9
	}
}

// Packed f16/bf16 encoded path: special values only, 1 byte (non-special is stored raw
// 2-byte native, handled by the caller). bf16 widens to f32 (its API type).
decode_packed_f16 :: proc(buf: []u8, at: int) -> (f16, int) {
	switch buf[at] {
	case 1: return transmute(f16)(u16(0x8000)), 1
	case 2: return transmute(f16)(u16(0x7C00)), 1
	case 3: return transmute(f16)(u16(0xFC00)), 1
	case 4: return transmute(f16)(u16(0x7E00)), 1
	case:   return 0, 1  // tag 0 (+0)
	}
}

decode_packed_bf16 :: proc(buf: []u8, at: int) -> (f32, int) {
	switch buf[at] {
	case 1: return transmute(f32)(u32(0x80000000)), 1
	case 2: return transmute(f32)(u32(0x7F800000)), 1
	case 3: return transmute(f32)(u32(0xFF800000)), 1
	case 4: return transmute(f32)(u32(0x7FC00000)), 1
	case:   return 0, 1  // tag 0 (+0)
	}
}

// Packed union header `[LEB (typeId<<3)|code][payload]` (06 §8). Returns
// (payload_pos, tag, code): code = payload size class — 0 LEB · 1/2/3/4 = 1/2/4/8 raw
// bytes · 5 packed-float · 6 len-prefixed block (utf8/data/array/nested node|union).
packed_union_header :: proc(buf: []u8, at: int) -> (vp: int, tag: u8, code: u8) {
	r, b := read_leb(buf, at)
	return at + b, u8((r >> 3) & 0xFF), u8(r & 7)
}

// Byte size of a packed-union payload after its header (skip a union field in a scan).
packed_union_payload_bytes :: proc(buf: []u8, ep: int, code: int) -> int {
	switch code {
	case 0: _, b := read_leb(buf, ep); return b
	case 1: return 1
	case 2: return 2
	case 3: return 4
	case 4: return 8
	case 5: _, n := decode_packed_f64(buf, ep); return n  // self-describing packed float
	case:   r, b := read_leb(buf, ep); return b + int(r)  // code 6: len-prefixed block
	}
}

// ── Frozen-node primitives (06 §13 / 05 Regular Nodes) ──────────────────────
// A frozen (non-packed) node is `[presence bitset ⌈nOpt/8⌉][field values in ID order]`
// (bitset omitted if no optional fields). Values are RAW (like a regular node); only
// field position differs (a positional forward-walk, not a vtable).

// Read an `n`-byte little-endian presence/encoding bitset as a u64 (n ≤ 8).
read_bitset :: proc(buf: []u8, at: int, n: int) -> u64 {
	v: u64 = 0
	for k in 0 ..< n { v |= u64(buf[at + k]) << uint(8 * k) }
	return v
}

// Byte width of a V62 pointer at `at` (from its low 2 bits: 0→1,1→2,2→4,3→8) — advances
// the frozen walk past a forward-pointer slot (utf8/data/array) or bidir node-ref slot.
v62_bytes :: proc(buf: []u8, at: int) -> int { return 1 << uint(buf[at] & 3) }

// Total bytes of a union field slot `[LEB (typeId<<2)|wc][1<<wc payload]` — advances the
// frozen walk past a union field.
union_slot_bytes :: proc(buf: []u8, at: int) -> int {
	r, b := read_leb(buf, at)
	return b + (1 << uint(r & 3))
}

// Raw embedded-graph leaf (17 §4): a `raw` node-ref inline entry
// `[LEB payloadLen][pad?][standalone .dagr blob]`. `pos` = payloadLen LEB start;
// `has_pad` = the embedded graph is alignment-bearing (a leading pad byte precedes the
// blob framing). Returns the absolute root-node position inside the blob (opened with the
// target's OWN-format accessor).
raw_embedded_root :: proc(buf: []u8, pos: int, has_pad: bool) -> int {
	_, plb := read_leb(buf, pos)                 // payloadLen (skip)
	bs := pos + plb + (has_pad ? 1 : 0)          // blob framing byte
	fr, frb := read_leb(buf, bs)
	return bs + frb + int(fr >> 2)
}

// V62 bidirectional pointer. Low 2 bits select width (0→1B,1→2B,2→4B,3→8B),
// value = raw >> 2. Returns (value, bytesConsumed). UNSIGNED for utf8/data/array
// forward pointers; wrap in read_zigzag_v62 for node-refs (may point backward).
read_v62 :: proc(buf: []u8, at: int) -> (u64, int) {
	switch int(buf[at] & 3) {
	case 0:  return u64(buf[at]) >> 2, 1
	case 1:  return u64(read_u16(buf, at)) >> 2, 2
	case 2:  return u64(read_u32(buf, at)) >> 2, 4
	case:    return read_u64(buf, at) >> 2, 8
	}
}

read_zigzag_v62 :: proc(buf: []u8, at: int) -> (i64, int) {
	v, n := read_v62(buf, at)
	return zigzag_decode(v), n
}

// Length-prefixed utf8 / data ([LEB count][bytes]). Zero-copy: returns a `string` /
// `[]u8` aliasing the buffer (no allocation — Odin has no origin system) + the byte
// count so inline callers can advance (forward-pointer callers ignore it).
read_utf8 :: proc(buf: []u8, at: int) -> (string, int) {
	length, b := read_leb(buf, at)
	start := at + b
	return string(buf[start : start + int(length)]), b + int(length)
}

read_data :: proc(buf: []u8, at: int) -> ([]u8, int) {
	length, b := read_leb(buf, at)
	start := at + b
	return buf[start : start + int(length)], b + int(length)
}

// Union field slot header `[LEB (tag<<2)|wc][payload]`. Returns (payload_pos, tag).
// The wc (payload width class) low bits are only needed by the frozen forward-walk;
// each variant reader self-describes its payload width.
union_header :: proc(buf: []u8, pos: int) -> (vp: int, tag: u8) {
	r, b := read_leb(buf, pos)
	return pos + b, u8(r >> 2)
}

// Root node absolute offset from the framing word (bit0 = custom-header flag).
root_offset :: proc(buf: []u8) -> int {
	framing, hb := read_leb(buf, 0)
	assert(framing & 1 == 0, "unexpected custom header")
	return hb + int(framing >> 2)
}

// Regular-node vtable: the node-relative offset of field `idx` (-1 = absent), without
// materializing the whole table. node-start pointer LEB is ZigZag: even = dedup
// forward-ref (+b1 off-by-one), odd = fresh vtable. Header LEB = (fieldCount<<1)|wide.
field_offset :: proc(buf: []u8, start: int, idx: int) -> int {
	offset_value, b1 := read_leb(buf, start)
	adj := (offset_value & 1) == 0 ? b1 : 0
	vt_start := start + int(zigzag_decode(offset_value)) + adj
	vt_size, b2 := read_leb(buf, vt_start)
	count := int(vt_size >> 1)
	if idx >= count { return -1 }
	wide := (vt_size & 1) != 0
	cursor := vt_start + b2 + (wide ? idx * 2 : idx)
	v := wide ? int(read_u16(buf, cursor)) : int(buf[cursor])
	return v == 0 ? -1 : v - 1 + b1
}

// ── Mutable arena handle packing (plan 29 §8.5) ───────────────────────────────
// A node handle packs generation (bits 40..63) | index (bits 0..39) into a u64.
// deletable=False arenas use bare index (generation always 0).
DAGR_IDX_MASK :: u64(0xFF_FFFF_FFFF) // low 40 bits
dagr_pack :: proc(gen: u32, idx: int) -> u64 { return (u64(gen) << 40) | (u64(idx) & DAGR_IDX_MASK) }
dagr_uidx :: proc(p: u64) -> int { return int(p & DAGR_IDX_MASK) }
dagr_ugen :: proc(p: u64) -> u32 { return u32(p >> 40) }

// ── Cycle-aware structural methods support (plan 29 §8.7) ──────────────────────
// Visited-set key: a node's arena identity (type tag + arena address + slot index). The
// arena codegen assigns each node a TRAVERSAL ORDINAL keyed on this, so the canonical string
// is arena-identity-free (isomorphic graphs in different arenas canonicalize equal).
Dagr_NodeKey :: struct { type_id: int, arena: int, index: int }
dagr_fnv1a :: proc(data: []u8) -> u64 {
	h: u64 = 0xcbf29ce484222325
	for b in data { h = (h ~ u64(b)) * 0x100000001b3 }
	return h
}
