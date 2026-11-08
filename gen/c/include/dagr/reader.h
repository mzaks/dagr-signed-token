/* dagr/reader.h — the C target's read runtime, packed subset (spec/44 §12.1): what a
 * generated packed accessor calls. A transliteration of the C++ target's dagr/reader.hpp
 * (the parts a packed record needs) and the scalar half of dagr/packed.hpp.
 *
 * THE CONTRACT (spec/41 §5, kept): every function here is TOTAL. For any bytes and any
 * position it returns without reading outside [buf.ptr, buf.ptr + buf.len). What it returns
 * for malformed input is unspecified but safe — a zero, an empty view, SIZE_MAX (no
 * position), a zero length. Three rules make that hold:
 *
 *   1. A dereference takes an ABSOLUTE position and is checked at that position. Position
 *      arithmetic is unsigned and may wrap: a wrapped position fails the check like any
 *      other. SIZE_MAX is "no position" — reading through it yields zeros.
 *   2. A length or count read from the buffer is clamped against the bytes that remain
 *      WHERE IT IS RECORDED.
 *   3. A varint read that fails reports length 0, and a scan stops on it.
 *
 * Core tier: <stdbool.h> <stddef.h> <stdint.h> <string.h>; no allocation.
 */
#ifndef DAGR_READER_H
#define DAGR_READER_H

#include "sb_core.h"

/* ── Status ──────────────────────────────────────────────────────────────────── */

/** Why something did not happen — the C++ target's `dagr::Status`, same values, same order. */
typedef enum dagr_status {
  dagr_ok = 0,
  dagr_bad_framing,     /* the framing word is malformed or points outside the buffer */
  dagr_no_header,       /* a header was asked for and the framing word carries none (spec 15) */
  dagr_malformed,       /* inconsistent bytes */
  dagr_buffer_full,     /* a fixed-capacity writer, scratch or destination ran out of room */
  dagr_depth_exceeded,  /* a recursive walk over the data hit its depth limit */
  dagr_invalid_value,   /* a value holds what the wire cannot express (a union with no variant) */
  dagr_out_of_memory,   /* a growing writer or scratch could not allocate */
  dagr_rejected,        /* an open-time gate refused the stream (spec 34 §4.3) */
  dagr_wrong_type,      /* a DataSink record was asked for as a type it is not */
  dagr_invalid_utf8     /* a utf8 value is not well-formed UTF-8 (spec/49 U1) */
} dagr_status;

/* ── Bounds ──────────────────────────────────────────────────────────────────── */

/** Whether [at, at + len) lies inside the buffer — neither a wrapped `at` nor a huge `len`
 * can pass. */
static inline bool dagr_in_bounds(dagr_bytes b, size_t at, size_t len) {
  return at <= b.len && len <= b.len - at;
}

/** Bytes left from `at` to the end of the buffer (0 when `at` is out of range). */
static inline size_t dagr_remaining(dagr_bytes b, size_t at) { return at <= b.len ? b.len - at : 0; }

/* ── Checked fixed-width loads ───────────────────────────────────────────────── */

static inline uint8_t dagr_read_u8(dagr_bytes b, size_t at) { return at < b.len ? b.ptr[at] : 0; }
static inline uint16_t dagr_read_u16(dagr_bytes b, size_t at) {
  return dagr_in_bounds(b, at, 2) ? dagr_sb_get_u16(b.ptr, at) : 0;
}
static inline uint32_t dagr_read_u32(dagr_bytes b, size_t at) {
  return dagr_in_bounds(b, at, 4) ? dagr_sb_get_u32(b.ptr, at) : 0;
}
static inline uint64_t dagr_read_u64(dagr_bytes b, size_t at) {
  return dagr_in_bounds(b, at, 8) ? dagr_sb_get_u64(b.ptr, at) : 0;
}
static inline int8_t dagr_read_i8(dagr_bytes b, size_t at) { return (int8_t)dagr_read_u8(b, at); }
static inline int16_t dagr_read_i16(dagr_bytes b, size_t at) { return (int16_t)dagr_read_u16(b, at); }
static inline int32_t dagr_read_i32(dagr_bytes b, size_t at) { return (int32_t)dagr_read_u32(b, at); }
static inline int64_t dagr_read_i64(dagr_bytes b, size_t at) { return (int64_t)dagr_read_u64(b, at); }
static inline bool dagr_read_bool(dagr_bytes b, size_t at) { return dagr_read_u8(b, at) != 0; }
static inline float dagr_read_f32(dagr_bytes b, size_t at) { return dagr_f32_from_bits(dagr_read_u32(b, at)); }
static inline double dagr_read_f64(dagr_bytes b, size_t at) { return dagr_f64_from_bits(dagr_read_u64(b, at)); }
static inline float dagr_read_f16(dagr_bytes b, size_t at) { return dagr_f16_to_f32(dagr_read_u16(b, at)); }
static inline float dagr_read_bf16(dagr_bytes b, size_t at) { return dagr_bf16_to_f32(dagr_read_u16(b, at)); }

/** An unsigned `width`-byte little-endian integer (width ≤ 8). */
static inline uint64_t dagr_read_uint_le(dagr_bytes b, size_t at, size_t width) {
  uint64_t v = 0;
  if (width <= 8 && dagr_in_bounds(b, at, width)) {
    for (size_t k = 0; k < width; k++) v |= (uint64_t)b.ptr[at + k] << (8 * k);
  }
  return v;
}

/** The low `width` bytes of `v` — a two's-complement integer of that width — sign-extended;
 * whatever the bits above them hold. */
static inline int64_t dagr_sign_extend(uint64_t v, size_t width) {
  if (width >= 8) return (int64_t)v;
  const unsigned bits = (unsigned)(8 * width);
  const uint64_t sign = UINT64_C(1) << (bits - 1);
  const uint64_t low = v & ((UINT64_C(1) << bits) - 1u);
  return (int64_t)((low ^ sign) - sign);
}

/** Bit `i` of a bitset starting at `base`. */
static inline bool dagr_bit_at(dagr_bytes b, size_t base, size_t i) {
  return (((unsigned)dagr_read_u8(b, base + (i >> 3)) >> (i & 7u)) & 1u) != 0;
}

/** `bits` bits (1, 2 or 4) of element `i` of a bit-packed array at `base`. */
static inline unsigned dagr_packed_bits(dagr_bytes b, size_t base, size_t i, unsigned bits) {
  const size_t bit = i * bits;
  return ((unsigned)dagr_read_u8(b, base + (bit >> 3)) >> (bit & 7u)) & ((1u << bits) - 1u);
}

/* ── Varints ─────────────────────────────────────────────────────────────────── */

/** A decoded varint and the bytes it occupied; `len == 0` means the read failed (truncated,
 * out of range, or longer than a u64 allows), and `value` is then 0. */
typedef struct dagr_varint {
  uint64_t value;
  size_t len;
} dagr_varint;

static inline dagr_varint dagr_varint_of(uint64_t value, size_t len) {
  dagr_varint v;
  v.value = value;
  v.len = len;
  return v;
}

static inline dagr_varint dagr_read_leb_multi(dagr_bytes b, size_t at) {
  uint64_t result = 0;
  unsigned shift = 0;
  size_t pos = at;
  for (;;) {
    /* a u64 needs at most 10 LEB bytes (shift 63); anything longer is malformed */
    if (pos >= b.len || shift > 63) return dagr_varint_of(0, 0);
    const uint8_t byte = b.ptr[pos];
    result |= (uint64_t)(byte & 0x7fu) << shift;
    pos++;
    shift += 7;
    if ((byte & 0x80u) == 0) break;
  }
  return dagr_varint_of(result, pos - at);
}

/** Unsigned LEB128 at `at`; the one- and two-byte cases inline. */
static inline dagr_varint dagr_read_leb(dagr_bytes b, size_t at) {
  if (at < b.len) {
    const uint8_t b0 = b.ptr[at];
    if (b0 < 0x80u) return dagr_varint_of(b0, 1);
    if (b.len - at >= 2) {
      const uint8_t b1 = b.ptr[at + 1];
      if (b1 < 0x80u) return dagr_varint_of((uint64_t)(b0 & 0x7fu) | ((uint64_t)b1 << 7), 2);
    }
    return dagr_read_leb_multi(b, at);
  }
  return dagr_varint_of(0, 0);
}

static inline int64_t dagr_zigzag_decode(uint64_t n) { return (int64_t)(n >> 1) ^ -(int64_t)(n & 1); }
static inline uint64_t dagr_zigzag_encode(int64_t v) { return ((uint64_t)v << 1) ^ (uint64_t)(v >> 63); }

/** Position just past the varint at `at`, or SIZE_MAX when it cannot be read. */
static inline size_t dagr_leb_end(dagr_bytes b, size_t at) {
  const dagr_varint v = dagr_read_leb(b, at);
  return v.len != 0 ? at + v.len : SIZE_MAX;
}

/** End of a size-prefixed blob `[LEB N][N bytes]` at `at`, or SIZE_MAX when it does not fit. */
static inline size_t dagr_skip_blob(dagr_bytes b, size_t at) {
  const dagr_varint n = dagr_read_leb(b, at);
  if (n.len == 0) return SIZE_MAX;
  const size_t start = at + n.len;
  if (n.value > dagr_remaining(b, start)) return SIZE_MAX;
  return start + (size_t)n.value;
}

/** The bytes of the `[LEB N][N bytes]` blob at `at`; empty when unreadable or overlong. */
static inline dagr_bytes dagr_read_blob(dagr_bytes b, size_t at) {
  const dagr_varint n = dagr_read_leb(b, at);
  if (n.len == 0) return dagr_bytes_of(NULL, 0);
  const size_t start = at + n.len;
  if (n.value > dagr_remaining(b, start)) return dagr_bytes_of(NULL, 0);
  return dagr_bytes_of(b.ptr + start, (size_t)n.value);
}

/** Whether `s` is well-formed UTF-8 (RFC 3629): no overlong form, no surrogate, nothing above
 * U+10FFFF, no sequence cut short. Total on any bytes. */
static inline bool dagr_valid_utf8(dagr_str s) {
  const unsigned char *p = (const unsigned char *)(const void *)s.ptr;
  const size_t n = s.len;
  size_t i = 0;
  while (i < n) {
    const unsigned char c = p[i];
    if (c < 0x80) {
      i++;
      continue;
    }
    size_t len;
    unsigned char lo = 0x80, hi = 0xBF; /* the bounds of the second byte */
    if (c >= 0xC2 && c <= 0xDF) {
      len = 2;
    } else if (c >= 0xE0 && c <= 0xEF) {
      len = 3;
      if (c == 0xE0) lo = 0xA0; /* no overlong 3-byte form */
      if (c == 0xED) hi = 0x9F; /* no surrogate */
    } else if (c >= 0xF0 && c <= 0xF4) {
      len = 4;
      if (c == 0xF0) lo = 0x90; /* no overlong 4-byte form */
      if (c == 0xF4) hi = 0x8F; /* nothing above U+10FFFF */
    } else {
      return false;
    }
    if (n - i < len) return false;
    if (p[i + 1] < lo || p[i + 1] > hi) return false;
    for (size_t k = 2; k < len; k++) {
      if (p[i + k] < 0x80 || p[i + k] > 0xBF) return false;
    }
    i += len;
  }
  return true;
}

/** A utf8 blob as text — a view, not validated as UTF-8 (the restores check it, spec/49). */
static inline dagr_str dagr_read_text(dagr_bytes b, size_t at) {
  const dagr_bytes v = dagr_read_blob(b, at);
  return dagr_str_of((const char *)(const void *)v.ptr, v.len);
}

/** `buf[from, to)`, clamped to the buffer: never a view outside it. */
static inline dagr_bytes dagr_slice(dagr_bytes buf, size_t from, size_t to) {
  if (from > buf.len) from = buf.len;
  if (to > buf.len) to = buf.len;
  if (to < from) to = from;
  return dagr_bytes_of(buf.len == 0 ? NULL : buf.ptr + from, to - from);
}

/* ── Packed nodes (spec 07) ─────────────────────────────────────────────────── */

/** The entries of the packed block whose length LEB is at `start`. A block that does not
 * fit in the buffer is empty. */
typedef struct dagr_block {
  size_t begin;
  size_t end;
} dagr_block;

static inline dagr_block dagr_packed_bounds(dagr_bytes b, size_t start) {
  dagr_block out;
  const dagr_varint s = dagr_read_leb(b, start);
  if (s.len == 0) {
    out.begin = SIZE_MAX;
    out.end = SIZE_MAX;
    return out;
  }
  out.begin = start + s.len;
  out.end = s.value > dagr_remaining(b, out.begin) ? out.begin : out.begin + (size_t)s.value;
  return out;
}

/** A decoded float and the bytes it occupied (`len == 0`: unreadable). */
typedef struct dagr_float_read {
  double value;
  size_t len;
} dagr_float_read;

static inline dagr_float_read dagr_float_read_of(double value, size_t len) {
  dagr_float_read r;
  r.value = value;
  r.len = len;
  return r;
}

/** A self-describing packed float (spec 07 §12): 00 +0 · 01 -0 · 02 +inf · 03 -inf · 04 NaN ·
 * 05 zigzag-LEB integer · 06 f16 bits · 07 f32 · 08 f64. `single` decodes as an f32 would
 * (the integer and NaN as f32, then widened). */
static inline dagr_float_read dagr_decode_packed_float(dagr_bytes b, size_t at, bool single) {
  if (at >= b.len) return dagr_float_read_of(0.0, 0);
  switch (b.ptr[at]) {
    case 0: return dagr_float_read_of(0.0, 1);
    case 1: return dagr_float_read_of(dagr_f64_from_bits(UINT64_C(0x8000000000000000)), 1);
    case 2: return dagr_float_read_of(dagr_f64_from_bits(UINT64_C(0x7FF0000000000000)), 1);
    case 3: return dagr_float_read_of(dagr_f64_from_bits(UINT64_C(0xFFF0000000000000)), 1);
    case 4:
      return dagr_float_read_of(single ? (double)dagr_f32_from_bits(0x7FC00000u)
                                       : dagr_f64_from_bits(UINT64_C(0x7FF8000000000000)),
                                1);
    case 5: {
      const dagr_varint v = dagr_read_leb(b, at + 1);
      if (v.len == 0) return dagr_float_read_of(0.0, 0);
      const int64_t iv = dagr_zigzag_decode(v.value);
      return dagr_float_read_of(single ? (double)(float)iv : (double)iv, 1 + v.len);
    }
    case 6: return dagr_in_bounds(b, at + 1, 2) ? dagr_float_read_of(dagr_read_f16(b, at + 1), 3) : dagr_float_read_of(0.0, 0);
    case 7: return dagr_in_bounds(b, at + 1, 4) ? dagr_float_read_of(dagr_read_f32(b, at + 1), 5) : dagr_float_read_of(0.0, 0);
    default:
      /* as the C++ decoders: an f32 reads any other tag as 07, an f64 as 08 */
      if (single) return dagr_in_bounds(b, at + 1, 4) ? dagr_float_read_of(dagr_read_f32(b, at + 1), 5) : dagr_float_read_of(0.0, 0);
      return dagr_in_bounds(b, at + 1, 8) ? dagr_float_read_of(dagr_read_f64(b, at + 1), 9) : dagr_float_read_of(0.0, 0);
  }
}

/** The encoded (special-value, one byte) form of a packed f16 / bf16; anything else is
 * stored raw and read by the caller. */
static inline float dagr_decode_packed_half(dagr_bytes b, size_t at) {
  switch (dagr_read_u8(b, at)) {
    case 1: return dagr_f32_from_bits(0x80000000u);
    case 2: return dagr_f32_from_bits(0x7F800000u);
    case 3: return dagr_f32_from_bits(0xFF800000u);
    case 4: return dagr_f32_from_bits(0x7FC00000u);
    default: return 0.0f;
  }
}

/* ── Packed scalars: the payload is a varint or the raw fixed-width form ───────
 * `raw` comes from the field's tag bit (packed nodes), its encoding bit (frozen+packed) or a
 * union header's code. */

static inline uint64_t dagr_read_packed_uint(dagr_bytes b, size_t at, bool raw, size_t width) {
  return raw ? dagr_read_uint_le(b, at, width) : dagr_read_leb(b, at).value;
}
static inline int64_t dagr_read_packed_int(dagr_bytes b, size_t at, bool raw, size_t width) {
  return raw ? dagr_sign_extend(dagr_read_uint_le(b, at, width), width) : dagr_zigzag_decode(dagr_read_leb(b, at).value);
}
static inline float dagr_read_packed_f32(dagr_bytes b, size_t at, bool raw) {
  return raw ? dagr_read_f32(b, at) : (float)dagr_decode_packed_float(b, at, true).value;
}
static inline double dagr_read_packed_f64(dagr_bytes b, size_t at, bool raw) {
  return raw ? dagr_read_f64(b, at) : dagr_decode_packed_float(b, at, false).value;
}
static inline float dagr_read_packed_f16(dagr_bytes b, size_t at, bool raw) {
  return raw ? dagr_read_f16(b, at) : dagr_decode_packed_half(b, at);
}
static inline float dagr_read_packed_bf16(dagr_bytes b, size_t at, bool raw) {
  return raw ? dagr_read_bf16(b, at) : dagr_decode_packed_half(b, at);
}

/* A packed UNION variant says how its payload is encoded in the header's `code` (spec 07 §8):
 * 0 a varint, 1 / 2 / 3 / 4 a fixed 1 / 2 / 4 / 8 bytes. */

/** An unsigned integer variant of any width — a wide enum a writer may have stored in one byte. */
static inline uint64_t dagr_read_packed_union_uint(dagr_bytes b, size_t at, unsigned code) {
  switch (code) {
    case 0: return dagr_read_leb(b, at).value;
    case 1: return dagr_read_u8(b, at);
    case 2: return dagr_read_u16(b, at);
    case 3: return dagr_read_u32(b, at);
    default: return dagr_read_u64(b, at);
  }
}

/** An f16 / bf16 variant: its 16 bits AS AN UNSIGNED INTEGER — a varint under code 0 (older
 * writers), two raw bytes otherwise. Not the field codec. */
static inline float dagr_read_packed_union_f16(dagr_bytes b, size_t at, unsigned code) {
  return dagr_f16_to_f32((uint16_t)dagr_read_packed_union_uint(b, at, code == 0 ? 0u : 2u));
}
static inline float dagr_read_packed_union_bf16(dagr_bytes b, size_t at, unsigned code) {
  return dagr_bf16_to_f32((uint16_t)dagr_read_packed_union_uint(b, at, code == 0 ? 0u : 2u));
}

/* ── Packed unions ───────────────────────────────────────────────────────────── */

/** `[LEB (typeId << 3) | code]` at `at`: the payload position (SIZE_MAX: unreadable), the
 * type id and the code. */
typedef struct dagr_pk_union_header {
  size_t payload;
  uint32_t tag;
  uint32_t code;
} dagr_pk_union_header;

static inline dagr_pk_union_header dagr_packed_union_header(dagr_bytes b, size_t at) {
  dagr_pk_union_header h;
  const dagr_varint r = dagr_read_leb(b, at);
  h.payload = r.len != 0 ? at + r.len : SIZE_MAX;
  h.tag = r.len != 0 ? (uint32_t)((r.value >> 3) & 0xffu) : 0;
  h.code = r.len != 0 ? (uint32_t)(r.value & 7u) : 0;
  return h;
}

/** Byte size of a packed-union payload after its header; 0 when it cannot be sized. */
static inline size_t dagr_packed_union_payload_bytes(dagr_bytes b, size_t ep, unsigned code) {
  switch (code) {
    case 0: return dagr_read_leb(b, ep).len;
    case 1: return 1;
    case 2: return 2;
    case 3: return 4;
    case 4: return 8;
    case 5: return dagr_decode_packed_float(b, ep, false).len;
    default: {
      const size_t end = dagr_skip_blob(b, ep);
      return end != SIZE_MAX ? end - ep : 0;
    }
  }
}

/* ── Scan steps: the position just past one field's payload ───────────────────
 * Each returns a position strictly greater than `at`, or SIZE_MAX when the payload cannot be
 * sized — past every block end, so it ends the scan. */

static inline size_t dagr_skip_packed_varint(dagr_bytes b, size_t at, bool raw, size_t width) {
  return raw ? at + width : dagr_leb_end(b, at);
}
static inline size_t dagr_skip_packed_float(dagr_bytes b, size_t at, bool raw, size_t width) {
  if (raw) return at + width;
  const size_t len = dagr_decode_packed_float(b, at, width == 4).len;
  return len != 0 ? at + len : SIZE_MAX;
}
static inline size_t dagr_skip_packed_half(size_t at, bool raw) { return at + (raw ? 2u : 1u); }
static inline size_t dagr_skip_packed_union(dagr_bytes b, size_t at) {
  const dagr_pk_union_header h = dagr_packed_union_header(b, at);
  const size_t len = dagr_packed_union_payload_bytes(b, h.payload, h.code);
  return len != 0 ? h.payload + len : SIZE_MAX;
}

/* ── Framing (spec 06, spec 15) ──────────────────────────────────────────────── */

/** The absolute root-node position of a GRAPH buffer from its framing word, or SIZE_MAX. With a
 * header (bit 0) the stored offset already spans it (spec 15 §4): the expression is the same. */
static inline size_t dagr_root_offset(dagr_bytes b) {
  const dagr_varint framing = dagr_read_leb(b, 0);
  if (framing.len == 0 || (framing.value & 2u) != 0) return SIZE_MAX;
  const uint64_t off = framing.value >> 2;
  if (off >= dagr_remaining(b, framing.len)) return SIZE_MAX;
  return framing.len + (size_t)off;
}

/** The framing of a graph buffer that carries a spec-15 header: where the header starts (right
 * after the framing word), its total span (size LEB + content), and the header-free root offset
 * the producer signed over (stored − span). */
typedef struct dagr_header_frame {
  size_t start;
  size_t span;
  size_t root_offset;
} dagr_header_frame;

/** `dagr_bad_framing`, `dagr_no_header` or `dagr_ok` with `*out` filled (zeroed otherwise). */
static inline dagr_status dagr_read_header_frame(dagr_bytes b, dagr_header_frame *out) {
  out->start = 0;
  out->span = 0;
  out->root_offset = 0;
  const dagr_varint framing = dagr_read_leb(b, 0);
  if (framing.len == 0 || (framing.value & 2u) != 0) return dagr_bad_framing;
  if ((framing.value & 1u) == 0) return dagr_no_header;
  const dagr_varint hcs = dagr_read_leb(b, framing.len);
  if (hcs.len == 0 || hcs.value > dagr_remaining(b, framing.len + hcs.len)) return dagr_bad_framing;
  const size_t span = hcs.len + (size_t)hcs.value;
  const uint64_t stored = framing.value >> 2;
  if (stored < span) return dagr_bad_framing;
  out->start = framing.len;
  out->span = span;
  out->root_offset = (size_t)stored - span;
  return dagr_ok;
}

/** Whether a graph buffer's framing word carries a header. */
static inline bool dagr_has_header(dagr_bytes b) {
  const dagr_varint framing = dagr_read_leb(b, 0);
  return framing.len != 0 && (framing.value & 1u) == 1;
}

/* ── V62 pointers (spec 06) ──────────────────────────────────────────────────── */

/** A V62 pointer: the low 2 bits of the first byte select the width (0→1, 1→2, 2→4, 3→8
 * bytes); the value is raw >> 2. Unsigned (forward pointers). `len == 0`: unreadable. */
static inline dagr_varint dagr_read_v62(dagr_bytes b, size_t at) {
  if (at >= b.len) return dagr_varint_of(0, 0);
  const size_t w = (size_t)1 << (b.ptr[at] & 3u);
  if (!dagr_in_bounds(b, at, w)) return dagr_varint_of(0, 0);
  return dagr_varint_of(dagr_read_uint_le(b, at, w) >> 2, w);
}

/** Byte width of the V62 pointer at `at` (advances a frozen walk); 0 when out of range. */
static inline size_t dagr_v62_bytes(dagr_bytes b, size_t at) {
  return at < b.len ? (size_t)1 << (b.ptr[at] & 3u) : 0;
}

/** The position the V62 forward pointer at `slot` targets, or SIZE_MAX when the pointer is
 * unreadable or leaves the buffer. */
static inline size_t dagr_fwd_target(dagr_bytes b, size_t slot) {
  const dagr_varint v = dagr_read_v62(b, slot);
  if (v.len == 0) return SIZE_MAX;
  const size_t from = slot + v.len;
  if (v.value > dagr_remaining(b, from)) return SIZE_MAX;
  return from + (size_t)v.value;
}

/** The position the bidirectional (ZigZag V62) node reference at `slot` targets, or SIZE_MAX
 * when the reference is unreadable. A backward reference — a shared or cyclic node — is a
 * negative offset; the sum is modular, so a hostile offset lands on some position that the
 * target accessor's own checked reads then deal with. */
static inline size_t dagr_ref_target(dagr_bytes b, size_t slot) {
  const dagr_varint v = dagr_read_v62(b, slot);
  if (v.len == 0) return SIZE_MAX;
  return slot + v.len + (size_t)(uint64_t)dagr_zigzag_decode(v.value);
}

/* ── Regular nodes: the vtable (spec 06) ─────────────────────────────────────── */

/** Absolute position of vtable field `idx` of the regular node at `start`, or SIZE_MAX when the
 * field is absent or the vtable unreadable — without materialising the table. The node-start
 * LEB is ZigZag: even = a dedup forward reference (+ its own width, off by one), odd = a fresh
 * vtable. The vtable header LEB is (fieldCount << 1) | wide. */
static inline size_t dagr_field_pos(dagr_bytes b, size_t start, size_t idx) {
  const dagr_varint ov = dagr_read_leb(b, start);
  if (ov.len == 0) return SIZE_MAX;
  const size_t adj = (ov.value & 1u) == 0 ? ov.len : 0;
  /* a hostile offset wraps; the vtable read below is checked at whatever it lands on */
  const size_t vt = start + (size_t)(uint64_t)dagr_zigzag_decode(ov.value) + adj;
  const dagr_varint vs = dagr_read_leb(b, vt);
  if (vs.len == 0 || idx >= (vs.value >> 1)) return SIZE_MAX;
  const size_t v = (vs.value & 1u) != 0 ? (size_t)dagr_read_u16(b, vt + vs.len + idx * 2)
                                        : (size_t)dagr_read_u8(b, vt + vs.len + idx);
  if (v == 0) return SIZE_MAX;
  return start + v - 1 + ov.len;
}

/* ── Union slots of regular and frozen nodes (spec 05) ───────────────────────── */

/** A union slot header `[LEB (tag << 2) | wc]` at `pos`: the payload (slot) position — SIZE_MAX
 * when unreadable — and the type id. */
typedef struct dagr_union_header {
  size_t payload;
  uint32_t tag;
} dagr_union_header;

static inline dagr_union_header dagr_read_union_header(dagr_bytes b, size_t pos) {
  dagr_union_header h;
  const dagr_varint r = dagr_read_leb(b, pos);
  h.payload = r.len != 0 ? pos + r.len : SIZE_MAX;
  h.tag = r.len != 0 ? (uint32_t)((r.value >> 2) & 0xffu) : 0;
  return h;
}

/** Total size of a union slot `[LEB (tag << 2) | wc][1 << wc bytes]` (advances a frozen walk);
 * 0 when unreadable. */
static inline size_t dagr_union_slot_bytes(dagr_bytes b, size_t at) {
  const dagr_varint r = dagr_read_leb(b, at);
  return r.len != 0 ? r.len + ((size_t)1 << (r.value & 3u)) : 0;
}

/* ── Raw-embedded graphs (spec 18) ───────────────────────────────────────────── */

/** Absolute root position inside a raw-embedded graph entry `[LEB payloadLen][pad?][standalone
 * graph]` at `pos` of a graph's packed node; SIZE_MAX when unreadable. */
static inline size_t dagr_raw_embedded_root(dagr_bytes b, size_t pos, bool has_pad) {
  const dagr_varint pl = dagr_read_leb(b, pos);
  if (pl.len == 0) return SIZE_MAX;
  const size_t bs = pos + pl.len + (has_pad ? 1u : 0u);
  const dagr_varint fr = dagr_read_leb(b, bs);
  if (fr.len == 0) return SIZE_MAX;
  const size_t from = bs + fr.len;
  const uint64_t off = fr.value >> 2;
  if (off >= dagr_remaining(b, from)) return SIZE_MAX;
  return from + (size_t)off;
}

#endif /* DAGR_READER_H */
