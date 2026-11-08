/* dagr/writer.h — the C target's write runtime, packed subset (spec/44 §12.1): the builder and
 * every packed store a generated record store calls. A transliteration of the C++ target's
 * dagr/fixed_writer.hpp, with its two builder types folded into one.
 *
 * Writer model: ONE buffer filled from its END toward its start — a parent is stored after
 * its children, so a block's length is known when its prefix is written and nothing is ever
 * patched. "Store X then store Y" puts Y BEFORE X in the finished bytes; each function's
 * comment gives the forward layout.
 *
 * dagr_builder: caller storage, a cursor, a sticky status — and an optional `grow` callback.
 * Without one it is the fixed builder (`dagr_buffer_full` when a record does not fit, no
 * allocation: core tier); dagr/heap.h supplies a growing one. The stores are the same code
 * over both, so `fixed == growing` is a real differential.
 *
 * FAILURE IS STICKY, NOT THREADED: a claim that cannot be served returns NULL, the store
 * writes nothing, and every later claim fails too; the caller checks the status once.
 *
 * Core tier: no allocation. */
#ifndef DAGR_WRITER_H
#define DAGR_WRITER_H

#include "reader.h"

typedef struct dagr_builder dagr_builder;

/** Makes room for `need` more bytes: re-points `data` / `cap` (keeping the stored bytes at
 * the END of the new storage) and returns true, or returns false. */
typedef bool (*dagr_grow_fn)(dagr_builder *b, size_t need);

struct dagr_builder {
  uint8_t *data;
  size_t cap;
  size_t cursor;            /* bytes stored so far, at data[cap - cursor, cap) */
  dagr_status status;
  size_t alignment_offset;  /* bytes that will precede the finished buffer (spec 12 §14) */
  dagr_grow_fn grow;        /* NULL: a fixed builder */
  void *grow_context;
};

/** A builder over caller storage: no allocation, `dagr_buffer_full` when a record does not fit. */
static inline dagr_builder dagr_builder_fixed(uint8_t *storage, size_t capacity) {
  dagr_builder b;
  b.data = storage;
  b.cap = capacity;
  b.cursor = 0;
  b.status = dagr_ok;
  b.alignment_offset = 0;
  b.grow = NULL;
  b.grow_context = NULL;
  return b;
}

/** Records the first failure and leaves no room, so that no later claim succeeds. */
static inline void dagr_builder_fail(dagr_builder *b, dagr_status status) {
  if (b->status == dagr_ok) b->status = status;
  b->cursor = b->cap;
}

static inline bool dagr_builder_ok(const dagr_builder *b) { return b->status == dagr_ok; }

/** `n` writable bytes immediately below what is stored so far, or NULL — and then every later
 * claim fails as well. */
static inline uint8_t *dagr_claim(dagr_builder *b, size_t n) {
  if (n > b->cap - b->cursor) {
    if (b->status != dagr_ok || b->grow == NULL || !b->grow(b, n)) {
      dagr_builder_fail(b, b->grow == NULL ? dagr_buffer_full : dagr_out_of_memory);
      return NULL;
    }
  }
  b->cursor += n;
  return b->data + (b->cap - b->cursor);
}

/** The bytes stored so far; empty once anything has failed. */
static inline dagr_bytes dagr_builder_bytes(const dagr_builder *b) {
  if (b->status != dagr_ok || b->cursor == 0) return dagr_bytes_of(NULL, 0);
  return dagr_bytes_of(b->data + (b->cap - b->cursor), b->cursor);
}

/** The first byte of what was stored when the cursor was `at` (an offset: bytes from it to the
 * record's end), or NULL — nothing stored there, or the builder has failed. The graph writer
 * reads back a cached string and patches a late-bound reference through it (spec/44 §12.4). */
static inline uint8_t *dagr_builder_written(dagr_builder *b, size_t at) {
  if (b->status != dagr_ok || at == 0 || at > b->cursor) return NULL;
  return b->data + (b->cap - at);
}

/** Rewinds for another record over the same storage (the alignment offset is kept). */
static inline void dagr_builder_reset(dagr_builder *b) {
  b->cursor = 0;
  b->status = dagr_ok;
}

/** `n` bytes below what is stored that may be written FORWARD without claiming them — a sink
 * record of bounded scalars (spec 11 §6.1) — growing for them; NULL once anything has failed,
 * and for a fixed builder they do not fit in. */
static inline uint8_t *dagr_builder_room(dagr_builder *b, size_t n) {
  if (b->status != dagr_ok) return NULL;
  if (n > b->cap - b->cursor && (b->grow == NULL || !b->grow(b, n))) return NULL;
  return b->data + (b->cap - b->cursor - n);
}

/** Appends `n` bytes AFTER what is stored — a doubly-linked sink's trailing span (spec 11
 * §11.5). What is stored moves down by `n`. Fails like a claim. */
static inline void dagr_builder_append_tail(dagr_builder *b, const uint8_t *tail, size_t n) {
  if (n == 0 || dagr_claim(b, n) == NULL) return;
  uint8_t *front = b->data + (b->cap - b->cursor);
  memmove(front, front + n, b->cursor - n);
  memcpy(b->data + (b->cap - n), tail, n);
}

/* ── Encoding arithmetic ─────────────────────────────────────────────────────── */

/** LEB128 byte length of `v` (0 → 1). */
static inline size_t dagr_leb_length(uint64_t v) {
  size_t n = 1;
  while (v >= 0x80u) {
    v >>= 7;
    n++;
  }
  return n;
}

/** Writes the LEB128 of `v` forward at `p`; returns its length. */
static inline size_t dagr_put_leb(uint8_t *p, uint64_t v) {
  size_t n = 0;
  while (v >= 0x80u) {
    p[n++] = (uint8_t)((v & 0x7fu) | 0x80u);
    v >>= 7;
  }
  p[n++] = (uint8_t)v;
  return n;
}

/** The low `width` bytes of `v`, little-endian, forward at `p`. */
static inline void dagr_put_le(uint8_t *p, uint64_t v, size_t width) {
  for (size_t k = 0; k < width; k++) p[k] = (uint8_t)(v >> (8 * k));
}

static inline void dagr_set_bit(uint8_t *bits, size_t i) { bits[i >> 3] = (uint8_t)(bits[i >> 3] | (1u << (i & 7u))); }

/** What the varint form of a packed integer encodes: the value, or its ZigZag when signed.
 * `bits` holds the value's two's complement in its low `width` bytes. */
static inline uint64_t dagr_leb_form(uint64_t bits, size_t width, bool is_signed) {
  return is_signed ? dagr_zigzag_encode(dagr_sign_extend(bits, width)) : bits;
}

/* ── Fixed-width scalars, bytes, varints ─────────────────────────────────────── */

static inline void dagr_store_u8(dagr_builder *b, uint8_t v) {
  uint8_t *p = dagr_claim(b, 1);
  if (p != NULL) *p = v;
}

/** The low `width` bytes of `v`, little-endian. */
static inline void dagr_store_fixed(dagr_builder *b, uint64_t v, size_t width) {
  uint8_t *p = dagr_claim(b, width);
  if (p != NULL) dagr_put_le(p, v, width);
}

/** Raw bytes, in order. */
static inline void dagr_store_bytes(dagr_builder *b, const void *src, size_t n) {
  if (n == 0) return;
  uint8_t *p = dagr_claim(b, n);
  if (p != NULL) memcpy(p, src, n);
}

static inline void dagr_store_zeros(dagr_builder *b, size_t n) {
  if (n == 0) return;
  uint8_t *p = dagr_claim(b, n);
  if (p != NULL) memset(p, 0, n);
}

/** Unsigned LEB128. */
static inline void dagr_store_leb(dagr_builder *b, uint64_t v) {
  if (v < 0x80u) {
    uint8_t *p = dagr_claim(b, 1);
    if (p != NULL) p[0] = (uint8_t)v;
    return;
  }
  uint8_t *p = dagr_claim(b, dagr_leb_length(v));
  if (p != NULL) dagr_put_leb(p, v);
}

/** `[LEB length][bytes]` in one claim — utf8 and data payloads. */
static inline void dagr_store_blob(dagr_builder *b, const void *src, size_t n) {
  const size_t ln = dagr_leb_length(n);
  uint8_t *p = dagr_claim(b, ln + n);
  if (p == NULL) return;
  dagr_put_leb(p, n);
  if (n != 0) memcpy(p + ln, src, n);
}

static inline void dagr_store_text(dagr_builder *b, dagr_str s) { dagr_store_blob(b, s.ptr, s.len); }
static inline void dagr_store_data(dagr_builder *b, dagr_bytes d) { dagr_store_blob(b, d.ptr, d.len); }

/* ── Packed scalars (spec 07 §3, §12) ─────────────────────────────────────────
 * A packed node's field is `[LEB (index << 1) | raw][payload]`; `raw` says the payload is in
 * its fixed-width form, otherwise the compact one (a varint, or the self-describing float
 * codec). The writer picks per value — the compact form only when strictly smaller — unless
 * the schema marks the field `raw` (spec 39). */

/** The payload of a u16..i64 field (`bits`: its two's complement in `width` bytes): a varint
 * when that is shorter than the width, else the width. Returns whether it went raw. */
static inline bool dagr_store_packed_int(dagr_builder *b, uint64_t bits, size_t width, bool is_signed, bool force_raw) {
  const uint64_t lv = dagr_leb_form(bits, width, is_signed);
  if (!force_raw && dagr_leb_length(lv) < width) {
    dagr_store_leb(b, lv);
    return false;
  }
  dagr_store_fixed(b, bits, width);
  return true;
}

/** `[tag][payload]` of a u16..i64 field in ONE claim. */
static inline void dagr_store_packed_int_field(dagr_builder *b, uint64_t bits, size_t width, bool is_signed,
                                               uint64_t index, bool force_raw) {
  const uint64_t lv = dagr_leb_form(bits, width, is_signed);
  const size_t ll = dagr_leb_length(lv);
  if (!force_raw && ll < width) {
    const uint64_t tag = index << 1;
    const size_t tl = dagr_leb_length(tag);
    uint8_t *p = dagr_claim(b, tl + ll);
    if (p != NULL) {
      dagr_put_leb(p, tag);
      dagr_put_leb(p + tl, lv);
    }
    return;
  }
  const uint64_t tag = (index << 1) | 1u;
  const size_t tl = dagr_leb_length(tag);
  uint8_t *p = dagr_claim(b, tl + width);
  if (p != NULL) {
    dagr_put_leb(p, tag);
    dagr_put_le(p + tl, bits, width);
  }
}

/** `[tag | 1][byte]` — u8, i8, bool and byte-wide enums have one encoding. */
static inline void dagr_store_packed_byte_field(dagr_builder *b, uint8_t v, uint64_t index) {
  const uint64_t tag = (index << 1) | 1u;
  const size_t tl = dagr_leb_length(tag);
  uint8_t *p = dagr_claim(b, tl + 1);
  if (p != NULL) {
    dagr_put_leb(p, tag);
    p[tl] = v;
  }
}

/** `[tag | 1][LEB length][bytes]` in one claim — utf8 and data fields. */
static inline void dagr_store_packed_blob_field(dagr_builder *b, const void *src, size_t n, uint64_t index) {
  const uint64_t tag = (index << 1) | 1u;
  const size_t tl = dagr_leb_length(tag);
  const size_t ln = dagr_leb_length(n);
  uint8_t *p = dagr_claim(b, tl + ln + n);
  if (p == NULL) return;
  dagr_put_leb(p, tag);
  dagr_put_leb(p + tl, n);
  if (n != 0) memcpy(p + tl + ln, src, n);
}

/** The tag of a field whose payload was just stored. */
static inline void dagr_store_packed_tag(dagr_builder *b, uint64_t index, bool raw) {
  dagr_store_leb(b, (index << 1) | (raw ? 1u : 0u));
}

/** The half bits of `v` when `v` is a NORMAL half (or ±0) exactly — what the float codec's
 * tag 06 stores — and whether it is. */
static inline bool dagr_exact_half(float v, uint16_t *out) {
  const uint32_t b = dagr_f32_bits(v);
  const uint32_t sign = b >> 31;
  const uint32_t exp32 = (b >> 23) & 0xffu;
  const uint32_t mant32 = b & 0x7fffffu;
  if (exp32 == 0xffu) return false;
  if (exp32 == 0) {
    if (mant32 != 0) return false;
    *out = (uint16_t)(sign << 15);
    return true;
  }
  const int exp16 = (int)exp32 - 112;
  if (exp16 < 1 || exp16 > 30) return false;
  if ((mant32 & 0x1fffu) != 0) return false;
  *out = (uint16_t)((sign << 15) | ((uint32_t)exp16 << 10) | (mant32 >> 13));
  return true;
}

/** An encoded packed float: at most `[tag][8 payload bytes]`; `raw` when the fixed-width
 * fallback was used. */
typedef struct dagr_packed_float {
  uint8_t bytes[9];
  size_t len;
  bool raw;
} dagr_packed_float;

/** The one-byte encodings of ±0, ±infinity and NaN of an f32; false when `bits` is none. */
static inline bool dagr_float_special32(uint32_t bits, uint8_t *tag) {
  if (bits == 0) *tag = 0x00;
  else if (bits == 0x80000000u) *tag = 0x01;
  else if ((bits & 0x7fffffffu) > 0x7f800000u) *tag = 0x04;
  else if (bits == 0x7f800000u) *tag = 0x02;
  else if (bits == 0xff800000u) *tag = 0x03;
  else return false;
  return true;
}

static inline void dagr_float_int(dagr_packed_float *out, int64_t iv) {
  out->bytes[0] = 0x05;
  out->len = 1 + dagr_put_leb(out->bytes + 1, dagr_zigzag_encode(iv));
}

/** spec 07 §12, f32: special → `[tag]`; a small integer → `[05][zigzag LEB ≤ 3]`; an exact half
 * → `[06][2]`; else the 4 raw bytes — behind tag 07 when `elem` (array elements are always
 * self-describing; a field says "raw" in its tag instead). */
static inline dagr_packed_float dagr_encode_packed_f32(float v, bool elem) {
  dagr_packed_float out;
  memset(&out, 0, sizeof out);
  const uint32_t bits = dagr_f32_bits(v);
  uint8_t tag;
  if (dagr_float_special32(bits, &tag)) {
    out.bytes[0] = tag;
    out.len = 1;
    return out;
  }
  if (v > -2097152.0f && v < 2097152.0f) { /* |v| < 2^21: the cast is defined */
    const int64_t iv = (int64_t)v;
    if ((float)iv == v && dagr_leb_length(dagr_zigzag_encode(iv)) <= 3) {
      dagr_float_int(&out, iv);
      return out;
    }
  }
  uint16_t h;
  if (dagr_exact_half(v, &h)) {
    out.bytes[0] = 0x06;
    dagr_put_le(out.bytes + 1, h, 2);
    out.len = 3;
    return out;
  }
  size_t at = 0;
  if (elem) out.bytes[at++] = 0x07;
  dagr_put_le(out.bytes + at, bits, 4);
  out.len = at + 4;
  out.raw = true;
  return out;
}

/** spec 07 §12, f64: as f32 with a 7-byte integer, then an exact half (06), an exact float
 * (07), else the 8 raw bytes (behind tag 08 when `elem`). */
static inline dagr_packed_float dagr_encode_packed_f64(double v, bool elem) {
  dagr_packed_float out;
  memset(&out, 0, sizeof out);
  const uint64_t bits = dagr_f64_bits(v);
  int special = -1;
  if (bits == 0) special = 0x00;
  else if (bits == UINT64_C(0x8000000000000000)) special = 0x01;
  else if ((bits & UINT64_C(0x7fffffffffffffff)) > UINT64_C(0x7ff0000000000000)) special = 0x04;
  else if (bits == UINT64_C(0x7ff0000000000000)) special = 0x02;
  else if (bits == UINT64_C(0xfff0000000000000)) special = 0x03;
  if (special >= 0) {
    out.bytes[0] = (uint8_t)special;
    out.len = 1;
    return out;
  }
  if (v > -281474976710656.0 && v < 281474976710656.0) { /* |v| < 2^48 */
    const int64_t iv = (int64_t)v;
    if ((double)iv == v && dagr_leb_length(dagr_zigzag_encode(iv)) <= 7) {
      dagr_float_int(&out, iv);
      return out;
    }
  }
  /* a double outside float's range does not convert (undefined), and is no exact float */
  if (v >= -3.4028234663852886e38 && v <= 3.4028234663852886e38) {
    const float f = (float)v;
    if ((double)f == v) {
      uint16_t h;
      if (dagr_exact_half(f, &h)) {
        out.bytes[0] = 0x06;
        dagr_put_le(out.bytes + 1, h, 2);
        out.len = 3;
        return out;
      }
      out.bytes[0] = 0x07;
      dagr_put_le(out.bytes + 1, dagr_f32_bits(f), 4);
      out.len = 5;
      return out;
    }
  }
  size_t at = 0;
  if (elem) out.bytes[at++] = 0x08;
  dagr_put_le(out.bytes + at, bits, 8);
  out.len = at + 8;
  out.raw = true;
  return out;
}

static inline bool dagr_store_encoded(dagr_builder *b, const dagr_packed_float *f) {
  dagr_store_bytes(b, f->bytes, f->len);
  return f->raw;
}

/** A packed f32 payload; whether the raw fallback was used. */
static inline bool dagr_store_packed_f32(dagr_builder *b, float v, bool elem) {
  const dagr_packed_float f = dagr_encode_packed_f32(v, elem);
  return dagr_store_encoded(b, &f);
}

static inline bool dagr_store_packed_f64(dagr_builder *b, double v, bool elem) {
  const dagr_packed_float f = dagr_encode_packed_f64(v, elem);
  return dagr_store_encoded(b, &f);
}

/** The tag byte a packed f16 / bf16 stores INSTEAD of its two bytes, or 0xff for none. */
static inline uint8_t dagr_half_special(float v) {
  uint8_t tag;
  return dagr_float_special32(dagr_f32_bits(v), &tag) ? tag : (uint8_t)0xff;
}

static inline uint16_t dagr_half_bits(float v, bool bf16) { return bf16 ? dagr_f32_to_bf16(v) : dagr_f32_to_f16(v); }

/** A packed f16 / bf16 SCALAR: a special value as its one tag byte (false), else the two raw
 * bytes (true). */
static inline bool dagr_store_packed_half(dagr_builder *b, float v, bool bf16) {
  const uint8_t special = dagr_half_special(v);
  if (special != 0xff) {
    dagr_store_u8(b, special);
    return false;
  }
  dagr_store_fixed(b, dagr_half_bits(v, bf16), 2);
  return true;
}

/* ── Packed unions (spec 07 §8) ───────────────────────────────────────────────
 * `[LEB (type id << 3) | code][payload]`; the code says how to SKIP the payload: 0 a varint,
 * 1 / 2 / 3 / 4 a fixed 1 / 2 / 4 / 8 bytes, 5 the float codec, 6 a length-prefixed blob. */

static inline uint64_t dagr_width_code(size_t width) { return width == 1 ? 1u : width == 2 ? 2u : width == 4 ? 3u : 4u; }

/** The code of a u16..i64 variant: 0 when its varint is shorter than its width. */
static inline uint64_t dagr_packed_union_int_code(uint64_t bits, size_t width, bool is_signed) {
  return dagr_leb_length(dagr_leb_form(bits, width, is_signed)) < width ? 0u : dagr_width_code(width);
}
static inline uint64_t dagr_store_packed_union_int(dagr_builder *b, uint64_t bits, size_t width, bool is_signed) {
  return dagr_store_packed_int(b, bits, width, is_signed, false) ? dagr_width_code(width) : 0u;
}
static inline uint64_t dagr_packed_union_f32_code(float v) { return dagr_encode_packed_f32(v, false).raw ? 3u : 5u; }
static inline uint64_t dagr_store_packed_union_f32(dagr_builder *b, float v) {
  return dagr_store_packed_f32(b, v, false) ? 3u : 5u;
}
static inline uint64_t dagr_packed_union_f64_code(double v) { return dagr_encode_packed_f64(v, false).raw ? 4u : 5u; }
static inline uint64_t dagr_store_packed_union_f64(dagr_builder *b, double v) {
  return dagr_store_packed_f64(b, v, false) ? 4u : 5u;
}

/* ── Packed arrays (spec 04 §5, spec 07) ──────────────────────────────────────
 * `[LEB block length][count word][bitsets][elements]`, the block length counting everything
 * after itself; an array with optionals stores a nil bitset (bit i set = element i absent)
 * and only the PRESENT elements. Element arrays are passed as `(elems, present, n)`:
 * `present` NULL for a plain array. Where a bitset depends on the elements, they are
 * measured first and the body written forward into ONE exact claim — an over-claim would
 * make a record that fits an exact-size buffer fail. */

static inline void dagr_pk_finish_block(dagr_builder *b, size_t before, uint64_t count_word) {
  dagr_store_leb(b, count_word);
  dagr_store_leb(b, b->cursor - before);
}

static inline bool dagr_is_present(const bool *present, size_t i) { return present == NULL || present[i]; }

/** The nil bitset of an array with optionals. */
static inline void dagr_store_nil_bits(dagr_builder *b, const bool *present, size_t n) {
  const size_t nb = (n + 7) >> 3;
  if (nb == 0) return;
  uint8_t *p = dagr_claim(b, nb);
  if (p == NULL) return;
  memset(p, 0, nb);
  for (size_t i = 0; i < n; i++) {
    if (!present[i]) dagr_set_bit(p, i);
  }
}

/** Element `i` of a caller's integer array of `width`-byte elements, as its two's complement bits. */
static inline uint64_t dagr_elem_bits(const void *elems, size_t i, size_t width) {
  uint64_t v = 0;
  memcpy(&v, (const uint8_t *)elems + i * width, width);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  v >>= 8 * (8 - width);
#endif
  return v;
}

/** `[u16..i64]` / `[u16?..i64?]`: `[(count << 2) | tag][nil bitset][encoding bitset if tag 2]
 * [elements]` — tag 0 every element a varint, 1 every element fixed-width, 2 mixed (bit i set
 * = element i fixed). `raw` (spec 39) skips the probe: tag 1. */
static inline void dagr_store_pk_int_array(dagr_builder *b, const void *elems, const bool *present, size_t n, size_t width,
                                           bool is_signed, bool raw) {
  const size_t before = b->cursor;
  size_t total = 0, raw_count = 0, count = 0;
  for (size_t i = 0; i < n; i++) {
    if (!dagr_is_present(present, i)) continue;
    count++;
    const size_t ll = dagr_leb_length(dagr_leb_form(dagr_elem_bits(elems, i, width), width, is_signed));
    if (!raw && ll < width) {
      total += ll;
    } else {
      total += width;
      raw_count++;
    }
  }
  const uint64_t tag = raw ? 1u : (raw_count == count && count > 0) ? 1u : raw_count > 0 ? 2u : 0u;
  const size_t nb = present != NULL ? (n + 7) >> 3 : 0;
  const size_t eb = tag == 2 ? (n + 7) >> 3 : 0;
  if (nb + eb + total != 0) {
    uint8_t *p = dagr_claim(b, nb + eb + total);
    if (p != NULL) {
      memset(p, 0, nb + eb);
      uint8_t *enc = p + nb;
      uint8_t *out = enc + eb;
      for (size_t i = 0; i < n; i++) {
        if (!dagr_is_present(present, i)) {
          dagr_set_bit(p, i);
          continue;
        }
        const uint64_t bits = dagr_elem_bits(elems, i, width);
        const uint64_t lv = dagr_leb_form(bits, width, is_signed);
        if (tag != 1 && dagr_leb_length(lv) < width) {
          out += dagr_put_leb(out, lv);
        } else {
          dagr_put_le(out, bits, width);
          out += width;
          if (eb != 0) dagr_set_bit(enc, i);
        }
      }
    }
  }
  dagr_pk_finish_block(b, before, ((uint64_t)n << 2) | tag);
}

/** `[u8]` / `[i8]`: `[count][bytes]`; `[u8?]` / `[i8?]`: `[count][nil bitset][present bytes]`. */
static inline void dagr_store_pk_byte_array(dagr_builder *b, const void *elems, const bool *present, size_t n) {
  const uint8_t *bytes = (const uint8_t *)elems;
  const size_t before = b->cursor;
  size_t count = 0;
  for (size_t i = 0; i < n; i++) count += dagr_is_present(present, i) ? 1u : 0u;
  if (count != 0) {
    uint8_t *p = dagr_claim(b, count);
    if (p != NULL) {
      for (size_t i = 0; i < n; i++) {
        if (dagr_is_present(present, i)) *p++ = bytes[i];
      }
    }
  }
  if (present != NULL) dagr_store_nil_bits(b, present, n);
  dagr_pk_finish_block(b, before, n);
}

/** `[bool]`: `[count][bitset]`; `[bool?]`: `[count][nil bitset][the present values' bits]`. */
static inline void dagr_store_pk_bool_array(dagr_builder *b, const bool *elems, const bool *present, size_t n) {
  const size_t before = b->cursor;
  size_t count = 0;
  for (size_t i = 0; i < n; i++) count += dagr_is_present(present, i) ? 1u : 0u;
  const size_t vb = (count + 7) >> 3;
  if (vb != 0) {
    uint8_t *p = dagr_claim(b, vb);
    if (p != NULL) {
      memset(p, 0, vb);
      size_t at = 0;
      for (size_t i = 0; i < n; i++) {
        if (!dagr_is_present(present, i)) continue;
        if (elems[i]) dagr_set_bit(p, at);
        at++;
      }
    }
  }
  if (present != NULL) dagr_store_nil_bits(b, present, n);
  dagr_pk_finish_block(b, before, n);
}

/** `[f16]` / `[bf16]`: `[count][encoding bitset][elements]` — a special value its one tag byte,
 * anything else its two raw bytes with the bit set. `[f16?]` / `[bf16?]`: `[count][nil
 * bitset][two raw bytes per present element]`. */
static inline void dagr_store_pk_half_array(dagr_builder *b, const float *elems, const bool *present, size_t n, bool bf16) {
  const size_t before = b->cursor;
  if (present != NULL) {
    for (size_t i = n; i-- > 0;) {
      if (present[i]) dagr_store_fixed(b, dagr_half_bits(elems[i], bf16), 2);
    }
    dagr_store_nil_bits(b, present, n);
    dagr_pk_finish_block(b, before, n);
    return;
  }
  const size_t eb = (n + 7) >> 3;
  size_t total = 0;
  for (size_t i = 0; i < n; i++) total += dagr_half_special(elems[i]) != 0xff ? 1u : 2u;
  if (eb + total != 0) {
    uint8_t *p = dagr_claim(b, eb + total);
    if (p != NULL) {
      memset(p, 0, eb);
      uint8_t *out = p + eb;
      for (size_t i = 0; i < n; i++) {
        const uint8_t special = dagr_half_special(elems[i]);
        if (special != 0xff) {
          *out++ = special;
        } else {
          dagr_put_le(out, dagr_half_bits(elems[i], bf16), 2);
          out += 2;
          dagr_set_bit(p, i);
        }
      }
    }
  }
  dagr_pk_finish_block(b, before, n);
}

/** `[f32]` / `[f64]` (width 4 / 8; `elems` of that width): `[(count << 2) | mode][nil bitset?]
 * [elements]` — mode 0 each element in the self-describing codec, mode 1 (`raw`) native. */
static inline void dagr_store_pk_float_array(dagr_builder *b, const void *elems, const bool *present, size_t n, size_t width,
                                             bool raw) {
  const size_t before = b->cursor;
  for (size_t i = n; i-- > 0;) {
    if (!dagr_is_present(present, i)) continue;
    if (width == 4) {
      float v;
      memcpy(&v, (const uint8_t *)elems + i * 4, 4);
      if (raw) dagr_store_fixed(b, dagr_f32_bits(v), 4);
      else dagr_store_packed_f32(b, v, true);
    } else {
      double v;
      memcpy(&v, (const uint8_t *)elems + i * 8, 8);
      if (raw) dagr_store_fixed(b, dagr_f64_bits(v), 8);
      else dagr_store_packed_f64(b, v, true);
    }
  }
  if (present != NULL) dagr_store_nil_bits(b, present, n);
  dagr_pk_finish_block(b, before, ((uint64_t)n << 2) | (raw ? 1u : 0u));
}

/** A sub-byte enum array (`bits` 1, 2 or 4; elements of `width` bytes): `[count][nil bitset?]
 * [the present values' bits, low first]`. */
static inline void dagr_store_pk_bit_enum_array(dagr_builder *b, const void *elems, const bool *present, size_t n,
                                                size_t width, unsigned bits) {
  const size_t before = b->cursor;
  size_t count = 0;
  for (size_t i = 0; i < n; i++) count += dagr_is_present(present, i) ? 1u : 0u;
  const size_t nb = (count * bits + 7) / 8;
  if (nb != 0) {
    uint8_t *p = dagr_claim(b, nb);
    if (p != NULL) {
      memset(p, 0, nb);
      const size_t per_byte = 8 / bits;
      const uint64_t mask = (UINT64_C(1) << bits) - 1u;
      size_t at = 0;
      for (size_t i = 0; i < n; i++) {
        if (!dagr_is_present(present, i)) continue;
        const uint64_t v = dagr_elem_bits(elems, i, width) & mask;
        p[at / per_byte] = (uint8_t)(p[at / per_byte] | (v << ((at % per_byte) * bits)));
        at++;
      }
    }
  }
  if (present != NULL) dagr_store_nil_bits(b, present, n);
  dagr_pk_finish_block(b, before, n);
}

/** An enum array of a byte or more per element: `[count][nil bitset?][LEB per present element]`. */
static inline void dagr_store_pk_leb_enum_array(dagr_builder *b, const void *elems, const bool *present, size_t n,
                                                size_t width) {
  const size_t before = b->cursor;
  for (size_t i = n; i-- > 0;) {
    if (dagr_is_present(present, i)) dagr_store_leb(b, dagr_elem_bits(elems, i, width));
  }
  if (present != NULL) dagr_store_nil_bits(b, present, n);
  dagr_pk_finish_block(b, before, n);
}

/** `[utf8]` / `[utf8?]`: `[count][nil bitset?][blob per present element]`. */
static inline void dagr_store_pk_text_array(dagr_builder *b, const dagr_str *elems, const bool *present, size_t n) {
  const size_t before = b->cursor;
  for (size_t i = n; i-- > 0;) {
    if (dagr_is_present(present, i)) dagr_store_text(b, elems[i]);
  }
  if (present != NULL) dagr_store_nil_bits(b, present, n);
  dagr_pk_finish_block(b, before, n);
}

/** `[data]` / `[data?]`. */
static inline void dagr_store_pk_data_array(dagr_builder *b, const dagr_bytes *elems, const bool *present, size_t n) {
  const size_t before = b->cursor;
  for (size_t i = n; i-- > 0;) {
    if (dagr_is_present(present, i)) dagr_store_data(b, elems[i]);
  }
  if (present != NULL) dagr_store_nil_bits(b, present, n);
  dagr_pk_finish_block(b, before, n);
}

/* ── Graph framing (spec 06, spec 12 §4 / §14, spec 42) ──────────────────────── */

/** Sets the number of bytes that will PRECEDE the finished buffer in its envelope (spec 12 §14):
 * finish padding then puts aligned arrays on their boundary in the envelope's frame. Kept across
 * `dagr_builder_reset`; 0 is the plain buffer. */
static inline void dagr_builder_set_alignment_offset(dagr_builder *b, size_t offset) { b->alignment_offset = offset; }

/** The zero bytes that make `alignment offset + finished length` a multiple of `max_n` — the
 * graph's largest aligned(N) — given the framing word that follows them. `root` is the cursor
 * right after the root was stored. The framing word's length depends on the pad (it encodes a
 * distance that includes it), hence the search; it runs over [0, 2 · max_n), which crosses at
 * most one step of the framing length, so a pad always exists (over [0, max_n) the range can
 * straddle the step and hold none — spec 42 §1). The smallest pad is taken. */
static inline void dagr_store_finish_alignment_padding(dagr_builder *b, size_t root, size_t max_n) {
  for (size_t pad = 0; pad < 2 * max_n; pad++) {
    const size_t after = b->cursor + pad;
    const size_t framing = dagr_leb_length((uint64_t)(after - root) << 2);
    if ((b->alignment_offset + after + framing) % max_n == 0) {
      dagr_store_zeros(b, pad);
      return;
    }
  }
}

/** Ends a graph buffer whose root was just stored: alignment padding when the graph declares
 * aligned arrays (`max_align` > 1), then the framing word, LEB(distance to the root << 2). */
static inline void dagr_store_graph_framing(dagr_builder *b, size_t max_align) {
  const size_t root = b->cursor;
  if (max_align > 1) dagr_store_finish_alignment_padding(b, root, max_align);
  dagr_store_leb(b, (uint64_t)(b->cursor - root) << 2);
}

/** `dagr_store_graph_framing` for a root stored at offset `root`: a regular root's offset is its
 * vtable marker, which is not the last thing its store wrote. */
static inline void dagr_store_graph_framing_at(dagr_builder *b, size_t root, size_t max_align) {
  if (max_align > 1) dagr_store_finish_alignment_padding(b, root, max_align);
  dagr_store_leb(b, (uint64_t)(b->cursor - root) << 2);
}

/* ── A spec-15 header in front of a graph ─────────────────────────────────────────────────────
 * The body is stored first; then the header node's packed block `[LEB fields][fields]` (its
 * `_put`); `dagr_store_header_frame` turns that into the header frame
 * `[framing word][LEB content][fields][pad zeros][body]`. With aligned arrays the pad (`q` zero
 * bytes, stored BEFORE the block) inflates the header so the buffer length stays a multiple of
 * their alignment (spec 15 §6) — it depends on the fields' length, so such a header is stored
 * twice: once to measure (`dagr_header_fields_len`), then, rewound, behind its pad. */

/** Moves the cursor back to `cursor` (a position this builder reached): what was stored after it
 * is discarded. */
static inline void dagr_builder_rewind(dagr_builder *b, size_t cursor) {
  if (b->status == dagr_ok && cursor <= b->cursor) b->cursor = cursor;
}

/** The leading LEB of what was stored since `since` — a packed block's length — and its encoded
 * length in `*leb_len` (0 when no well-formed LEB is there). */
static inline uint64_t dagr_builder_front_leb(const dagr_builder *b, size_t since, size_t *leb_len) {
  *leb_len = 0;
  if (b->status != dagr_ok || since > b->cursor) return 0;
  const size_t avail = b->cursor - since;
  const uint8_t *p = b->data + (b->cap - b->cursor);
  uint64_t v = 0;
  for (size_t i = 0; i < avail && i < 10; i++) {
    v |= (uint64_t)(p[i] & 0x7fu) << (7 * i);
    if ((p[i] & 0x80u) == 0) {
      *leb_len = i + 1;
      return v;
    }
  }
  return 0;
}

/** The fields' length of the header block stored since `body` (0 when there is none). */
static inline size_t dagr_header_fields_len(const dagr_builder *b, size_t body) {
  size_t n = 0;
  const uint64_t v = dagr_builder_front_leb(b, body, &n);
  return n == 0 ? 0 : (size_t)v;
}

/** The zero bytes between a header's fields and the body that keep `max_n`-aligned arrays on
 * their boundary: the framing word encodes a distance that includes them, hence the search
 * (as every other writer does it; 0 when `max_n` <= 1). */
static inline size_t dagr_header_padding(size_t fields_len, size_t root_offset, size_t body, size_t max_n) {
  size_t q = 0;
  if (max_n > 1) {
    for (;; q++) {
      const size_t c = fields_len + q;
      const size_t span = dagr_leb_length(c) + c;
      const uint64_t stored = ((uint64_t)(root_offset + span) << 2) | 1u;
      if ((dagr_leb_length(stored) + span + body) % max_n == 0 || q > 4 * max_n) break;
    }
  }
  return q;
}

/** Ends a buffer behind a spec-15 header: since `body` the builder holds `q` zero bytes and then
 * the header's packed block `[LEB fields][fields]`. Its LEB becomes the content length (fields +
 * pad), and the framing word — LEB((root_offset + header span) << 2 | 1), `root_offset` the
 * header-free root offset — goes in front. `dagr_invalid_value` when the block is not one. */
static inline void dagr_store_header_frame(dagr_builder *b, size_t body, size_t q, size_t root_offset) {
  if (b->status != dagr_ok) return;
  size_t n = 0;
  const uint64_t fields = dagr_builder_front_leb(b, body, &n);
  if (n == 0 || fields + n + q != b->cursor - body) {
    dagr_builder_fail(b, dagr_invalid_value);
    return;
  }
  b->cursor -= n;
  const size_t c = (size_t)fields + q;
  dagr_store_leb(b, c);
  dagr_store_leb(b, ((uint64_t)(root_offset + dagr_leb_length(c) + c) << 2) | 1u);
}

#endif /* DAGR_WRITER_H */
