/* dagr/packed.h — the arrays of a packed node (spec 04 §5, spec 07), read forward
 * (spec/44 §12.1). A transliteration of the C++ target's dagr/packed.hpp ranges.
 *
 * A packed array is a run of SELF-SIZING elements, with no offset table: element i is
 * reached by walking the i before it. So there is no `at(i)` — an iterator: one struct for
 * every encoding, an `open` per encoding and a `next` per value domain, which returns false
 * after `count` elements. A cursor that cannot advance parks at SIZE_MAX, where every read
 * yields zero; iteration still ends after `count` steps.
 *
 *     dagr_pk_array it = log_ClickAccessor_ids(&click);       // opened by the getter
 *     uint64_t v;
 *     while (dagr_pk_next_uint(&it, &v, NULL)) { … }
 *
 * `present` (may be NULL) reports a nil element of an array with optionals; a nil element
 * yields zero. Totality (spec/41 §5): `open` clamps the element count against the buffer
 * (every element occupies at least one bit), every read is a checked primitive.
 *
 * Core tier: no allocation. */
#ifndef DAGR_PACKED_H
#define DAGR_PACKED_H

#include "reader.h"

typedef struct dagr_pk_array {
  dagr_bytes buf;
  size_t count;    /* elements (clamped) */
  size_t i;        /* the next element */
  size_t pos;      /* the next element's bytes; for a union array, the next header */
  size_t payload;  /* a union array's next payload; the next present element's bit index */
  size_t enc;      /* the encoding bitset (mode 2) or the bits of a bit-packed array */
  size_t nil;      /* the nil bitset, SIZE_MAX when the array has none */
  unsigned mode;   /* 0 every element compact, 1 every element raw, 2 per the encoding bitset */
  unsigned width;  /* an element's raw width in bytes; bits per element of a bit-packed array */
} dagr_pk_array;

/* ── Opening ─────────────────────────────────────────────────────────────────── */

static inline dagr_pk_array dagr_pk_empty(dagr_bytes buf) {
  dagr_pk_array a;
  a.buf = buf;
  a.count = 0;
  a.i = 0;
  a.pos = SIZE_MAX;
  a.payload = 0;
  a.enc = SIZE_MAX;
  a.nil = SIZE_MAX;
  a.mode = 0;
  a.width = 1;
  return a;
}

/** A count read from a header, clamped: each element occupies at least `min_bits` bits of
 * what follows `base`. A count that cannot fit is an empty array. */
static inline size_t dagr_pk_count(dagr_bytes b, size_t base, uint64_t count, unsigned min_bits) {
  const size_t rem = dagr_remaining(b, base);
  if (min_bits >= 8) return count <= rem ? (size_t)count : 0;
  return count / 8 <= rem && (count + 7) / 8 <= rem ? (size_t)count : 0;
}

static inline size_t dagr_pk_step(size_t p, size_t n) { return p == SIZE_MAX ? SIZE_MAX : p + n; }

/** `[u16]` … `[i64]` (and wide-enum fields' arrays of the int form): `[LEB (count << 2) |
 * tag]`, then by tag — 0 every element a varint; 1 every element raw; 2 an encoding bitset,
 * then each element raw (bit set) or a varint. */
static inline dagr_pk_array dagr_pk_ints_open(dagr_bytes buf, size_t c, unsigned width) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const dagr_varint h = dagr_read_leb(buf, c);
  if (h.len == 0) return a;
  a.width = width;
  a.mode = (unsigned)(h.value & 3u);
  a.enc = c + h.len;
  a.count = dagr_pk_count(buf, a.enc, h.value >> 2, 8);
  a.pos = a.enc + (a.mode == 2 ? (a.count + 7) / 8 : 0);
  return a;
}

/** `[u8]` / `[i8]`: `[LEB count][bytes]`. */
static inline dagr_pk_array dagr_pk_bytes_open(dagr_bytes buf, size_t c) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const dagr_varint h = dagr_read_leb(buf, c);
  if (h.len == 0) return a;
  a.mode = 1;
  a.pos = c + h.len;
  a.count = dagr_pk_count(buf, a.pos, h.value, 8);
  return a;
}

/** `[f32]` / `[f64]`: `[LEB (count << 2) | mode]`; mode 1 every element raw, otherwise each a
 * self-describing packed float. */
static inline dagr_pk_array dagr_pk_floats_open(dagr_bytes buf, size_t c, unsigned width) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const dagr_varint h = dagr_read_leb(buf, c);
  if (h.len == 0) return a;
  a.width = width;
  a.mode = (h.value & 3u) == 1 ? 1u : 0u;
  a.pos = c + h.len;
  a.count = dagr_pk_count(buf, a.pos, h.value >> 2, 8);
  return a;
}

/** `[f16]` / `[bf16]`: `[LEB count][encoding bitset]`, then each element two raw bytes (bit
 * set) or a one-byte special value. */
static inline dagr_pk_array dagr_pk_halves_open(dagr_bytes buf, size_t c) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const dagr_varint h = dagr_read_leb(buf, c);
  if (h.len == 0) return a;
  a.width = 2;
  a.mode = 2;
  a.enc = c + h.len;
  a.count = dagr_pk_count(buf, a.enc, h.value, 8);
  a.pos = a.enc + (a.count + 7) / 8;
  return a;
}

/** `[bool]` (bits 1) and sub-byte enum arrays (bits 1, 2 or 4): `[LEB count][packed bits]`. */
static inline dagr_pk_array dagr_pk_bits_open(dagr_bytes buf, size_t c, unsigned bits) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const dagr_varint h = dagr_read_leb(buf, c);
  if (h.len == 0) return a;
  const size_t base = c + h.len;
  const size_t rem = dagr_remaining(buf, base);
  const unsigned bpe = bits == 0 ? 1u : bits;
  /* count * bpe bits must fit in rem bytes; compared without multiplying the hostile count */
  if (h.value / 8 > rem / bpe) return a;
  const size_t count = (size_t)h.value;
  if ((count * bpe + 7) / 8 > rem) return a;
  a.width = bpe;
  a.enc = base;
  a.count = count;
  return a;
}

/** `[utf8]`, `[data]`, `[Node]`: `[LEB count]`, then each element a length-prefixed blob. Also
 * a wide enum array — `[LEB count]`, then a varint each (`dagr_pk_next_uint`). */
static inline dagr_pk_array dagr_pk_blobs_open(dagr_bytes buf, size_t c) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const dagr_varint h = dagr_read_leb(buf, c);
  if (h.len == 0) return a;
  a.pos = c + h.len;
  a.count = dagr_pk_count(buf, a.pos, h.value, 8);
  return a;
}

/** Where a union array's payloads start: past `present` header varints from `headers`. */
static inline size_t dagr_pk_union_payloads(dagr_bytes b, size_t headers, size_t present) {
  size_t p = headers;
  for (size_t k = 0; k < present; k++) {
    p = dagr_leb_end(b, p);
    if (p == SIZE_MAX) return SIZE_MAX;
  }
  return p;
}

/** `[Union]`: `[LEB count][headers][payloads]`. */
static inline dagr_pk_array dagr_pk_unions_open(dagr_bytes buf, size_t c) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const dagr_varint h = dagr_read_leb(buf, c);
  if (h.len == 0) return a;
  a.pos = c + h.len;
  a.count = dagr_pk_count(buf, a.pos, h.value, 8);
  a.payload = dagr_pk_union_payloads(buf, a.pos, a.count);
  return a;
}

/* Arrays with optionals: `[header][nil bitset]`, then the PRESENT elements only. A nil element
 * is a set bit and nothing else. */

/** The header of an array with optionals: `tagged` headers are `(count << 2) | mode`. The nil
 * bitset is at `a.nil`; returns the first byte past it (SIZE_MAX: an empty array). */
static inline size_t dagr_pk_opt_header(dagr_pk_array *a, size_t c, bool tagged) {
  const dagr_varint h = dagr_read_leb(a->buf, c);
  if (h.len == 0) return SIZE_MAX;
  const size_t nil = c + h.len;
  const size_t count = dagr_pk_count(a->buf, nil, tagged ? h.value >> 2 : h.value, 1);
  if (count == 0) return SIZE_MAX;
  a->count = count;
  a->mode = tagged ? (unsigned)(h.value & 3u) : 0u;
  a->nil = nil;
  return nil + (count + 7) / 8;
}

/** `[u16?]` … `[i64?]`: mode 1 every present element raw; mode 2 an encoding bitset (indexed
 * by ELEMENT) follows the nil bitset; otherwise every present element a varint. */
static inline dagr_pk_array dagr_pk_ints_opt_open(dagr_bytes buf, size_t c, unsigned width) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const size_t after = dagr_pk_opt_header(&a, c, true);
  if (after == SIZE_MAX) return a;
  a.width = width;
  a.enc = after;
  a.pos = after + (a.mode == 2 ? (a.count + 7) / 8 : 0);
  return a;
}

/** `[u8?]`, `[i8?]` (width 1) and `[f16?]`, `[bf16?]` (width 2): the present elements at their
 * fixed width. */
static inline dagr_pk_array dagr_pk_fixed_opt_open(dagr_bytes buf, size_t c, unsigned width) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const size_t after = dagr_pk_opt_header(&a, c, false);
  if (after == SIZE_MAX) return a;
  a.width = width;
  a.mode = 1;
  a.pos = after;
  return a;
}

/** `[f32?]` / `[f64?]`: mode 1 present elements raw; otherwise each a packed float. */
static inline dagr_pk_array dagr_pk_floats_opt_open(dagr_bytes buf, size_t c, unsigned width) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const size_t after = dagr_pk_opt_header(&a, c, true);
  if (after == SIZE_MAX) return a;
  a.width = width;
  a.mode = a.mode == 1 ? 1u : 0u;
  a.pos = after;
  return a;
}

/** `[bool?]` (bits 1) and sub-byte enum arrays with optionals: `bits` bits per PRESENT element. */
static inline dagr_pk_array dagr_pk_bits_opt_open(dagr_bytes buf, size_t c, unsigned bits) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const size_t after = dagr_pk_opt_header(&a, c, false);
  if (after == SIZE_MAX) return a;
  a.width = bits == 0 ? 1u : bits;
  a.enc = after;
  return a;
}

/** `[utf8?]`, `[data?]`, `[Node?]`, and wide enum arrays with optionals (a varint each). */
static inline dagr_pk_array dagr_pk_blobs_opt_open(dagr_bytes buf, size_t c) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const size_t after = dagr_pk_opt_header(&a, c, false);
  if (after == SIZE_MAX) return a;
  a.pos = after;
  return a;
}

/** `[Union?]`: `[LEB count][nil bitset][LEB header section size][headers][payloads]`. */
static inline dagr_pk_array dagr_pk_unions_opt_open(dagr_bytes buf, size_t c) {
  dagr_pk_array a = dagr_pk_empty(buf);
  const size_t after = dagr_pk_opt_header(&a, c, false);
  if (after == SIZE_MAX) return a;
  a.pos = dagr_leb_end(buf, after);
  size_t present = 0;
  for (size_t k = 0; k < a.count; k++) present += dagr_bit_at(buf, a.nil, k) ? 0u : 1u;
  a.payload = dagr_pk_union_payloads(buf, a.pos, present);
  return a;
}

/* ── Iterating ───────────────────────────────────────────────────────────────── */

/** Starts element `a->i`: false at the end; true and `*present = false` for a nil element
 * (which the caller then skips without moving the cursor). */
static inline bool dagr_pk_begin(dagr_pk_array *a, bool *present, bool *nil) {
  if (a->i >= a->count) return false;
  *nil = a->nil != SIZE_MAX && dagr_bit_at(a->buf, a->nil, a->i);
  if (present != NULL) *present = !*nil;
  return true;
}

static inline bool dagr_pk_raw(const dagr_pk_array *a) {
  return a->mode == 1 || (a->mode == 2 && dagr_bit_at(a->buf, a->enc, a->i));
}

/** The next element of an unsigned integer array (`[u8]` … `[u64]`, their optional forms, wide
 * enum arrays). */
static inline bool dagr_pk_next_uint(dagr_pk_array *a, uint64_t *v, bool *present) {
  bool nil;
  if (!dagr_pk_begin(a, present, &nil)) return false;
  *v = 0;
  if (!nil) {
    if (dagr_pk_raw(a)) {
      *v = dagr_read_uint_le(a->buf, a->pos, a->width);
      a->pos = dagr_pk_step(a->pos, a->width);
    } else {
      *v = dagr_read_leb(a->buf, a->pos).value;
      a->pos = dagr_leb_end(a->buf, a->pos);
    }
  }
  a->i++;
  return true;
}

/** The next element of a signed integer array: raw two's complement, or a zigzag varint. */
static inline bool dagr_pk_next_int(dagr_pk_array *a, int64_t *v, bool *present) {
  bool nil;
  if (!dagr_pk_begin(a, present, &nil)) return false;
  *v = 0;
  if (!nil) {
    if (dagr_pk_raw(a)) {
      *v = dagr_sign_extend(dagr_read_uint_le(a->buf, a->pos, a->width), a->width);
      a->pos = dagr_pk_step(a->pos, a->width);
    } else {
      *v = dagr_zigzag_decode(dagr_read_leb(a->buf, a->pos).value);
      a->pos = dagr_leb_end(a->buf, a->pos);
    }
  }
  a->i++;
  return true;
}

/** The next element of an `[f32]` / `[f64]` array (an f32 widened exactly). */
static inline bool dagr_pk_next_float(dagr_pk_array *a, double *v, bool *present) {
  bool nil;
  if (!dagr_pk_begin(a, present, &nil)) return false;
  *v = 0.0;
  if (!nil) {
    if (a->mode == 1) {
      *v = a->width == 4 ? (double)dagr_read_f32(a->buf, a->pos) : dagr_read_f64(a->buf, a->pos);
      a->pos = dagr_pk_step(a->pos, a->width);
    } else {
      const dagr_float_read r = dagr_decode_packed_float(a->buf, a->pos, a->width == 4);
      *v = r.value;
      a->pos = r.len != 0 ? dagr_pk_step(a->pos, r.len) : SIZE_MAX;
    }
  }
  a->i++;
  return true;
}

/** The next element of an `[f16]` / `[bf16]` array (`bf16` says which). */
static inline bool dagr_pk_next_half(dagr_pk_array *a, float *v, bool *present, bool bf16) {
  bool nil;
  if (!dagr_pk_begin(a, present, &nil)) return false;
  *v = 0.0f;
  if (!nil) {
    if (dagr_pk_raw(a)) {
      *v = bf16 ? dagr_read_bf16(a->buf, a->pos) : dagr_read_f16(a->buf, a->pos);
      a->pos = dagr_pk_step(a->pos, 2);
    } else {
      *v = dagr_decode_packed_half(a->buf, a->pos);
      a->pos = dagr_pk_step(a->pos, 1);
    }
  }
  a->i++;
  return true;
}

/** The next element of a bit-packed array: a bool (`[bool]`, 1 bit) or a sub-byte enum. */
static inline bool dagr_pk_next_bits(dagr_pk_array *a, unsigned *v, bool *present) {
  bool nil;
  if (!dagr_pk_begin(a, present, &nil)) return false;
  *v = 0;
  if (!nil) {
    *v = dagr_packed_bits(a->buf, a->enc, a->payload, a->width);
    a->payload++;
  }
  a->i++;
  return true;
}

/** The next element of a blob array: the POSITION of its `[LEB size][bytes]` (a utf8 or data
 * element: `dagr_read_text` / `dagr_read_blob` there; a node element: its accessor there).
 * A nil element yields SIZE_MAX. */
static inline bool dagr_pk_next_blob(dagr_pk_array *a, size_t *at, bool *present) {
  bool nil;
  if (!dagr_pk_begin(a, present, &nil)) return false;
  *at = SIZE_MAX;
  if (!nil) {
    *at = a->pos;
    a->pos = dagr_skip_blob(a->buf, a->pos);
  }
  a->i++;
  return true;
}

/** The next element of a union array: its header (payload position, type id, code). A nil
 * element yields an unreadable header (payload SIZE_MAX). */
static inline bool dagr_pk_next_union(dagr_pk_array *a, dagr_pk_union_header *h, bool *present) {
  bool nil;
  if (!dagr_pk_begin(a, present, &nil)) return false;
  h->payload = SIZE_MAX;
  h->tag = 0;
  h->code = 0;
  if (!nil) {
    const dagr_varint r = dagr_read_leb(a->buf, a->pos);
    if (r.len == 0) {
      a->pos = SIZE_MAX;
      a->payload = SIZE_MAX;
    } else {
      h->payload = a->payload;
      h->tag = (uint32_t)((r.value >> 3) & 0xffu);
      h->code = (uint32_t)(r.value & 7u);
      a->pos += r.len;
      const size_t len = dagr_packed_union_payload_bytes(a->buf, a->payload, h->code);
      a->payload = len != 0 ? dagr_pk_step(a->payload, len) : SIZE_MAX;
    }
  }
  a->i++;
  return true;
}

#endif /* DAGR_PACKED_H */
