/* dagr/arrays.h — the arrays of a regular or frozen node (spec 04, spec 05), read by index
 * (spec/44 §12.2). A transliteration of the C++ target's dagr/arrays.hpp ranges.
 *
 * Every array a regular or frozen node holds indexes in O(1) — a fixed element stride, a bit
 * stride, or a pointer table — so a getter returns a `dagr_array` and elements are read by
 * index. ONE struct serves every encoding: it is opened per encoding (`dagr_array_*_open`, which
 * the generated getter calls) and read per value domain:
 *
 *     dagr_array xs = book_PersonAccessor_scores(&person);
 *     for (size_t i = 0; i < dagr_array_len(&xs); i++) total += dagr_array_u32(&xs, i);
 *
 * `dagr_array_has(a, i)` is false past the end and for a nil element of an array with optionals;
 * every read of such an element yields zero / empty / SIZE_MAX. Enum and node elements have
 * generated typed reads (`P_E_array_at`, `P_NAccessor_array_at`) over `dagr_array_uint` and
 * `dagr_array_node`. Union arrays are `dagr_union_array` (below).
 *
 * Totality (spec/41 §5): `open` clamps the element count against the buffer, every element read
 * is a checked primitive, and an index at or past the count reads nothing.
 *
 * Core tier: no allocation. */
#ifndef DAGR_ARRAYS_H
#define DAGR_ARRAYS_H

#include "reader.h"

typedef struct dagr_array {
  dagr_bytes buf;
  size_t base;    /* the first element; a pointer table's first slot */
  size_t nil;     /* the nil bitset of an array with optionals; SIZE_MAX: none */
  size_t data;    /* a pointer table's data base (slot values are offsets from it, plus one) */
  size_t count;   /* elements (clamped) */
  size_t width;   /* element width in bytes; bits per element of a bit-packed array; slot width */
  bool table;     /* a pointer table: a zero slot is a nil element */
} dagr_array;

/* ── Opening ─────────────────────────────────────────────────────────────────── */

/** The empty array (what every malformed header opens as). */
static inline dagr_array dagr_array_empty(dagr_bytes buf) {
  dagr_array a;
  a.buf = buf;
  a.base = SIZE_MAX;
  a.nil = SIZE_MAX;
  a.data = SIZE_MAX;
  a.count = 0;
  a.width = 1;
  a.table = false;
  return a;
}

/** `count` elements of `width` bytes at `base` — the caller has bounded `count` (a default over
 * its own constant bytes). */
static inline dagr_array dagr_array_of(dagr_bytes buf, size_t base, size_t count, size_t width) {
  dagr_array a = dagr_array_empty(buf);
  a.base = base;
  a.count = count;
  a.width = width;
  return a;
}

/** Fixed-width elements `[LEB count][elements]` at `ps` (numerics, byte-aligned enums). */
static inline dagr_array dagr_array_fixed_open(dagr_bytes buf, size_t ps, size_t width) {
  dagr_array a = dagr_array_empty(buf);
  a.width = width;
  const dagr_varint c = dagr_read_leb(buf, ps);
  if (c.len == 0) return a;
  const size_t base = ps + c.len;
  const size_t w = width == 0 ? 1 : width;
  if (c.value > dagr_remaining(buf, base) / w) return a;
  a.base = base;
  a.count = (size_t)c.value;
  return a;
}

/** Bit-packed elements `[LEB count][ceil(count · bits / 8) bytes]` at `ps`: bool arrays (bits 1),
 * sub-byte enum arrays (bits 1, 2 or 4). */
static inline dagr_array dagr_array_bits_open(dagr_bytes buf, size_t ps, unsigned bits) {
  dagr_array a = dagr_array_empty(buf);
  a.width = bits;
  const dagr_varint c = dagr_read_leb(buf, ps);
  if (c.len == 0) return a;
  const size_t base = ps + c.len;
  const size_t bpe = bits == 0 ? 1 : bits;
  const size_t rem = dagr_remaining(buf, base);
  /* count · bpe bits must fit in rem bytes; compare without multiplying the hostile count */
  if (c.value / 8 > rem / bpe) return a;
  const size_t count = (size_t)c.value;
  if ((count * bpe + 7) / 8 > rem) return a;
  a.base = base;
  a.count = count;
  return a;
}

/** The array-with-optionals form `[LEB count][nil bitset][values]` at `ps`, uncompacted: value i
 * sits at index i whether or not its neighbours are nil. `width` is the value width in bytes, or
 * with `bits` set, the values are bit-packed `width` bits each (`[bool?]`, sub-byte enums). */
static inline dagr_array dagr_array_awo_open_(dagr_bytes buf, size_t ps, size_t width, bool bits) {
  dagr_array a = dagr_array_empty(buf);
  a.width = width;
  const dagr_varint c = dagr_read_leb(buf, ps);
  if (c.len == 0) return a;
  const size_t nil = ps + c.len;
  const size_t rem = dagr_remaining(buf, nil);
  /* the nil bitset alone needs ceil(count / 8) bytes, so count ≤ 8 · rem before any multiply */
  if (c.value / 8 > rem) return a;
  const size_t count = (size_t)c.value;
  const size_t nil_bytes = (count + 7) / 8;
  if (nil_bytes > rem) return a;
  const size_t left = rem - nil_bytes;
  if (bits ? (count / 8 > left / (width == 0 ? 1 : width) || (count * width + 7) / 8 > left)
           : (width != 0 && count > left / width)) {
    return a;
  }
  a.nil = nil;
  a.base = nil + nil_bytes;
  a.count = count;
  return a;
}
static inline dagr_array dagr_array_awo_open(dagr_bytes buf, size_t ps, size_t width) {
  return dagr_array_awo_open_(buf, ps, width, false);
}
static inline dagr_array dagr_array_awo_bits_open(dagr_bytes buf, size_t ps, unsigned bits) {
  return dagr_array_awo_open_(buf, ps, bits, true);
}

/** A pointer table `[LEB (count << 2) | wc][count slots of 1 << wc bytes][element data]` at
 * `ps`: utf8, data and node arrays. Slot i holds the element's offset from the data base plus
 * one; 0 is a nil element. */
static inline dagr_array dagr_array_ptrs_open(dagr_bytes buf, size_t ps) {
  dagr_array a = dagr_array_empty(buf);
  a.table = true;
  const dagr_varint h = dagr_read_leb(buf, ps);
  if (h.len == 0) return a;
  const size_t es = (size_t)1 << (h.value & 3u);
  const size_t base = ps + h.len;
  const uint64_t count = h.value >> 2;
  a.width = es;
  if (count > dagr_remaining(buf, base) / es) return a;
  a.base = base;
  a.data = base + (size_t)count * es;
  a.count = (size_t)count;
  return a;
}

/* ── Reading ─────────────────────────────────────────────────────────────────── */

static inline size_t dagr_array_len(const dagr_array *a) { return a->count; }

/** The raw slot value of element `i` of a pointer table (0: nil). */
static inline uint64_t dagr_array_slot_(const dagr_array *a, size_t i) {
  return dagr_read_uint_le(a->buf, a->base + i * a->width, a->width);
}

/** Whether element `i` exists and is not nil. The nil bitset is tested only when there is one:
 * SIZE_MAX + (i >> 3) would wrap onto a real byte. */
static inline bool dagr_array_has(const dagr_array *a, size_t i) {
  if (i >= a->count) return false;
  if (a->nil != SIZE_MAX && dagr_bit_at(a->buf, a->nil, i)) return false;
  return !a->table || dagr_array_slot_(a, i) != 0;
}

/** Where fixed-width element `i` sits; SIZE_MAX past the end or for a nil element. */
static inline size_t dagr_array_at_(const dagr_array *a, size_t i) {
  if (i >= a->count) return SIZE_MAX;
  if (a->nil != SIZE_MAX && dagr_bit_at(a->buf, a->nil, i)) return SIZE_MAX;
  return a->base + i * a->width;
}

static inline uint8_t dagr_array_u8(const dagr_array *a, size_t i) { return dagr_read_u8(a->buf, dagr_array_at_(a, i)); }
static inline uint16_t dagr_array_u16(const dagr_array *a, size_t i) { return dagr_read_u16(a->buf, dagr_array_at_(a, i)); }
static inline uint32_t dagr_array_u32(const dagr_array *a, size_t i) { return dagr_read_u32(a->buf, dagr_array_at_(a, i)); }
static inline uint64_t dagr_array_u64(const dagr_array *a, size_t i) { return dagr_read_u64(a->buf, dagr_array_at_(a, i)); }
static inline int8_t dagr_array_i8(const dagr_array *a, size_t i) { return dagr_read_i8(a->buf, dagr_array_at_(a, i)); }
static inline int16_t dagr_array_i16(const dagr_array *a, size_t i) { return dagr_read_i16(a->buf, dagr_array_at_(a, i)); }
static inline int32_t dagr_array_i32(const dagr_array *a, size_t i) { return dagr_read_i32(a->buf, dagr_array_at_(a, i)); }
static inline int64_t dagr_array_i64(const dagr_array *a, size_t i) { return dagr_read_i64(a->buf, dagr_array_at_(a, i)); }
static inline float dagr_array_f32(const dagr_array *a, size_t i) { return dagr_read_f32(a->buf, dagr_array_at_(a, i)); }
static inline double dagr_array_f64(const dagr_array *a, size_t i) { return dagr_read_f64(a->buf, dagr_array_at_(a, i)); }
static inline float dagr_array_f16(const dagr_array *a, size_t i) { return dagr_read_f16(a->buf, dagr_array_at_(a, i)); }
static inline float dagr_array_bf16(const dagr_array *a, size_t i) { return dagr_read_bf16(a->buf, dagr_array_at_(a, i)); }

/** An unsigned element at the array's width — a byte-aligned enum element at its backing width. */
static inline uint64_t dagr_array_uint(const dagr_array *a, size_t i) {
  return dagr_read_uint_le(a->buf, dagr_array_at_(a, i), a->width);
}

/** Element `i` of a bit-packed array: `width` bits (1, 2 or 4) — a sub-byte enum. */
static inline unsigned dagr_array_bits(const dagr_array *a, size_t i) {
  if (!dagr_array_has(a, i)) return 0;
  return dagr_packed_bits(a->buf, a->base, i, (unsigned)a->width);
}

/** Element `i` of a `[bool]` / `[bool?]` array. */
static inline bool dagr_array_bool(const dagr_array *a, size_t i) { return dagr_array_bits(a, i) != 0; }

/** The position of element `i` of a pointer table — SIZE_MAX past the end or for a nil slot.
 * `sign`: node slots are two's complement (a shared or cyclic node may sit BEFORE the array);
 * the sum is modular, and the reader of the position checks wherever it lands. */
static inline size_t dagr_array_elem_(const dagr_array *a, size_t i, bool sign) {
  if (i >= a->count || !a->table) return SIZE_MAX;
  const uint64_t slot = dagr_array_slot_(a, i);
  if (slot == 0) return SIZE_MAX;
  const uint64_t off = sign ? (uint64_t)dagr_sign_extend(slot, a->width) : slot;
  return a->data + (size_t)off - 1;
}

/** Element `i` of a `[utf8]` / `[utf8?]` array; empty when absent. */
static inline dagr_str dagr_array_str(const dagr_array *a, size_t i) {
  return dagr_read_text(a->buf, dagr_array_elem_(a, i, false));
}

/** Element `i` of a `[data]` / `[data?]` array; empty when absent. */
static inline dagr_bytes dagr_array_bytes(const dagr_array *a, size_t i) {
  return dagr_read_blob(a->buf, dagr_array_elem_(a, i, false));
}

/** Where node element `i` of a `[Node]` / `[Node?]` array starts — SIZE_MAX when absent. The
 * generated `P_NAccessor_array_at` reads it with the node's accessor. */
static inline size_t dagr_array_node(const dagr_array *a, size_t i) { return dagr_array_elem_(a, i, true); }

/* ── Bulk reads (spec/43) ────────────────────────────────────────────────────── */

/** Copies the first min(count, cap) elements into `out` and returns how many: ONE block copy on
 * a little-endian host when the elements are the array's whole native block — `width` is the
 * element type's size, there is no nil bitset and the block fits — element by element
 * otherwise, which yields the same values for the same bytes. */
static inline bool dagr_array_block_(const dagr_array *a, size_t n, size_t size, void *out) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  (void)a;
  (void)n;
  (void)size;
  (void)out;
  return false;
#else
  if (n == 0) return true;
  if (a->width != size || a->nil != SIZE_MAX || a->table) return false;
  if (n > dagr_remaining(a->buf, a->base) / size) return false;
  memcpy(out, a->buf.ptr + a->base, n * size);
  return true;
#endif
}

static inline size_t dagr_array_copy_u8(const dagr_array *a, uint8_t *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(uint8_t), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_u8(a, i);
  return n;
}
static inline size_t dagr_array_copy_u16(const dagr_array *a, uint16_t *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(uint16_t), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_u16(a, i);
  return n;
}
static inline size_t dagr_array_copy_u32(const dagr_array *a, uint32_t *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(uint32_t), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_u32(a, i);
  return n;
}
static inline size_t dagr_array_copy_u64(const dagr_array *a, uint64_t *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(uint64_t), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_u64(a, i);
  return n;
}
static inline size_t dagr_array_copy_i8(const dagr_array *a, int8_t *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(int8_t), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_i8(a, i);
  return n;
}
static inline size_t dagr_array_copy_i16(const dagr_array *a, int16_t *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(int16_t), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_i16(a, i);
  return n;
}
static inline size_t dagr_array_copy_i32(const dagr_array *a, int32_t *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(int32_t), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_i32(a, i);
  return n;
}
static inline size_t dagr_array_copy_i64(const dagr_array *a, int64_t *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(int64_t), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_i64(a, i);
  return n;
}
static inline size_t dagr_array_copy_f32(const dagr_array *a, float *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(float), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_f32(a, i);
  return n;
}
static inline size_t dagr_array_copy_f64(const dagr_array *a, double *out, size_t cap) {
  const size_t n = a->count < cap ? a->count : cap;
  if (dagr_array_block_(a, n, sizeof(double), out)) return n;
  for (size_t i = 0; i < n; i++) out[i] = dagr_array_f64(a, i);
  return n;
}

/* ── Zero-copy views of aligned(N) arrays (spec 12) ──────────────────────────── */

/** The elements in place: true with `*ptr` / `*len` set on a little-endian host when the block
 * is in bounds and its ADDRESS keeps the element alignment (an aligned(N) array is aligned
 * relative to the buffer start, so the buffer itself must be N-aligned). False otherwise — read
 * by index, which has no such precondition. An empty array is a view of nothing. */
static inline bool dagr_array_view_(const dagr_array *a, size_t size, const void **ptr, size_t *len) {
  *ptr = NULL;
  *len = 0;
  if (a->count == 0) return true;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return false;
#else
  if (a->width != size || a->nil != SIZE_MAX || a->table) return false;
  if (a->count > dagr_remaining(a->buf, a->base) / size) return false;
  const uint8_t *p = a->buf.ptr + a->base;
  if ((uintptr_t)p % size != 0) return false;
  *ptr = p;
  *len = a->count;
  return true;
#endif
}

static inline bool dagr_array_view_u8(const dagr_array *a, const uint8_t **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(uint8_t), &p, len);
  *ptr = (const uint8_t *)p;
  return ok;
}
static inline bool dagr_array_view_u16(const dagr_array *a, const uint16_t **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(uint16_t), &p, len);
  *ptr = (const uint16_t *)p;
  return ok;
}
static inline bool dagr_array_view_u32(const dagr_array *a, const uint32_t **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(uint32_t), &p, len);
  *ptr = (const uint32_t *)p;
  return ok;
}
static inline bool dagr_array_view_u64(const dagr_array *a, const uint64_t **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(uint64_t), &p, len);
  *ptr = (const uint64_t *)p;
  return ok;
}
static inline bool dagr_array_view_i8(const dagr_array *a, const int8_t **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(int8_t), &p, len);
  *ptr = (const int8_t *)p;
  return ok;
}
static inline bool dagr_array_view_i16(const dagr_array *a, const int16_t **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(int16_t), &p, len);
  *ptr = (const int16_t *)p;
  return ok;
}
static inline bool dagr_array_view_i32(const dagr_array *a, const int32_t **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(int32_t), &p, len);
  *ptr = (const int32_t *)p;
  return ok;
}
static inline bool dagr_array_view_i64(const dagr_array *a, const int64_t **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(int64_t), &p, len);
  *ptr = (const int64_t *)p;
  return ok;
}
static inline bool dagr_array_view_f32(const dagr_array *a, const float **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(float), &p, len);
  *ptr = (const float *)p;
  return ok;
}
static inline bool dagr_array_view_f64(const dagr_array *a, const double **ptr, size_t *len) {
  const void *p = NULL;
  const bool ok = dagr_array_view_(a, sizeof(double), &p, len);
  *ptr = (const double *)p;
  return ok;
}

/* ── Union arrays of a regular or frozen node (spec 05) ──────────────────────── */

/** `[LEB (count << 2) | wc][type ids][nil bitset?][count slots of 1 << wc bytes][payloads]`.
 * Type ids are `tag_bits` wide (1, 2 or 4 bits packed low first, or whole bytes); the nil bitset
 * exists only in the array-with-optionals form. A slot holds a small scalar in place, or an
 * offset from `base`. The generated `P_U_array_at` reads an element as a `P_UArrayElem`. */
typedef struct dagr_union_array {
  dagr_bytes buf;
  size_t tid;      /* the first type id */
  size_t nil;      /* SIZE_MAX: every element present */
  size_t slots;    /* the first slot */
  size_t base;     /* payload offsets in the slots are relative to this */
  size_t count;
  size_t es;       /* slot width in bytes */
  unsigned tag_bits;
} dagr_union_array;

/** The union array whose header is at `at`. The count is clamped: type ids, the nil bitset and
 * the slots must all fit in the buffer, or the array is empty. */
static inline dagr_union_array dagr_union_array_open(dagr_bytes buf, size_t at, unsigned tag_bits, bool optionals) {
  dagr_union_array a;
  a.buf = buf;
  a.tid = SIZE_MAX;
  a.nil = SIZE_MAX;
  a.slots = SIZE_MAX;
  a.base = SIZE_MAX;
  a.count = 0;
  a.es = 1;
  a.tag_bits = tag_bits;
  const dagr_varint h = dagr_read_leb(buf, at);
  if (h.len == 0) return a;
  const size_t es = (size_t)1 << (h.value & 3u);
  const size_t tid = at + h.len;
  const size_t rem = dagr_remaining(buf, tid);
  const uint64_t count64 = h.value >> 2;
  if (count64 > rem) return a; /* bounds the count before anything multiplies it */
  const size_t count = (size_t)count64;
  const size_t tid_bytes = tag_bits < 8 ? (count * tag_bits + 7) / 8 : count * (tag_bits / 8);
  const size_t nil_bytes = optionals ? (count + 7) / 8 : 0;
  if (tid_bytes > rem || nil_bytes > rem - tid_bytes || count * es > rem - tid_bytes - nil_bytes) return a;
  a.tid = tid;
  a.nil = optionals ? tid + tid_bytes : SIZE_MAX;
  a.slots = tid + tid_bytes + nil_bytes;
  a.base = a.slots + count * es;
  a.count = count;
  a.es = es;
  return a;
}

static inline size_t dagr_union_array_len(const dagr_union_array *a) { return a->count; }

/** Whether element `i` exists and is not nil. */
static inline bool dagr_union_array_has(const dagr_union_array *a, size_t i) {
  if (i >= a->count) return false;
  return a->nil == SIZE_MAX || !dagr_bit_at(a->buf, a->nil, i);
}

/** The type id of element `i`; 0xffffffff (no variant) past the end or for a nil element. */
static inline uint32_t dagr_union_array_tag(const dagr_union_array *a, size_t i) {
  if (!dagr_union_array_has(a, i)) return 0xffffffffu;
  if (a->tag_bits < 8) {
    const size_t bit = i * a->tag_bits;
    return ((uint32_t)dagr_read_u8(a->buf, a->tid + (bit >> 3)) >> (bit & 7u)) & ((1u << a->tag_bits) - 1u);
  }
  const size_t w = a->tag_bits / 8;
  return (uint32_t)dagr_read_uint_le(a->buf, a->tid + i * w, w);
}

/** Where element `i`'s slot is; SIZE_MAX past the end or for a nil element. */
static inline size_t dagr_union_array_slot(const dagr_union_array *a, size_t i) {
  return dagr_union_array_has(a, i) ? a->slots + i * a->es : SIZE_MAX;
}

#endif /* DAGR_ARRAYS_H */
