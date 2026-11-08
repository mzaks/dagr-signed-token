/* dagr/values.h — what the generated VALUE form needs (spec/44 §12.1): the scratch memory a
 * restore builds arrays in, and the restore context. A transliteration of the C++ target's
 * dagr/values.hpp.
 *
 * A value tree BORROWS: strings and data are views of the caller's memory (or of the buffer a
 * restore read), arrays are pointer + length, a union holding a node points at it. Nothing
 * here owns or frees anything a value refers to.
 *
 * Core tier: no allocation — a dagr_scratch hands out the caller's memory; dagr/heap.h makes
 * one that grows. */
#ifndef DAGR_VALUES_H
#define DAGR_VALUES_H

#include "reader.h"

typedef struct dagr_scratch dagr_scratch;

/** How a growing scratch gets another block of at least `bytes`: it re-points begin / cur /
 * end and returns true, or returns false. */
typedef bool (*dagr_refill_fn)(dagr_scratch *s, size_t bytes);

/** Memory for the arrays a restore builds: a bump allocator over storage the caller provides.
 * Nothing is freed individually — rewinding (`dagr_scratch_reset`) invalidates everything
 * handed out. A request that does not fit yields NULL and is remembered (`exhausted`). */
struct dagr_scratch {
  uint8_t *begin;
  uint8_t *cur;
  uint8_t *end;
  size_t used;              /* bytes in blocks before the current one */
  bool exhausted;
  dagr_status failure;      /* why a request is refused: buffer_full, or out_of_memory (heap) */
  dagr_refill_fn refill;
  void *context;
};

static inline dagr_scratch dagr_scratch_over(void *storage, size_t size) {
  dagr_scratch s;
  s.begin = (uint8_t *)storage;
  s.cur = s.begin;
  s.end = s.begin == NULL ? NULL : s.begin + size;
  s.used = 0;
  s.exhausted = false;
  s.failure = dagr_buffer_full;
  s.refill = NULL;
  s.context = NULL;
  return s;
}

/** Uninitialized room for `n` objects of `size` bytes aligned to `align`, or NULL. */
static inline void *dagr_scratch_room(dagr_scratch *s, size_t n, size_t size, size_t align) {
  if (size != 0 && n > SIZE_MAX / size) {
    s->exhausted = true;
    return NULL;
  }
  const size_t bytes = n * size;
  for (int attempt = 0; attempt < 2; attempt++) {
    const size_t left = (size_t)(s->end - s->cur);
    const size_t pad = (align - ((uintptr_t)s->cur & (align - 1))) & (align - 1);
    if (s->cur != NULL && pad <= left && bytes <= left - pad) {
      uint8_t *p = s->cur + pad;
      s->cur = p + bytes;
      return p;
    }
    /* one refill, sized so that the request fits whatever the new block's alignment */
    if (attempt == 1 || s->refill == NULL) break;
    const size_t before = (size_t)(s->cur - s->begin);
    if (!s->refill(s, bytes + align)) break;
    s->used += before;
  }
  s->exhausted = true;
  return NULL;
}

/** Bytes handed out so far. */
static inline size_t dagr_scratch_used(const dagr_scratch *s) { return s->used + (size_t)(s->cur - s->begin); }

/** Invalidates everything handed out (a growing scratch keeps its current block). */
static inline void dagr_scratch_reset(dagr_scratch *s) {
  s->cur = s->begin;
  s->used = 0;
  s->exhausted = false;
}

/* ── Slices: the arrays of a value tree ─────────────────────────────────────────
 * `{ptr, len}` over the caller's memory (or a restore's scratch); the `_opt_slice` of an
 * array with optionals adds `present` — element i is nil when present[i] is false (its
 * value is then ignored). f16 / bf16 arrays are f32 slices: their API type is float. */

typedef struct dagr_u8_slice {
  const uint8_t *ptr;
  size_t len;
} dagr_u8_slice;
typedef struct dagr_u8_opt_slice {
  const uint8_t *ptr;
  const bool *present;
  size_t len;
} dagr_u8_opt_slice;

typedef struct dagr_u16_slice {
  const uint16_t *ptr;
  size_t len;
} dagr_u16_slice;
typedef struct dagr_u16_opt_slice {
  const uint16_t *ptr;
  const bool *present;
  size_t len;
} dagr_u16_opt_slice;

typedef struct dagr_u32_slice {
  const uint32_t *ptr;
  size_t len;
} dagr_u32_slice;
typedef struct dagr_u32_opt_slice {
  const uint32_t *ptr;
  const bool *present;
  size_t len;
} dagr_u32_opt_slice;

typedef struct dagr_u64_slice {
  const uint64_t *ptr;
  size_t len;
} dagr_u64_slice;
typedef struct dagr_u64_opt_slice {
  const uint64_t *ptr;
  const bool *present;
  size_t len;
} dagr_u64_opt_slice;

typedef struct dagr_i8_slice {
  const int8_t *ptr;
  size_t len;
} dagr_i8_slice;
typedef struct dagr_i8_opt_slice {
  const int8_t *ptr;
  const bool *present;
  size_t len;
} dagr_i8_opt_slice;

typedef struct dagr_i16_slice {
  const int16_t *ptr;
  size_t len;
} dagr_i16_slice;
typedef struct dagr_i16_opt_slice {
  const int16_t *ptr;
  const bool *present;
  size_t len;
} dagr_i16_opt_slice;

typedef struct dagr_i32_slice {
  const int32_t *ptr;
  size_t len;
} dagr_i32_slice;
typedef struct dagr_i32_opt_slice {
  const int32_t *ptr;
  const bool *present;
  size_t len;
} dagr_i32_opt_slice;

typedef struct dagr_i64_slice {
  const int64_t *ptr;
  size_t len;
} dagr_i64_slice;
typedef struct dagr_i64_opt_slice {
  const int64_t *ptr;
  const bool *present;
  size_t len;
} dagr_i64_opt_slice;

typedef struct dagr_f32_slice {
  const float *ptr;
  size_t len;
} dagr_f32_slice;
typedef struct dagr_f32_opt_slice {
  const float *ptr;
  const bool *present;
  size_t len;
} dagr_f32_opt_slice;

typedef struct dagr_f64_slice {
  const double *ptr;
  size_t len;
} dagr_f64_slice;
typedef struct dagr_f64_opt_slice {
  const double *ptr;
  const bool *present;
  size_t len;
} dagr_f64_opt_slice;

typedef struct dagr_bool_slice {
  const bool *ptr;
  size_t len;
} dagr_bool_slice;
typedef struct dagr_bool_opt_slice {
  const bool *ptr;
  const bool *present;
  size_t len;
} dagr_bool_opt_slice;

typedef struct dagr_str_slice {
  const dagr_str *ptr;
  size_t len;
} dagr_str_slice;
typedef struct dagr_str_opt_slice {
  const dagr_str *ptr;
  const bool *present;
  size_t len;
} dagr_str_opt_slice;

typedef struct dagr_bytes_slice {
  const dagr_bytes *ptr;
  size_t len;
} dagr_bytes_slice;
typedef struct dagr_bytes_opt_slice {
  const dagr_bytes *ptr;
  const bool *present;
  size_t len;
} dagr_bytes_opt_slice;

/* ── Restore ─────────────────────────────────────────────────────────────────── */

/** How deep a restore follows nested nodes and unions before it gives up: the walk is
 * recursive over the DATA (spec/41 §5 rule 7). */
enum { dagr_default_max_depth = 128 };

/** What the generated restore functions thread: where arrays go, how deep the walk may still
 * descend, and the first thing that went wrong. */
typedef struct dagr_restore {
  dagr_scratch *scratch;
  size_t depth_left;
  dagr_status status;
} dagr_restore;

static inline dagr_restore dagr_restore_init(dagr_scratch *scratch, size_t max_depth) {
  dagr_restore r;
  r.scratch = scratch;
  r.depth_left = max_depth;
  r.status = dagr_ok;
  return r;
}

static inline void dagr_restore_fail(dagr_restore *r, dagr_status status) {
  if (r->status == dagr_ok) r->status = status;
}

/** Enters one level of the recursion: false (recorded) when the depth limit is reached, and the
 * restore then returns an empty value instead of descending. Pair with dagr_restore_leave. */
static inline bool dagr_restore_enter(dagr_restore *r) {
  if (r->depth_left == 0) {
    dagr_restore_fail(r, dagr_depth_exceeded);
    return false;
  }
  r->depth_left--;
  return true;
}

static inline void dagr_restore_leave(dagr_restore *r) { r->depth_left++; }

/** A utf8 value, checked (spec/49 U1): invalid text records `dagr_invalid_utf8`. */
static inline dagr_str dagr_restore_text(dagr_restore *r, dagr_str s) {
  if (!dagr_valid_utf8(s)) dagr_restore_fail(r, dagr_invalid_utf8);
  return s;
}

/** Room for `n` elements in the restore's scratch; NULL (recorded) when it does not fit. A
 * zero count is no request at all. */
static inline void *dagr_restore_room(dagr_restore *r, size_t n, size_t size, size_t align) {
  if (n == 0) return NULL;
  void *p = dagr_scratch_room(r->scratch, n, size, align);
  if (p == NULL) dagr_restore_fail(r, r->scratch->failure);
  return p;
}

/* ── Comparisons a writer's default elision makes (spec 14 §4) ───────────────── */

/** Bitwise, so that an elided value is synthesized back bit for bit. */
static inline bool dagr_same_f32(float a, float b) { return dagr_f32_bits(a) == dagr_f32_bits(b); }
static inline bool dagr_same_f64(double a, double b) { return dagr_f64_bits(a) == dagr_f64_bits(b); }

#endif /* DAGR_VALUES_H */
