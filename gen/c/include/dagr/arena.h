/* dagr/arena.h — what a generated ARENA calls to own its memory (spec/44 §12.4): copies into
 * the store and frees out of it, through the arena's `dagr_allocator`. A generated arena holds a
 * record per node; strings, data and arrays in a record are OWNED blocks seen through the
 * runtime's views and slices (`dagr_str`, `dagr_u32_opt_slice`, …): a getter hands the view out
 * as it is, a setter copies the caller's in, and the arena frees what it replaces.
 *
 * Every copy reports failure through `*ok` (left untouched on success), so a generated setter
 * makes several and checks once; the arena turns a failure into its sticky `dagr_out_of_memory`.
 *
 * Model tier: grows through a `dagr_allocator` (dagr/heap.h). */
#ifndef DAGR_ARENA_H
#define DAGR_ARENA_H

#include <stdio.h>

#include "graph_writer.h"

/** A handle used with an arena it does not belong to, or one that is empty: a programming error,
 * reported and aborted — like an out-of-range index in a checked container. */
static inline void dagr_arena_misuse(const char *what) {
  fputs("dagr arena misuse: ", stderr);
  fputs(what, stderr);
  fputc('\n', stderr);
  abort();
}

/** A copy of `n` bytes at `src` in a new block (NULL for none); `*ok` false when it fails. */
static inline void *dagr_arena_dup(const dagr_allocator *a, const void *src, size_t n, bool *ok) {
  if (n == 0 || src == NULL) return NULL;
  void *p = a->resize(a->context, NULL, n);
  if (p == NULL) {
    *ok = false;
    return NULL;
  }
  memcpy(p, src, n);
  return p;
}

/** A copy of `n` elements of `size` bytes. */
static inline void *dagr_arena_dup_elems(const dagr_allocator *a, const void *src, size_t n, size_t size, bool *ok) {
  if (size != 0 && n > SIZE_MAX / size) {
    *ok = false;
    return NULL;
  }
  return dagr_arena_dup(a, src, n * size, ok);
}

/** `n` zeroed elements of `size` bytes (NULL for none). */
static inline void *dagr_arena_zeroed(const dagr_allocator *a, size_t n, size_t size, bool *ok) {
  if (n == 0 || size == 0) return NULL;
  if (n > SIZE_MAX / size) {
    *ok = false;
    return NULL;
  }
  void *p = a->resize(a->context, NULL, n * size);
  if (p == NULL) {
    *ok = false;
    return NULL;
  }
  memset(p, 0, n * size);
  return p;
}

static inline dagr_str dagr_arena_dup_str(const dagr_allocator *a, dagr_str s, bool *ok) {
  const char *p = (const char *)dagr_arena_dup(a, s.ptr, s.len, ok);
  return dagr_str_of(p, p != NULL ? s.len : 0);
}

static inline dagr_bytes dagr_arena_dup_bytes(const dagr_allocator *a, dagr_bytes d, bool *ok) {
  const uint8_t *p = (const uint8_t *)dagr_arena_dup(a, d.ptr, d.len, ok);
  return dagr_bytes_of(p, p != NULL ? d.len : 0);
}

/** A copy of a presence array (NULL stays NULL: an array without optionals). */
static inline const bool *dagr_arena_dup_present(const dagr_allocator *a, const bool *present, size_t n, bool *ok) {
  return present == NULL ? NULL : (const bool *)dagr_arena_dup_elems(a, present, n, sizeof(bool), ok);
}

/** The presence array of an array WITH optionals, always owned: a copy of `present`, or every
 * element present when it is NULL — so that a stale element can be nilled in place (spec 09). */
static inline const bool *dagr_arena_presence(const dagr_allocator *a, const bool *present, size_t n, bool *ok) {
  if (present != NULL) return dagr_arena_dup_present(a, present, n, ok);
  bool *out = (bool *)dagr_arena_zeroed(a, n, sizeof(bool), ok);
  if (out != NULL) {
    for (size_t i = 0; i < n; i++) out[i] = true;
  }
  return out;
}

/** Copies of `n` strings, each its own block (an absent element is empty). */
static inline const dagr_str *dagr_arena_dup_strs(const dagr_allocator *a, const dagr_str *src, const bool *present,
                                                  size_t n, bool *ok) {
  dagr_str *out = (dagr_str *)dagr_arena_zeroed(a, n, sizeof(dagr_str), ok);
  if (out == NULL) return NULL;
  for (size_t i = 0; i < n; i++) {
    if (dagr_is_present(present, i)) out[i] = dagr_arena_dup_str(a, src[i], ok);
  }
  return out;
}

static inline const dagr_bytes *dagr_arena_dup_blobs(const dagr_allocator *a, const dagr_bytes *src, const bool *present,
                                                     size_t n, bool *ok) {
  dagr_bytes *out = (dagr_bytes *)dagr_arena_zeroed(a, n, sizeof(dagr_bytes), ok);
  if (out == NULL) return NULL;
  for (size_t i = 0; i < n; i++) {
    if (dagr_is_present(present, i)) out[i] = dagr_arena_dup_bytes(a, src[i], ok);
  }
  return out;
}

static inline void dagr_arena_free_strs(const dagr_allocator *a, const dagr_str *p, size_t n) {
  if (p == NULL) return;
  for (size_t i = 0; i < n; i++) dagr_release(a, p[i].ptr);
  dagr_release(a, p);
}

static inline void dagr_arena_free_blobs(const dagr_allocator *a, const dagr_bytes *p, size_t n) {
  if (p == NULL) return;
  for (size_t i = 0; i < n; i++) dagr_release(a, p[i].ptr);
  dagr_release(a, p);
}

/** A mutable view of an element the arena owns (`elems` was allocated by it): what a restore
 * fills in place. */
static inline void *dagr_arena_mut(const void *elems) { return (void *)(uintptr_t)elems; }

/* ── The describer: equals / hash / to_string (spec/44 §12.4) ──────────────────────
 * One canonical walk of a node and everything it reaches, as text: a node met again — shared, or
 * a cycle — is `Name#n`, its traversal ordinal, so the text is arena-identity-free and the walk
 * terminates. Floats are written by their BITS (equal means bit-identical: -0.0 differs from 0.0, a
 * NaN equals itself). Deeper than `max_depth`, the walk writes `…`. */

typedef struct dagr_desc_entry {
  uint64_t type;
  uint64_t handle;
  size_t ordinal;
} dagr_desc_entry;

typedef struct dagr_describer {
  dagr_allocator alloc;
  char *out;
  size_t len, cap;
  dagr_index seen;
  dagr_desc_entry *entries;
  size_t n, entries_cap;
  size_t depth, max_depth;
  bool failed; /* an allocation failed: the text is incomplete */
} dagr_describer;

static inline dagr_describer dagr_describer_init(dagr_allocator alloc, size_t max_depth) {
  dagr_describer d;
  memset(&d, 0, sizeof d);
  d.alloc = alloc;
  d.seen = dagr_index_empty();
  d.max_depth = max_depth;
  return d;
}

static inline void dagr_describer_free(dagr_describer *d) {
  dagr_release(&d->alloc, d->out);
  dagr_release(&d->alloc, d->entries);
  dagr_index_free(&d->seen, &d->alloc);
  d->out = NULL;
  d->entries = NULL;
  d->len = d->cap = d->n = d->entries_cap = 0;
}

static inline void dagr_desc_raw_n(dagr_describer *d, const char *text, size_t n) {
  if (d->failed || n == 0) return;
  char *out = (char *)dagr_grow(&d->alloc, d->out, &d->cap, d->len + n + 1, 1);
  if (out == NULL) {
    d->failed = true;
    return;
  }
  d->out = out;
  memcpy(d->out + d->len, text, n);
  d->len += n;
  d->out[d->len] = '\0';
}

static inline void dagr_desc_raw(dagr_describer *d, const char *text) { dagr_desc_raw_n(d, text, strlen(text)); }

static inline void dagr_desc_u64(dagr_describer *d, uint64_t v) {
  char text[24];
  const int n = snprintf(text, sizeof text, "%llu", (unsigned long long)v);
  dagr_desc_raw_n(d, text, n > 0 ? (size_t)n : 0);
}

static inline void dagr_desc_i64(dagr_describer *d, int64_t v) {
  char text[24];
  const int n = snprintf(text, sizeof text, "%lld", (long long)v);
  dagr_desc_raw_n(d, text, n > 0 ? (size_t)n : 0);
}

static inline void dagr_desc_bits(dagr_describer *d, const char *prefix, uint64_t bits) {
  char text[24];
  const int n = snprintf(text, sizeof text, "%s%llx", prefix, (unsigned long long)bits);
  dagr_desc_raw_n(d, text, n > 0 ? (size_t)n : 0);
}

static inline void dagr_desc_bool(dagr_describer *d, bool v) { dagr_desc_raw(d, v ? "true" : "false"); }
static inline void dagr_desc_f32(dagr_describer *d, float v) { dagr_desc_bits(d, "f", dagr_f32_bits(v)); }
static inline void dagr_desc_f64(dagr_describer *d, double v) { dagr_desc_bits(d, "d", dagr_f64_bits(v)); }
static inline void dagr_desc_none(dagr_describer *d) { dagr_desc_raw(d, "nil"); }

/** Text, quoted, with `"` and `\` escaped. */
static inline void dagr_desc_str(dagr_describer *d, dagr_str s) {
  dagr_desc_raw(d, "\"");
  for (size_t i = 0; i < s.len; i++) {
    if (s.ptr[i] == '"' || s.ptr[i] == '\\') dagr_desc_raw(d, "\\");
    dagr_desc_raw_n(d, s.ptr + i, 1);
  }
  dagr_desc_raw(d, "\"");
}

/** Bytes as `0x` and lower-case hex. */
static inline void dagr_desc_bytes(dagr_describer *d, dagr_bytes b) {
  static const char hex[] = "0123456789abcdef";
  dagr_desc_raw(d, "0x");
  for (size_t i = 0; i < b.len; i++) {
    const char two[2] = {hex[b.ptr[i] >> 4], hex[b.ptr[i] & 15]};
    dagr_desc_raw_n(d, two, 2);
  }
}

static inline void dagr_desc_field(dagr_describer *d, const char *name, bool first) {
  if (!first) dagr_desc_raw(d, ", ");
  dagr_desc_raw(d, name);
  dagr_desc_raw(d, ": ");
}

static inline void dagr_desc_sep(dagr_describer *d, size_t i) {
  if (i > 0) dagr_desc_raw(d, ", ");
}

/** Starts node `handle` of node type `type`: false — having written `Name#n` (met before) or `…`
 * (the depth limit) — when its fields are not to be written; true after `Name#n{`, paired with
 * `dagr_desc_leave`. */
static inline bool dagr_desc_enter(dagr_describer *d, uint64_t type, const char *name, uint64_t handle) {
  const uint64_t h = dagr_mix(handle ^ dagr_mix(type + UINT64_C(0x51ed)));
  size_t i = dagr_index_first(&d->seen, h);
  for (uint32_t e; (e = dagr_index_next(&d->seen, h, &i)) != dagr_index_none;) {
    if (d->entries[e].type == type && d->entries[e].handle == handle) {
      dagr_desc_raw(d, name);
      dagr_desc_raw(d, "#");
      dagr_desc_u64(d, (uint64_t)d->entries[e].ordinal);
      return false;
    }
  }
  if (d->depth >= d->max_depth) {
    dagr_desc_raw(d, "\xe2\x80\xa6");
    return false;
  }
  dagr_desc_entry *entries = (dagr_desc_entry *)dagr_grow(&d->alloc, d->entries, &d->entries_cap, d->n + 1, sizeof *entries);
  if (entries == NULL || !dagr_index_insert(&d->seen, &d->alloc, h, (uint32_t)d->n)) {
    if (entries != NULL) d->entries = entries;
    d->failed = true;
    return false;
  }
  d->entries = entries;
  d->entries[d->n].type = type;
  d->entries[d->n].handle = handle;
  d->entries[d->n].ordinal = d->n;
  dagr_desc_raw(d, name);
  dagr_desc_raw(d, "#");
  dagr_desc_u64(d, (uint64_t)d->n);
  dagr_desc_raw(d, "{");
  d->n++;
  d->depth++;
  return true;
}

static inline void dagr_desc_leave(dagr_describer *d) {
  d->depth--;
  dagr_desc_raw(d, "}");
}

/** FNV-1a of `n` bytes. */
static inline uint64_t dagr_fnv1a(const char *p, size_t n) {
  uint64_t h = UINT64_C(0xcbf29ce484222325);
  for (size_t i = 0; i < n; i++) {
    h ^= (uint8_t)p[i];
    h *= UINT64_C(0x100000001b3);
  }
  return h;
}

/** Copies the description into `buf` (NUL-terminated, cut at `cap - 1`) and frees the
    describer; returns the full length, as snprintf does (0 when an allocation failed). */
static inline size_t dagr_describer_take(dagr_describer *d, char *buf, size_t cap) {
  const size_t n = d->failed ? 0 : d->len;
  if (buf != NULL && cap != 0) {
    const size_t k = n < cap - 1 ? n : cap - 1;
    if (k != 0) memcpy(buf, d->out, k);
    buf[k] = '\0';
  }
  dagr_describer_free(d);
  return n;
}

/** Whether two descriptions are the same text; frees both. A failed one equals nothing. */
static inline bool dagr_describer_same(dagr_describer *x, dagr_describer *y) {
  const bool same = !x->failed && !y->failed && x->len == y->len &&
                    (x->len == 0 || memcmp(x->out, y->out, x->len) == 0);
  dagr_describer_free(x);
  dagr_describer_free(y);
  return same;
}

/** FNV-1a of the description (0 when an allocation failed); frees the describer. */
static inline uint64_t dagr_describer_hash(dagr_describer *d) {
  const uint64_t out = d->failed ? 0 : dagr_fnv1a(d->out, d->len);
  dagr_describer_free(d);
  return out;
}

#endif /* DAGR_ARENA_H */
