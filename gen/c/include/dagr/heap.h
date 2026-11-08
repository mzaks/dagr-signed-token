/* dagr/heap.h — the alloc tier of the C target (spec/44 §12.1): a growing builder, a growing
 * scratch and a growing destination, over malloc / realloc / free. The ONLY runtime header that
 * allocates; everything else takes caller memory.
 *
 *   dagr_builder b = dagr_builder_heap();         // grows; dagr_builder_heap_free(&b) when done
 *   dagr_scratch s = dagr_scratch_heap();         // grows; dagr_scratch_heap_free(&s)
 *   dagr_heap_dest d = dagr_heap_dest_empty();    // dagr_heap_dest_as_dest(&d); free with _free
 */
#ifndef DAGR_HEAP_H
#define DAGR_HEAP_H

#include <stdlib.h>

#include "sink.h"
#include "values.h"

/* ── The allocator the model tier grows through (spec/44 §12.4) ───────────────────
 * One realloc-style function: `resize(context, ptr, size)` — `size` 0 frees `ptr` and returns
 * NULL; otherwise the resized block, or NULL (the old block untouched) when it cannot. The arena
 * and the serializer's caches allocate ONLY through it, so a caller can hand them a pool. */

typedef struct dagr_allocator {
  void *(*resize)(void *context, void *ptr, size_t size);
  void *context;
} dagr_allocator;

static inline void *dagr_libc_resize(void *context, void *ptr, size_t size) {
  (void)context;
  if (size == 0) {
    free(ptr);
    return NULL;
  }
  return realloc(ptr, size);
}

/** malloc / realloc / free. */
static inline dagr_allocator dagr_default_allocator(void) {
  dagr_allocator a;
  a.resize = dagr_libc_resize;
  a.context = NULL;
  return a;
}

/** `ptr` — `*cap` elements of `size` bytes — grown to hold at least `need` (doubling, from 8):
 * the block to use from now on (`ptr` itself when it is big enough), or NULL — `ptr` untouched,
 * still valid — when the allocator refuses or the size would overflow.
 *
 *     T *more = dagr_grow(&a, xs, &cap, n + 1, sizeof(T));
 *     if (more == NULL) fail; else xs = more;
 */
static inline void *dagr_grow(const dagr_allocator *a, void *ptr, size_t *cap, size_t need, size_t size) {
  if (need <= *cap && ptr != NULL) return ptr;
  size_t n = *cap < 8 ? 8 : *cap;
  while (n < need) {
    if (n > SIZE_MAX / 2) return NULL;
    n *= 2;
  }
  if (size != 0 && n > SIZE_MAX / size) return NULL;
  void *p = a->resize(a->context, ptr, n * size);
  if (p == NULL) return NULL;
  *cap = n;
  return p;
}

/** Frees through the allocator; a `const` view of an owned block is accepted. */
static inline void dagr_release(const dagr_allocator *a, const void *ptr) {
  if (ptr != NULL) (void)a->resize(a->context, (void *)(uintptr_t)ptr, 0);
}

/* ── A growing builder ─────────────────────────────────────────────────────────── */

/** Doubles the storage until `need` more bytes fit, keeping what is stored at the END. */
static inline bool dagr_builder_heap_grow(dagr_builder *b, size_t need) {
  size_t cap = b->cap < 64 ? 64 : b->cap;
  while (need > cap - b->cursor) {
    if (cap > SIZE_MAX / 2) return false;
    cap *= 2;
  }
  uint8_t *data = (uint8_t *)malloc(cap);
  if (data == NULL) return false;
  if (b->cursor != 0) memcpy(data + (cap - b->cursor), b->data + (b->cap - b->cursor), b->cursor);
  free(b->data);
  b->data = data;
  b->cap = cap;
  return true;
}

/** A builder that grows on the heap: `dagr_out_of_memory` when an allocation fails. Reusable —
 * `dagr_builder_reset` keeps its storage. */
static inline dagr_builder dagr_builder_heap(void) {
  dagr_builder b = dagr_builder_fixed(NULL, 0);
  b.grow = dagr_builder_heap_grow;
  return b;
}

static inline void dagr_builder_heap_free(dagr_builder *b) {
  free(b->data);
  b->data = NULL;
  b->cap = 0;
  b->cursor = 0;
}

/* ── A growing scratch ─────────────────────────────────────────────────────────────
 * Blocks are chained through a header at their start, so that freeing finds them all; a
 * reset keeps the newest (largest) block and frees the others. */

typedef struct dagr_heap_block {
  struct dagr_heap_block *prev;
  size_t size;
} dagr_heap_block;

static inline bool dagr_scratch_heap_refill(dagr_scratch *s, size_t bytes) {
  const dagr_heap_block *cur = (const dagr_heap_block *)s->context;
  size_t size = cur != NULL && cur->size > 4096 ? cur->size * 2 : 4096;
  while (size < bytes) {
    if (size > SIZE_MAX / 2) return false;
    size *= 2;
  }
  if (size > SIZE_MAX - sizeof(dagr_heap_block)) return false;
  dagr_heap_block *block = (dagr_heap_block *)malloc(sizeof(dagr_heap_block) + size);
  if (block == NULL) return false;
  block->prev = (dagr_heap_block *)s->context;
  block->size = size;
  s->context = block;
  s->begin = (uint8_t *)(block + 1);
  s->cur = s->begin;
  s->end = s->begin + size;
  return true;
}

/** A scratch that grows on the heap (`dagr_out_of_memory` when it cannot). */
static inline dagr_scratch dagr_scratch_heap(void) {
  dagr_scratch s = dagr_scratch_over(NULL, 0);
  s.refill = dagr_scratch_heap_refill;
  s.failure = dagr_out_of_memory;
  return s;
}

/** Invalidates everything handed out and keeps only the newest (largest) block. */
static inline void dagr_scratch_heap_reset(dagr_scratch *s) {
  dagr_heap_block *block = (dagr_heap_block *)s->context;
  if (block != NULL) {
    dagr_heap_block *older = block->prev;
    while (older != NULL) {
      dagr_heap_block *prev = older->prev;
      free(older);
      older = prev;
    }
    block->prev = NULL;
    s->begin = (uint8_t *)(block + 1);
    s->end = s->begin + block->size;
  }
  dagr_scratch_reset(s);
}

static inline void dagr_scratch_heap_free(dagr_scratch *s) {
  dagr_heap_block *block = (dagr_heap_block *)s->context;
  while (block != NULL) {
    dagr_heap_block *prev = block->prev;
    free(block);
    block = prev;
  }
  *s = dagr_scratch_heap();
}

/* ── A growing destination ─────────────────────────────────────────────────────── */

typedef struct dagr_heap_dest {
  uint8_t *data;
  size_t cap;
  size_t size;
} dagr_heap_dest;

static inline dagr_heap_dest dagr_heap_dest_empty(void) {
  dagr_heap_dest d;
  d.data = NULL;
  d.cap = 0;
  d.size = 0;
  return d;
}

/** Makes room for `n` more bytes (the capacity doubles); false when it cannot. */
static inline bool dagr_heap_dest_grow_(dagr_heap_dest *d, size_t n) {
  if (n <= d->cap - d->size) return true;
  size_t cap = d->cap < 64 ? 64 : d->cap;
  while (n > cap - d->size) {
    if (cap > SIZE_MAX / 2) return false;
    cap *= 2;
  }
  uint8_t *data = (uint8_t *)realloc(d->data, cap);
  if (data == NULL) return false;
  d->data = data;
  d->cap = cap;
  return true;
}

static inline dagr_status dagr_heap_dest_write(void *context, const uint8_t *bytes, size_t n) {
  dagr_heap_dest *d = (dagr_heap_dest *)context;
  if (!dagr_heap_dest_grow_(d, n)) return dagr_out_of_memory;
  if (n != 0) memcpy(d->data + d->size, bytes, n);
  d->size += n;
  return dagr_ok;
}

/** Writing IN PLACE (`dagr_sink_room`): `n` bytes right after what is written, growing for
 * them, or NULL. They count once committed. */
static inline uint8_t *dagr_heap_dest_room(void *context, size_t n) {
  dagr_heap_dest *d = (dagr_heap_dest *)context;
  return dagr_heap_dest_grow_(d, n) ? d->data + d->size : NULL;
}

/** Takes the `len` bytes written in place at what `room` returned. */
static inline dagr_status dagr_heap_dest_commit(void *context, size_t len) {
  dagr_heap_dest *d = (dagr_heap_dest *)context;
  if (len > d->cap - d->size) return dagr_buffer_full;
  d->size += len;
  return dagr_ok;
}

static inline dagr_sink_dest dagr_heap_dest_as_dest(dagr_heap_dest *d) {
  dagr_sink_dest dest = dagr_sink_dest_of(dagr_heap_dest_write, d);
  dest.room = dagr_heap_dest_room;
  dest.commit = dagr_heap_dest_commit;
  return dest;
}

static inline dagr_bytes dagr_heap_dest_bytes(const dagr_heap_dest *d) { return dagr_bytes_of(d->data, d->size); }

static inline void dagr_heap_dest_free(dagr_heap_dest *d) {
  free(d->data);
  *d = dagr_heap_dest_empty();
}

#endif /* DAGR_HEAP_H */
