/* dagr/graph_writer.h — the write side of the generated ARENAS (spec/44 §12.4): what a whole
 * graph needs beyond the packed stores of dagr/writer.h — regular (vtable) and frozen
 * (positional) nodes, the regular arrays and union slots they point at, the three dedup caches,
 * late binding for cycles — and the restore's table of nodes read so far. A port of the C++
 * target's dagr/graph_writer.hpp, itself a port of the Python reference writer
 * (dagr/runtime/dagr_writer.py), which is byte-identical to the Swift and Rust writers.
 *
 * Offsets. A stored thing is named by the builder's cursor right after it was stored — the bytes
 * from its first byte to the end of the record. Offsets survive the growing builder's
 * reallocation (the record grows at its front); a pointer is the difference of two of them.
 *
 * Failure is sticky, as everywhere: a builder that failed stores nothing more, and so does every
 * function here. A cache that cannot grow fails the builder with `dagr_out_of_memory`; a vtable
 * entry or a reference the wire cannot hold fails it with `dagr_invalid_value`.
 *
 * Model tier: grows through a `dagr_allocator` (dagr/heap.h). */
#ifndef DAGR_GRAPH_WRITER_H
#define DAGR_GRAPH_WRITER_H

#include "heap.h"
#include "writer.h"

/* ── Hashing ───────────────────────────────────────────────────────────────────── */

/** splitmix64's finalizer. */
static inline uint64_t dagr_mix(uint64_t x) {
  x ^= x >> 30;
  x *= UINT64_C(0xbf58476d1ce4e5b9);
  x ^= x >> 27;
  x *= UINT64_C(0x94d049bb133111eb);
  return x ^ (x >> 31);
}

static inline uint64_t dagr_hash_bytes(const uint8_t *p, size_t n) {
  uint64_t h = UINT64_C(0xcbf29ce484222325) ^ (uint64_t)n;
  for (size_t i = 0; i < n; i++) {
    h ^= p[i];
    h *= UINT64_C(0x100000001b3);
  }
  return dagr_mix(h);
}

/* ── An open-addressing index ──────────────────────────────────────────────────────
 * Maps a 64-bit hash to entries — indices into an array the caller owns — with linear probing;
 * equal hashes are told apart by the caller. Clearing is O(1): a slot is occupied only under the
 * current epoch. Probe with `dagr_index_first` / `dagr_index_next`. */

/** No entry. */
static const uint32_t dagr_index_none = 0xffffffffu;

typedef struct dagr_index_slot {
  uint64_t hash;
  uint32_t entry;
  uint32_t epoch;
} dagr_index_slot;

typedef struct dagr_index {
  dagr_index_slot *slots;
  size_t cap;    /* a power of two, or 0 */
  size_t used;
  uint32_t epoch;
} dagr_index;

static inline dagr_index dagr_index_empty(void) {
  dagr_index x;
  x.slots = NULL;
  x.cap = 0;
  x.used = 0;
  x.epoch = 1;
  return x;
}

/** The first slot to probe for `hash` (SIZE_MAX: the index is empty). */
static inline size_t dagr_index_first(const dagr_index *x, uint64_t hash) {
  return x->cap == 0 ? SIZE_MAX : (size_t)hash & (x->cap - 1);
}

/** The entry at probe position `*i` stored under `hash`, advancing `*i`; dagr_index_none once the
 * probe reaches a free slot (no more candidates). Skips slots of other hashes. */
static inline uint32_t dagr_index_next(const dagr_index *x, uint64_t hash, size_t *i) {
  if (*i == SIZE_MAX) return dagr_index_none;
  for (;;) {
    const dagr_index_slot *s = &x->slots[*i];
    if (s->epoch != x->epoch) {
      *i = SIZE_MAX;
      return dagr_index_none;
    }
    *i = (*i + 1) & (x->cap - 1);
    if (s->hash == hash) return s->entry;
  }
}

static inline void dagr_index_put_(dagr_index *x, uint64_t hash, uint32_t entry) {
  size_t i = (size_t)hash & (x->cap - 1);
  while (x->slots[i].epoch == x->epoch) i = (i + 1) & (x->cap - 1);
  x->slots[i].hash = hash;
  x->slots[i].entry = entry;
  x->slots[i].epoch = x->epoch;
}

/** False when the index cannot grow. */
static inline bool dagr_index_insert(dagr_index *x, const dagr_allocator *a, uint64_t hash, uint32_t entry) {
  if ((x->used + 1) * 2 > x->cap) {
    const size_t cap = x->cap == 0 ? 64 : x->cap * 2;
    if (cap > SIZE_MAX / sizeof(dagr_index_slot)) return false;
    dagr_index_slot *slots = (dagr_index_slot *)a->resize(a->context, NULL, cap * sizeof(dagr_index_slot));
    if (slots == NULL) return false;
    memset(slots, 0, cap * sizeof(dagr_index_slot));
    dagr_index old = *x;
    x->slots = slots;
    x->cap = cap;
    x->epoch = 1;
    for (size_t i = 0; i < old.cap; i++) {
      if (old.slots[i].epoch == old.epoch) dagr_index_put_(x, old.slots[i].hash, old.slots[i].entry);
    }
    dagr_release(a, old.slots);
  }
  dagr_index_put_(x, hash, entry);
  x->used++;
  return true;
}

static inline void dagr_index_clear(dagr_index *x) {
  x->used = 0;
  if (++x->epoch == 0) { /* wrapped: no stale slot may look current */
    for (size_t i = 0; i < x->cap; i++) x->slots[i].epoch = 0;
    x->epoch = 1;
  }
}

static inline void dagr_index_free(dagr_index *x, const dagr_allocator *a) {
  dagr_release(a, x->slots);
  *x = dagr_index_empty();
}

/* ── References to stored nodes ────────────────────────────────────────────────────
 * A stored node — its offset — or, for a node still being stored (an ancestor on the path a cycle
 * leads back to), a PENDING reference: a pointer to it is written as a placeholder and patched when
 * the node is finished (`dagr_gw_finish`). */

static const uint32_t dagr_ref_resolved = 0xffffffffu;
static const uint32_t dagr_ref_nil = 0xfffffffeu;

typedef struct dagr_node_ref {
  size_t off;
  uint32_t pending; /* the in-flight node's entry; dagr_ref_resolved; dagr_ref_nil: no node */
} dagr_node_ref;

static inline dagr_node_ref dagr_node_ref_at(size_t off) {
  dagr_node_ref r;
  r.off = off;
  r.pending = dagr_ref_resolved;
  return r;
}

/** No node: a nil element of a node array with optionals. */
static inline dagr_node_ref dagr_node_ref_nil(void) {
  dagr_node_ref r;
  r.off = 0;
  r.pending = dagr_ref_nil;
  return r;
}

/* What a union FIELD's first pass stored, for its slot to point at or hold: an inline VALUE is
 * `width` bytes of `bits`; a FORWARD pointer targets `ref.off`; a NODE is a bidirectional pointer. */
typedef enum dagr_union_kind { dagr_union_value = 0, dagr_union_forward, dagr_union_node } dagr_union_kind;

typedef struct dagr_union_applied {
  uint64_t id;
  dagr_union_kind kind;
  uint8_t width;
  uint64_t bits;
  dagr_node_ref ref;
} dagr_union_applied;

/* One element of a regular / frozen union ARRAY: a value's bit pattern, an offset to content, or
 * an offset to a node; `present` false is a nil element. */
typedef struct dagr_union_elem {
  uint64_t id;
  dagr_union_kind kind;
  bool present;
  uint64_t val;
} dagr_union_elem;

/* ── The caches ────────────────────────────────────────────────────────────────────
 * What a graph serialization keeps beside the builder: the node dedup cache (a node stored once,
 * pointed at from every reference — the sharing and cycles of the graph), the vtable and string
 * dedup caches, the late bindings, and a stack of temporaries the generated array stores use.
 * Reusable: `dagr_graph_caches_reset` keeps every allocation.
 *
 * `max_size` is the largest buffer the producer expects; it fixes the width of a cycle's
 * placeholder pointer (2 MiB → 4 bytes, every other writer's default) and must match across
 * producers for byte identity. */

typedef struct dagr_node_entry {
  uint64_t type;
  uint64_t handle;
  size_t off;      /* valid once done */
  uint32_t binds;  /* the first late binding against it, or dagr_index_none */
  bool done;
} dagr_node_entry;

typedef struct dagr_vt_entry {
  size_t at;  /* into vt_pool */
  size_t len;
  size_t off;
} dagr_vt_entry;

typedef struct dagr_binding {
  uint32_t next;
  size_t at;         /* the placeholder: dagr_builder_written(at) is its first byte */
  size_t base;       /* a field pointer's cursor before the placeholder */
  size_t array_end;  /* a node array's slot base, or SIZE_MAX for a field pointer */
  size_t es;
} dagr_binding;

typedef struct dagr_graph_caches {
  dagr_allocator alloc;
  dagr_index node_index;
  dagr_node_entry *nodes;
  size_t n_nodes, cap_nodes;
  dagr_index vt_index;
  dagr_vt_entry *vts;
  size_t n_vts, cap_vts;
  uint32_t *vt_pool;
  size_t n_pool, cap_pool;
  dagr_index str_index;
  size_t *strs;
  size_t n_strs, cap_strs;
  dagr_binding *binds;
  size_t n_binds, cap_binds;
  size_t *norm;  /* a vtable's entries, normalized */
  size_t cap_norm;
  uint8_t *tmp;  /* the stack of temporaries (dagr_gw_tmp_*) */
  size_t n_tmp, cap_tmp;
  size_t reserve;
} dagr_graph_caches;

/** bits = bitlen(max_size) + 3; the width is the power of two of bytes that holds them, at
 * least 2 — exactly the Swift / Rust `with_max_size` rule. */
static inline size_t dagr_reserve_width(size_t max_size) {
  size_t bitlen = 0;
  for (size_t v = max_size; v != 0; v >>= 1) bitlen++;
  const size_t bytes = (bitlen + 3 + 7) / 8;
  size_t w = 1;
  while (w < bytes) w <<= 1;
  return w < 2 ? 2 : w;
}

static inline dagr_graph_caches dagr_graph_caches_init(size_t max_size, dagr_allocator alloc) {
  dagr_graph_caches c;
  memset(&c, 0, sizeof c);
  c.alloc = alloc;
  c.node_index = dagr_index_empty();
  c.vt_index = dagr_index_empty();
  c.str_index = dagr_index_empty();
  c.reserve = dagr_reserve_width(max_size);
  return c;
}

/** Caches for buffers up to 2 MiB (the default every writer uses), over malloc. */
static inline dagr_graph_caches dagr_graph_caches_default(void) {
  return dagr_graph_caches_init(2u * 1024u * 1024u, dagr_default_allocator());
}

static inline void dagr_graph_caches_reset(dagr_graph_caches *c) {
  dagr_index_clear(&c->node_index);
  dagr_index_clear(&c->vt_index);
  dagr_index_clear(&c->str_index);
  c->n_nodes = 0;
  c->n_vts = 0;
  c->n_pool = 0;
  c->n_strs = 0;
  c->n_binds = 0;
  c->n_tmp = 0;
}

static inline void dagr_graph_caches_free(dagr_graph_caches *c) {
  const dagr_allocator a = c->alloc;
  dagr_index_free(&c->node_index, &a);
  dagr_index_free(&c->vt_index, &a);
  dagr_index_free(&c->str_index, &a);
  dagr_release(&a, c->nodes);
  dagr_release(&a, c->vts);
  dagr_release(&a, c->vt_pool);
  dagr_release(&a, c->strs);
  dagr_release(&a, c->binds);
  dagr_release(&a, c->norm);
  dagr_release(&a, c->tmp);
  const size_t reserve = c->reserve;
  *c = dagr_graph_caches_init(0, a);
  c->reserve = reserve;
}

/* ── The graph writer ──────────────────────────────────────────────────────────────
 * A builder and its caches, threaded through the generated node stores. */

typedef struct dagr_graph_writer {
  dagr_builder *b;
  dagr_graph_caches *c;
} dagr_graph_writer;

static inline dagr_graph_writer dagr_graph_writer_of(dagr_builder *b, dagr_graph_caches *c) {
  dagr_graph_writer w;
  w.b = b;
  w.c = c;
  return w;
}

static inline bool dagr_gw_ok(const dagr_graph_writer *w) { return w->b->status == dagr_ok; }

/** A cache that cannot grow: the serialization fails, sticky. */
static inline void dagr_gw_oom(dagr_graph_writer *w) { dagr_builder_fail(w->b, dagr_out_of_memory); }

static inline uint64_t dagr_node_hash(uint64_t type, uint64_t handle) {
  return dagr_mix(handle ^ dagr_mix(type + UINT64_C(0x9e3779b97f4a7c15)));
}

static inline uint32_t dagr_gw_find_node(const dagr_graph_writer *w, uint64_t h, uint64_t type, uint64_t handle) {
  size_t i = dagr_index_first(&w->c->node_index, h);
  for (uint32_t e; (e = dagr_index_next(&w->c->node_index, h, &i)) != dagr_index_none;) {
    if (w->c->nodes[e].type == type && w->c->nodes[e].handle == handle) return e;
  }
  return dagr_index_none;
}

static inline uint32_t dagr_gw_add_node(dagr_graph_writer *w, uint64_t h, dagr_node_entry n) {
  dagr_graph_caches *c = w->c;
  dagr_node_entry *nodes = (dagr_node_entry *)dagr_grow(&c->alloc, c->nodes, &c->cap_nodes, c->n_nodes + 1, sizeof *nodes);
  if (nodes == NULL || c->n_nodes >= dagr_ref_nil) {
    dagr_gw_oom(w);
    return dagr_index_none;
  }
  c->nodes = nodes;
  const uint32_t entry = (uint32_t)c->n_nodes;
  if (!dagr_index_insert(&c->node_index, &c->alloc, h, entry)) {
    dagr_gw_oom(w);
    return dagr_index_none;
  }
  c->nodes[c->n_nodes++] = n;
  return entry;
}

/* What `dagr_gw_begin` found: a stored node (`done`, `ref` resolved), an ancestor still being
 * stored (`done`, `ref` pending — a cycle), or a node to store now (`entry` names it for
 * `dagr_gw_finish`). */
typedef struct dagr_begun {
  bool done;
  dagr_node_ref ref;
  uint32_t entry;
} dagr_begun;

/** Starts storing the regular or frozen node `handle` of node type `type`. */
static inline dagr_begun dagr_gw_begin(dagr_graph_writer *w, uint64_t type, uint64_t handle) {
  dagr_begun out;
  const uint64_t h = dagr_node_hash(type, handle);
  const uint32_t e = dagr_gw_find_node(w, h, type, handle);
  if (e != dagr_index_none) {
    const dagr_node_entry *n = &w->c->nodes[e];
    out.done = true;
    out.ref = n->done ? dagr_node_ref_at(n->off) : dagr_node_ref_at(0);
    if (!n->done) out.ref.pending = e;
    out.entry = e;
    return out;
  }
  dagr_node_entry n;
  n.type = type;
  n.handle = handle;
  n.off = 0;
  n.binds = dagr_index_none;
  n.done = false;
  out.entry = dagr_gw_add_node(w, h, n);
  /* a cache that cannot grow: report the node done, so that nothing recurses into it */
  out.done = out.entry == dagr_index_none;
  out.ref = dagr_node_ref_at(0);
  return out;
}

/** The node `entry` is stored at `off`: every placeholder written against it is patched, and
 * later references find it. */
static inline dagr_node_ref dagr_gw_finish(dagr_graph_writer *w, uint32_t entry, size_t off) {
  if (entry == dagr_index_none) return dagr_node_ref_at(off);
  dagr_node_entry *n = &w->c->nodes[entry];
  n->off = off;
  n->done = true;
  for (uint32_t i = n->binds; i != dagr_index_none; i = w->c->binds[i].next) {
    const dagr_binding *bd = &w->c->binds[i];
    uint8_t *p = dagr_builder_written(w->b, bd->at);
    if (p == NULL) continue; /* the builder failed: nothing left to patch */
    if (bd->array_end != SIZE_MAX) {
      /* a node array's slot: the raw two's-complement distance, + 1 */
      dagr_put_le(p, (uint64_t)bd->array_end - (uint64_t)off + 1u, bd->es);
    } else {
      /* a field pointer: a ZigZag V62 at the reserved width */
      const int64_t d = (int64_t)bd->base - (int64_t)off;
      const uint64_t wc = bd->es == 2 ? 1u : bd->es == 4 ? 2u : 3u;
      dagr_put_le(p, (dagr_zigzag_encode(d) << 2) | wc, bd->es);
    }
  }
  n->binds = dagr_index_none;
  return dagr_node_ref_at(off);
}

/** Whether the packed node `handle` is already stored (a packed node is a tree: nothing in
 * flight), and where. */
static inline bool dagr_gw_cached(const dagr_graph_writer *w, uint64_t type, uint64_t handle, size_t *off) {
  const uint32_t e = dagr_gw_find_node(w, dagr_node_hash(type, handle), type, handle);
  if (e == dagr_index_none || !w->c->nodes[e].done) return false;
  *off = w->c->nodes[e].off;
  return true;
}

/** Registers a packed node stored at `off` — only a node DECLARED packed: a regular or frozen
 * node a packed parent inlines is a private copy (spec 07 §5.1). A node inlined again replaces the
 * earlier copy: a later pointer reaches the most recent one, as in every other writer. */
static inline void dagr_gw_cache(dagr_graph_writer *w, uint64_t type, uint64_t handle, size_t off) {
  const uint64_t h = dagr_node_hash(type, handle);
  const uint32_t e = dagr_gw_find_node(w, h, type, handle);
  if (e != dagr_index_none) {
    w->c->nodes[e].off = off;
    return;
  }
  dagr_node_entry n;
  n.type = type;
  n.handle = handle;
  n.off = off;
  n.binds = dagr_index_none;
  n.done = true;
  (void)dagr_gw_add_node(w, h, n);
}

static inline void dagr_gw_bind(dagr_graph_writer *w, uint32_t entry, size_t at, size_t base, size_t array_end, size_t es) {
  if (!dagr_gw_ok(w)) return;
  dagr_graph_caches *c = w->c;
  dagr_binding *binds = (dagr_binding *)dagr_grow(&c->alloc, c->binds, &c->cap_binds, c->n_binds + 1, sizeof *binds);
  if (binds == NULL) {
    dagr_gw_oom(w);
    return;
  }
  c->binds = binds;
  dagr_binding *bd = &c->binds[c->n_binds];
  bd->next = c->nodes[entry].binds;
  bd->at = at;
  bd->base = base;
  bd->array_end = array_end;
  bd->es = es;
  c->nodes[entry].binds = (uint32_t)c->n_binds++;
}

/* ── Pointers ──────────────────────────────────────────────────────────────────── */

/** A V62 of `value`, at least `min_code` wide (0 → 1 byte … 3 → 8 bytes). */
static inline void dagr_gw_store_v62(dagr_graph_writer *w, uint64_t value, unsigned min_code) {
  if (value < (UINT64_C(1) << 6) && min_code == 0) {
    dagr_store_u8(w->b, (uint8_t)(value << 2));
  } else if (value < (UINT64_C(1) << 14) && min_code <= 1) {
    dagr_store_fixed(w->b, (value << 2) | (min_code > 1 ? min_code : 1u), 2);
  } else if (value < (UINT64_C(1) << 30) && min_code <= 2) {
    dagr_store_fixed(w->b, (value << 2) | (min_code > 2 ? min_code : 2u), 4);
  } else if (value < (UINT64_C(1) << 62)) {
    dagr_store_fixed(w->b, (value << 2) | 3u, 8);
  } else {
    dagr_builder_fail(w->b, dagr_invalid_value);
  }
}

/** A forward pointer to the content stored at `off`. */
static inline void dagr_gw_store_forward_pointer(dagr_graph_writer *w, size_t off) {
  dagr_gw_store_v62(w, (uint64_t)(w->b->cursor - off), 0);
}

/** A bidirectional pointer to a node: ZigZag V62 of the distance, or — to a node in flight — a
 * placeholder of the reserved width, patched by `dagr_gw_finish`. */
static inline void dagr_gw_store_bidirectional_pointer(dagr_graph_writer *w, dagr_node_ref ref) {
  const size_t base = w->b->cursor;
  if (ref.pending == dagr_ref_resolved) {
    dagr_gw_store_v62(w, dagr_zigzag_encode((int64_t)base - (int64_t)ref.off), 0);
    return;
  }
  dagr_store_zeros(w->b, w->c->reserve);
  dagr_gw_bind(w, ref.pending, w->b->cursor, base, SIZE_MAX, w->c->reserve);
}

/* ── utf8 / data content ───────────────────────────────────────────────────────── */

/** Whether the `[LEB count][bytes]` stored at `off` holds exactly `n` bytes at `p`. */
static inline bool dagr_gw_stored_blob_is(dagr_graph_writer *w, size_t off, const uint8_t *p, size_t n) {
  const uint8_t *s = dagr_builder_written(w->b, off);
  if (s == NULL) return false;
  uint8_t expect[10];
  const size_t ln = dagr_put_leb(expect, (uint64_t)n);
  /* the length prefixes first: a stored blob of another length differs there */
  if (off < ln || memcmp(s, expect, ln) != 0 || off - ln < n) return false;
  return n == 0 || memcmp(s + ln, p, n) == 0;
}

/** `[LEB count][bytes]`, the same string stored once (spec 07 §5): its offset. */
static inline size_t dagr_gw_utf8(dagr_graph_writer *w, dagr_str s) {
  const uint8_t *p = (const uint8_t *)(const void *)s.ptr;
  const uint64_t h = dagr_hash_bytes(p, s.len);
  size_t i = dagr_index_first(&w->c->str_index, h);
  for (uint32_t e; (e = dagr_index_next(&w->c->str_index, h, &i)) != dagr_index_none;) {
    if (dagr_gw_stored_blob_is(w, w->c->strs[e], p, s.len)) return w->c->strs[e];
  }
  dagr_store_blob(w->b, p, s.len);
  const size_t off = w->b->cursor;
  if (dagr_gw_ok(w)) {
    dagr_graph_caches *c = w->c;
    size_t *strs = (size_t *)dagr_grow(&c->alloc, c->strs, &c->cap_strs, c->n_strs + 1, sizeof *strs);
    if (strs == NULL || !dagr_index_insert(&c->str_index, &c->alloc, h, (uint32_t)c->n_strs)) {
      if (strs != NULL) c->strs = strs;
      dagr_gw_oom(w);
      return off;
    }
    c->strs = strs;
    c->strs[c->n_strs++] = off;
  }
  return off;
}

/** `[LEB count][bytes]` — data is never deduplicated. */
static inline size_t dagr_gw_data(dagr_graph_writer *w, dagr_bytes d) {
  dagr_store_blob(w->b, d.ptr, d.len);
  return w->b->cursor;
}

/* ── The vtable (regular nodes, spec 05) ───────────────────────────────────────── */

/** Stores the vtable of a node whose field slots were stored at `offsets` (forward index order;
 * 0 = absent), deduplicated, and returns the node's offset. A slot more than 65535 bytes before
 * the header cannot be written: `dagr_invalid_value`. */
static inline size_t dagr_gw_store_vtable(dagr_graph_writer *w, const size_t *offsets, size_t n) {
  dagr_graph_caches *c = w->c;
  size_t *norm = (size_t *)dagr_grow(&c->alloc, c->norm, &c->cap_norm, n + 1, sizeof *norm);
  if (norm == NULL) {
    dagr_gw_oom(w);
    return w->b->cursor;
  }
  c->norm = norm;
  const size_t cur = w->b->cursor;
  bool wide = false;
  for (size_t k = 0; k < n; k++) {
    const size_t v = offsets[k] == 0 ? 0 : cur - offsets[k] + 1;
    if (v > 0xffffu) {
      dagr_builder_fail(w->b, dagr_invalid_value);
      return w->b->cursor;
    }
    wide = wide || v > 0xffu;
    norm[k] = v;
  }
  uint64_t h = wide ? 0x77u : 0x6eu;
  for (size_t k = 0; k < n; k++) h = dagr_mix(h ^ (uint64_t)norm[k]);
  size_t i = dagr_index_first(&c->vt_index, h);
  for (uint32_t e; (e = dagr_index_next(&c->vt_index, h, &i)) != dagr_index_none;) {
    const dagr_vt_entry *vt = &c->vts[e];
    if (vt->len != n) continue;
    bool same = true;
    for (size_t k = 0; k < n && same; k++) same = c->vt_pool[vt->at + k] == norm[k];
    if (same) {
      /* a vtable already stored: an EVEN marker, the distance to it doubled */
      dagr_store_leb(w->b, (uint64_t)(w->b->cursor - vt->off) << 1);
      return w->b->cursor;
    }
  }
  const uint64_t cnt = wide ? ((uint64_t)n << 1) | 1u : (uint64_t)n << 1;
  const size_t size = (!wide && cnt == 0) ? 0 : dagr_leb_length(cnt) + n * (wide ? 2u : 1u);
  dagr_store_leb(w->b, size == 0 ? 0 : (((uint64_t)size - 1u) << 1) | 1u);
  const size_t result = w->b->cursor;
  const size_t es = wide ? 2 : 1;
  if (n != 0) {
    uint8_t *p = dagr_claim(w->b, n * es);
    if (p != NULL) {
      for (size_t k = 0; k < n; k++) dagr_put_le(p + k * es, (uint64_t)norm[k], es);
    }
  }
  dagr_store_leb(w->b, cnt);
  if (dagr_gw_ok(w)) {
    dagr_vt_entry *vts = (dagr_vt_entry *)dagr_grow(&c->alloc, c->vts, &c->cap_vts, c->n_vts + 1, sizeof *vts);
    if (vts != NULL) c->vts = vts;
    uint32_t *pool = (uint32_t *)dagr_grow(&c->alloc, c->vt_pool, &c->cap_pool, c->n_pool + n + 1, sizeof *pool);
    if (pool != NULL) c->vt_pool = pool;
    if (vts == NULL || pool == NULL || !dagr_index_insert(&c->vt_index, &c->alloc, h, (uint32_t)c->n_vts)) {
      dagr_gw_oom(w);
      return result;
    }
    c->vts[c->n_vts].at = c->n_pool;
    c->vts[c->n_vts].len = n;
    c->vts[c->n_vts].off = w->b->cursor;
    c->n_vts++;
    for (size_t k = 0; k < n; k++) c->vt_pool[c->n_pool++] = (uint32_t)norm[k];
  }
  return result;
}

/* ── The stack of temporaries ──────────────────────────────────────────────────────
 * An array's elements are stored last first, each returning an offset, a node reference or a
 * union slot, which the array's table then holds. Element stores recurse (an element node holds
 * arrays), so the temporaries are a STACK in the caches, addressed by a base the push returns —
 * an index, not a pointer: a nested push may move the stack. */

/** Room for `n` items of `size` bytes, zeroed: their base, or SIZE_MAX when it cannot grow (the
 * builder then fails, and every tmp function with that base does nothing). */
static inline size_t dagr_gw_tmp_push(dagr_graph_writer *w, size_t n, size_t size) {
  dagr_graph_caches *c = w->c;
  if (!dagr_gw_ok(w) || (size != 0 && n > SIZE_MAX / size)) {
    dagr_gw_oom(w);
    return SIZE_MAX;
  }
  const size_t bytes = n * size;
  uint8_t *tmp = (uint8_t *)dagr_grow(&c->alloc, c->tmp, &c->cap_tmp, c->n_tmp + bytes + 1, 1);
  if (tmp == NULL) {
    dagr_gw_oom(w);
    return SIZE_MAX;
  }
  c->tmp = tmp;
  const size_t base = c->n_tmp;
  if (bytes != 0) memset(c->tmp + base, 0, bytes);
  c->n_tmp += bytes;
  return base;
}

/** Releases what the push at `base` took (and everything pushed after it). */
static inline void dagr_gw_tmp_pop(dagr_graph_writer *w, size_t base) {
  if (base != SIZE_MAX && base <= w->c->n_tmp) w->c->n_tmp = base;
}

static inline void dagr_gw_tmp_set_off(dagr_graph_writer *w, size_t base, size_t i, size_t off) {
  if (base != SIZE_MAX) memcpy(w->c->tmp + base + i * sizeof off, &off, sizeof off);
}
static inline size_t dagr_gw_tmp_off(const dagr_graph_writer *w, size_t base, size_t i) {
  size_t off = 0;
  if (base != SIZE_MAX) memcpy(&off, w->c->tmp + base + i * sizeof off, sizeof off);
  return off;
}
static inline void dagr_gw_tmp_set_ref(dagr_graph_writer *w, size_t base, size_t i, dagr_node_ref r) {
  if (base != SIZE_MAX) memcpy(w->c->tmp + base + i * sizeof r, &r, sizeof r);
}
static inline dagr_node_ref dagr_gw_tmp_ref(const dagr_graph_writer *w, size_t base, size_t i) {
  dagr_node_ref r = dagr_node_ref_nil();
  if (base != SIZE_MAX) memcpy(&r, w->c->tmp + base + i * sizeof r, sizeof r);
  return r;
}
static inline void dagr_gw_tmp_set_elem(dagr_graph_writer *w, size_t base, size_t i, dagr_union_elem e) {
  if (base != SIZE_MAX) memcpy(w->c->tmp + base + i * sizeof e, &e, sizeof e);
}
static inline dagr_union_elem dagr_gw_tmp_elem(const dagr_graph_writer *w, size_t base, size_t i) {
  dagr_union_elem e;
  memset(&e, 0, sizeof e);
  if (base != SIZE_MAX) memcpy(&e, w->c->tmp + base + i * sizeof e, sizeof e);
  return e;
}

/* ── Arrays of node references (spec 04 §4.7) ──────────────────────────────────── */

static inline unsigned dagr_unsigned_width_code(uint64_t v) {
  return v <= 0xffu ? 0u : v <= 0xffffu ? 1u : v <= 0xffffffffu ? 2u : 3u;
}
static inline unsigned dagr_signed_width_code(int64_t d) {
  return (d >= -128 && d <= 127) ? 0u : (d >= -32768 && d <= 32767) ? 1u
                                        : (d >= -2147483647 - 1 && d <= 2147483647) ? 2u : 3u;
}

/** `[LEB (count << 2) | wc][count × es signed slots]` over the `n` element references at tmp
 * `base` (a pending one is patched by `dagr_gw_finish`; a nil one is slot 0). Returns the
 * array's offset. */
static inline size_t dagr_gw_store_node_ref_array(dagr_graph_writer *w, size_t base, size_t n) {
  const size_t cur = w->b->cursor;
  unsigned wc = 0;
  bool pending = false;
  for (size_t i = 0; i < n; i++) {
    const dagr_node_ref r = dagr_gw_tmp_ref(w, base, i);
    if (r.pending == dagr_ref_nil) continue;
    if (r.pending == dagr_ref_resolved) {
      const unsigned c = dagr_signed_width_code((int64_t)(cur - r.off + 1));
      if (c > wc) wc = c;
    } else {
      pending = true;
    }
  }
  const unsigned reserve_wc = w->c->reserve == 2 ? 1u : w->c->reserve == 4 ? 2u : 3u;
  if (pending && wc < reserve_wc) wc = reserve_wc;
  const size_t es = (size_t)1 << wc;
  if (n != 0) {
    uint8_t *p = dagr_claim(w->b, n * es);
    if (p != NULL) {
      const size_t first = w->b->cursor;
      for (size_t i = 0; i < n; i++) {
        const dagr_node_ref r = dagr_gw_tmp_ref(w, base, i);
        const uint64_t v = r.pending == dagr_ref_resolved ? (uint64_t)(cur - r.off + 1) : 0;
        dagr_put_le(p + i * es, v, es);
        if (r.pending != dagr_ref_resolved && r.pending != dagr_ref_nil) {
          dagr_gw_bind(w, r.pending, first - i * es, 0, cur, es);
        }
      }
    }
  }
  dagr_store_leb(w->b, ((uint64_t)n << 2) | wc);
  return w->b->cursor;
}

/** A pointer table `[LEB (count << 2) | wc][count × es unsigned slots]` over the `n` utf8 / data
 * element offsets at tmp `base` (0 = nil). Returns the table's offset. */
static inline size_t dagr_gw_store_ptr_table(dagr_graph_writer *w, size_t base, size_t n) {
  const size_t cur = w->b->cursor;
  unsigned wc = 0;
  for (size_t i = 0; i < n; i++) {
    const size_t off = dagr_gw_tmp_off(w, base, i);
    if (off == 0) continue;
    const unsigned c = dagr_unsigned_width_code((uint64_t)(cur - off + 1));
    if (c > wc) wc = c;
  }
  const size_t es = (size_t)1 << wc;
  if (n != 0) {
    uint8_t *p = dagr_claim(w->b, n * es);
    if (p != NULL) {
      for (size_t i = 0; i < n; i++) {
        const size_t off = dagr_gw_tmp_off(w, base, i);
        dagr_put_le(p + i * es, off == 0 ? 0 : (uint64_t)(cur - off + 1), es);
      }
    }
  }
  dagr_store_leb(w->b, ((uint64_t)n << 2) | wc);
  return w->b->cursor;
}

/* ── Unions in regular / frozen nodes (spec 04 §4.9) ───────────────────────────── */

static inline void dagr_gw_emit_(dagr_graph_writer *w, const dagr_union_applied *a) {
  switch (a->kind) {
    case dagr_union_value: {
      uint8_t *p = dagr_claim(w->b, a->width);
      if (p != NULL) dagr_put_le(p, a->bits, a->width);
      break;
    }
    case dagr_union_forward:
      dagr_gw_store_forward_pointer(w, a->ref.off);
      break;
    case dagr_union_node:
      dagr_gw_store_bidirectional_pointer(w, a->ref);
      break;
  }
}

/** The slot of a union FIELD: the value or pointer, then `LEB (id << 2) | wc`. Its offset. */
static inline size_t dagr_gw_store_union_slot(dagr_graph_writer *w, const dagr_union_applied *a) {
  const size_t before = w->b->cursor;
  dagr_gw_emit_(w, a);
  const size_t n = w->b->cursor - before;
  const uint64_t wc = n == 1 ? 0u : n == 2 ? 1u : n == 4 ? 2u : 3u;
  dagr_store_leb(w->b, (a->id << 2) | wc);
  return w->b->cursor;
}

/** A NESTED union value (a union variant of a union): `LEB id << 2`, no width code. */
static inline size_t dagr_gw_store_nested_union_slot(dagr_graph_writer *w, const dagr_union_applied *a) {
  dagr_gw_emit_(w, a);
  dagr_store_leb(w->b, a->id << 2);
  return w->b->cursor;
}

static inline uint64_t dagr_union_slot_of_(const dagr_union_elem *e, size_t content_end) {
  switch (e->kind) {
    case dagr_union_value: return e->val;
    case dagr_union_forward: return (uint64_t)(content_end - (size_t)e->val);
    case dagr_union_node: return (uint64_t)(content_end - (size_t)e->val) << 1;
  }
  return 0;
}

/** A union ARRAY `[LEB (count << 2) | wc][type ids][nil bitset?][count slots]` over the `n`
 * elements at tmp `base`, their content already stored. `bits_per`: a type id's width (1, 2, 4,
 * or 8: a byte each). Its offset. */
static inline size_t dagr_gw_store_union_array(dagr_graph_writer *w, size_t base, size_t n, unsigned bits_per, bool opt) {
  const size_t content_end = w->b->cursor;
  unsigned wc = 0;
  for (size_t i = 0; i < n; i++) {
    const dagr_union_elem e = dagr_gw_tmp_elem(w, base, i);
    if (!e.present) continue;
    const unsigned c = dagr_unsigned_width_code(dagr_union_slot_of_(&e, content_end));
    if (c > wc) wc = c;
  }
  const size_t es = (size_t)1 << wc;
  const size_t nb = opt ? (n + 7) / 8 : 0;
  const size_t tb = bits_per < 8 ? (n * bits_per + 7) / 8 : n;
  const size_t total = n * es + nb + tb;
  if (total != 0) {
    uint8_t *p = dagr_claim(w->b, total);
    if (p != NULL) {
      memset(p, 0, total);
      uint8_t *types = p;
      uint8_t *nils = p + tb;
      uint8_t *slots = nils + nb;
      const size_t per = bits_per < 8 ? 8 / bits_per : 1;
      const uint64_t mask = bits_per < 8 ? (UINT64_C(1) << bits_per) - 1u : 0xffu;
      for (size_t i = 0; i < n; i++) {
        const dagr_union_elem e = dagr_gw_tmp_elem(w, base, i);
        if (!e.present) {
          if (opt) dagr_set_bit(nils, i);
          continue;
        }
        dagr_put_le(slots + i * es, dagr_union_slot_of_(&e, content_end), es);
        if (bits_per < 8) {
          types[i / per] = (uint8_t)(types[i / per] | ((e.id & mask) << ((i % per) * bits_per)));
        } else {
          types[i] = (uint8_t)e.id;
        }
      }
    }
  }
  dagr_store_leb(w->b, ((uint64_t)n << 2) | wc);
  return w->b->cursor;
}

/** The headers of a packed union array, its payloads already stored: `[headers][nil bitset,
 * LEB header size]?[LEB count]` then the block length counted from `before`. The `n` headers are
 * at tmp `base` as `dagr_union_elem`s (`id` the header word, `present`). */
static inline void dagr_gw_store_packed_union_headers(dagr_graph_writer *w, size_t base, size_t n, bool opt, size_t before) {
  const size_t at = w->b->cursor;
  for (size_t i = n; i-- > 0;) {
    const dagr_union_elem e = dagr_gw_tmp_elem(w, base, i);
    if (e.present) dagr_store_leb(w->b, e.id);
  }
  if (opt) {
    dagr_store_leb(w->b, (uint64_t)(w->b->cursor - at));
    const size_t nb = (n + 7) / 8;
    if (nb != 0) {
      uint8_t *p = dagr_claim(w->b, nb);
      if (p != NULL) {
        memset(p, 0, nb);
        for (size_t i = 0; i < n; i++) {
          if (!dagr_gw_tmp_elem(w, base, i).present) dagr_set_bit(p, i);
        }
      }
    }
  }
  dagr_store_leb(w->b, (uint64_t)n);
  dagr_store_leb(w->b, (uint64_t)(w->b->cursor - before));
}

/* ── Regular / frozen arrays of values (spec 04) ──────────────────────────────────
 * `elems` holds `n` elements of `size` bytes in native form; `bits(elems, i)` is what the wire
 * holds for one — every scalar kind but f16 / bf16 (held as float) is its own bits. */

/** One element's bits: an integer or f32 / f64 element of `size` bytes, as stored. */
static inline uint64_t dagr_native_bits(const void *elems, size_t i, size_t size) {
  return dagr_elem_bits(elems, i, size);
}

/** `[LEB count][elements]`, each `width` bytes little-endian (`half` 1: f16 / bf16 from floats,
 * `half` 2: bf16). Returns its offset. */
static inline size_t dagr_store_fixed_array(dagr_builder *b, const void *elems, size_t n, size_t width, int half) {
  if (n != 0) {
    uint8_t *p = dagr_claim(b, n * width);
    if (p != NULL) {
      for (size_t i = 0; i < n; i++) {
        const uint64_t v = half != 0 ? dagr_half_bits(((const float *)elems)[i], half == 2)
                                     : dagr_native_bits(elems, i, width);
        dagr_put_le(p + i * width, v, width);
      }
    }
  }
  dagr_store_leb(b, (uint64_t)n);
  return b->cursor;
}

/** `[LEB count][nil bitset][count slots]` — an absent element is `width` zero bytes (the regular
 * array with optionals is not compacted). */
static inline size_t dagr_store_fixed_opt_array(dagr_builder *b, const void *elems, const bool *present, size_t n,
                                                size_t width, int half) {
  const size_t nb = (n + 7) / 8;
  if (n != 0) {
    uint8_t *p = dagr_claim(b, nb + n * width);
    if (p != NULL) {
      memset(p, 0, nb + n * width);
      for (size_t i = 0; i < n; i++) {
        if (!dagr_is_present(present, i)) {
          dagr_set_bit(p, i);
          continue;
        }
        const uint64_t v = half != 0 ? dagr_half_bits(((const float *)elems)[i], half == 2)
                                     : dagr_native_bits(elems, i, width);
        dagr_put_le(p + nb + i * width, v, width);
      }
    }
  }
  dagr_store_leb(b, (uint64_t)n);
  return b->cursor;
}

/** `[LEB count][bitset]`. */
static inline size_t dagr_store_bool_array(dagr_builder *b, const bool *elems, size_t n) {
  const size_t nb = (n + 7) / 8;
  if (nb != 0) {
    uint8_t *p = dagr_claim(b, nb);
    if (p != NULL) {
      memset(p, 0, nb);
      for (size_t i = 0; i < n; i++) {
        if (elems[i]) dagr_set_bit(p, i);
      }
    }
  }
  dagr_store_leb(b, (uint64_t)n);
  return b->cursor;
}

/** `[LEB count][nil bitset][value bitset]`, both indexed by element. */
static inline size_t dagr_store_bool_opt_array(dagr_builder *b, const bool *elems, const bool *present, size_t n) {
  const size_t nb = (n + 7) / 8;
  if (nb != 0) {
    uint8_t *p = dagr_claim(b, 2 * nb);
    if (p != NULL) {
      memset(p, 0, 2 * nb);
      for (size_t i = 0; i < n; i++) {
        if (!dagr_is_present(present, i)) dagr_set_bit(p, i);
        else if (elems[i]) dagr_set_bit(p + nb, i);
      }
    }
  }
  dagr_store_leb(b, (uint64_t)n);
  return b->cursor;
}

/** A sub-byte enum array `[LEB count][nil bitset?][packed bits]` over `width`-byte backing values
 * (`present` NULL: no nil bitset; an absent element's bits zero — not compacted). */
static inline size_t dagr_store_bit_enum_array(dagr_builder *b, const void *elems, const bool *present, size_t n,
                                               size_t width, unsigned bits) {
  const size_t nb = present != NULL ? (n + 7) / 8 : 0;
  const size_t vb = (n * bits + 7) / 8;
  if (nb + vb != 0) {
    uint8_t *p = dagr_claim(b, nb + vb);
    if (p != NULL) {
      memset(p, 0, nb + vb);
      for (size_t i = 0; i < n; i++) {
        if (!dagr_is_present(present, i)) {
          dagr_set_bit(p, i);
          continue;
        }
        const size_t bit = i * bits;
        const uint64_t v = dagr_native_bits(elems, i, width) & ((UINT64_C(1) << bits) - 1u);
        p[nb + (bit >> 3)] = (uint8_t)(p[nb + (bit >> 3)] | (v << (bit & 7u)));
      }
    }
  }
  dagr_store_leb(b, (uint64_t)n);
  return b->cursor;
}

/* ── aligned(N) arrays and blobs (spec 12 §11) ─────────────────────────────────── */

/** Zero bytes before (in store order: after) a payload of `payload` bytes, so that its first byte
 * lands on a multiple of `n` counted from the record's end. */
static inline void dagr_store_aligned_pad(dagr_builder *b, size_t payload, size_t n) {
  dagr_store_zeros(b, (0u - (b->cursor + payload)) & (n - 1));
}

/** An aligned fixed-width array: the pad, the elements, `LEB count`. Its offset. */
static inline size_t dagr_store_aligned_array(dagr_builder *b, const void *elems, size_t n, size_t width, int half,
                                              size_t align) {
  dagr_store_aligned_pad(b, n * width, align);
  return dagr_store_fixed_array(b, elems, n, width, half);
}

/** An aligned utf8 / data payload — never deduplicated, its position matters. */
static inline size_t dagr_store_aligned_bytes(dagr_builder *b, const void *src, size_t n, size_t align) {
  dagr_store_aligned_pad(b, n, align);
  dagr_store_bytes(b, src, n);
  dagr_store_leb(b, (uint64_t)n);
  return b->cursor;
}

/* ── Restore: the nodes read so far ────────────────────────────────────────────────
 * What an arena restore threads: each node read so far, by type and buffer position, so that a
 * node met again — shared, or a cycle back to an ancestor — is the same node; and how deep the
 * walk may still descend (it recurses over the DATA, spec/41 §5). */

/** No node: a reference never set, or not restored. */
static const uint64_t dagr_no_handle = UINT64_MAX;

typedef struct dagr_seen_entry {
  uint64_t type;
  size_t pos;
  uint64_t handle;
} dagr_seen_entry;

/** A regular or frozen node reached by reference (spec/49 R1): allocated and registered, its
 * fields filled later by the restore's drain, not by a nested call. */
typedef struct dagr_seen_pending {
  uint64_t type;
  dagr_bytes buf;
  size_t pos;
  uint64_t handle;
} dagr_seen_pending;

typedef struct dagr_restore_seen {
  dagr_allocator alloc;
  dagr_index index;
  dagr_seen_entry *entries;
  size_t n, cap;
  dagr_seen_pending *pending;
  size_t pn, pcap;
  size_t depth_left, max_depth;
  dagr_status status;
} dagr_restore_seen;

static inline dagr_restore_seen dagr_restore_seen_init(size_t max_depth, dagr_allocator alloc) {
  dagr_restore_seen s;
  s.alloc = alloc;
  s.index = dagr_index_empty();
  s.entries = NULL;
  s.n = 0;
  s.cap = 0;
  s.pending = NULL;
  s.pn = 0;
  s.pcap = 0;
  s.depth_left = max_depth;
  s.max_depth = max_depth;
  s.status = dagr_ok;
  return s;
}

static inline void dagr_restore_seen_free(dagr_restore_seen *s) {
  dagr_index_free(&s->index, &s->alloc);
  dagr_release(&s->alloc, s->entries);
  dagr_release(&s->alloc, s->pending);
  s->entries = NULL;
  s->n = 0;
  s->cap = 0;
  s->pending = NULL;
  s->pn = 0;
  s->pcap = 0;
}

static inline void dagr_seen_fail(dagr_restore_seen *s, dagr_status st) {
  if (s->status == dagr_ok) s->status = st;
}

/** A utf8 value, checked (spec/49 U1): invalid text records `dagr_invalid_utf8`. */
static inline dagr_str dagr_seen_text(dagr_restore_seen *s, dagr_str x) {
  if (!dagr_valid_utf8(x)) dagr_seen_fail(s, dagr_invalid_utf8);
  return x;
}

/** Queues the fields of the node at (`buf`, `pos`), restored as `handle` (spec/49 R1). */
static inline void dagr_seen_later(dagr_restore_seen *s, uint64_t type, dagr_bytes buf, size_t pos, uint64_t handle) {
  dagr_seen_pending *p = (dagr_seen_pending *)dagr_grow(&s->alloc, s->pending, &s->pcap, s->pn + 1, sizeof *p);
  if (p == NULL) {
    dagr_seen_fail(s, dagr_out_of_memory);
    return;
  }
  s->pending = p;
  s->pending[s->pn].type = type;
  s->pending[s->pn].buf = buf;
  s->pending[s->pn].pos = pos;
  s->pending[s->pn].handle = handle;
  s->pn++;
}

/** The next queued node, while nothing has failed. */
static inline bool dagr_seen_next(dagr_restore_seen *s, dagr_seen_pending *out) {
  if (s->pn == 0 || s->status != dagr_ok) return false;
  *out = s->pending[--s->pn];
  return true;
}

/** A subtree reached by reference starts again at level 1 (spec/49 R2): the whole limit until
 * `dagr_seen_resume` gives the caller's depth back. */
static inline size_t dagr_seen_restart(dagr_restore_seen *s) {
  const size_t saved = s->depth_left;
  s->depth_left = s->max_depth;
  return saved;
}

static inline void dagr_seen_resume(dagr_restore_seen *s, size_t saved) { s->depth_left = saved; }

static inline uint64_t dagr_seen_hash(uint64_t type, size_t pos) {
  return dagr_mix((uint64_t)pos ^ dagr_mix(type ^ UINT64_C(0x5eed)));
}

/** The handle the node of `type` at `pos` was restored as, or dagr_no_handle. */
static inline uint64_t dagr_seen_find(const dagr_restore_seen *s, uint64_t type, size_t pos) {
  const uint64_t h = dagr_seen_hash(type, pos);
  size_t i = dagr_index_first(&s->index, h);
  for (uint32_t e; (e = dagr_index_next(&s->index, h, &i)) != dagr_index_none;) {
    if (s->entries[e].type == type && s->entries[e].pos == pos) return s->entries[e].handle;
  }
  return dagr_no_handle;
}

static inline void dagr_seen_add(dagr_restore_seen *s, uint64_t type, size_t pos, uint64_t handle) {
  dagr_seen_entry *e = (dagr_seen_entry *)dagr_grow(&s->alloc, s->entries, &s->cap, s->n + 1, sizeof *e);
  if (e == NULL || !dagr_index_insert(&s->index, &s->alloc, dagr_seen_hash(type, pos), (uint32_t)s->n)) {
    if (e != NULL) s->entries = e;
    dagr_seen_fail(s, dagr_out_of_memory);
    return;
  }
  s->entries = e;
  s->entries[s->n].type = type;
  s->entries[s->n].pos = pos;
  s->entries[s->n].handle = handle;
  s->n++;
}

/** One level of the walk: false — and `dagr_depth_exceeded` recorded — at the depth limit;
 * pair a true one with `dagr_seen_leave`. */
static inline bool dagr_seen_enter(dagr_restore_seen *s) {
  if (s->depth_left == 0) {
    dagr_seen_fail(s, dagr_depth_exceeded);
    return false;
  }
  s->depth_left--;
  return true;
}

static inline void dagr_seen_leave(dagr_restore_seen *s) { s->depth_left++; }

#endif /* DAGR_GRAPH_WRITER_H */
