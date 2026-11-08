/* dagr/shared_buffer.h — the SharedBuffer runtime (spec/20, spec/40; spec/44 §8.1): what a
 * generated overlay calls to read and write a fixed-layout region in place. A
 * transliteration of the C++ target's dagr/shared_buffer.hpp.
 *
 * A SharedBuffer is a region of BYTE_SIZE bytes laid out by the language-neutral manifest
 * (dagr/layout.py), so every target reads and writes the same bytes at the same offsets. A
 * generated overlay holds the region's base pointer and a node's offset and calls these
 * functions; it never touches memory itself (spec/44 §4).
 *
 *   - lengths and indices read from the region are CLAMPED to their capacity: a region
 *     shared with another process is not trusted to be well-formed;
 *   - atomics: the __atomic_* builtins of GCC and Clang on a naturally aligned 4- or 8-byte
 *     word (the layout places every atomic word so, relative to a REGION_ALIGN-aligned
 *     base); <stdatomic.h> through `_Atomic` casts where the builtins do not exist
 *     (spec/44 §7.1, O-C3 — written, not gated);
 *   - dagr_racy_copy: the seqlock's payload copy, every access a relaxed atomic — the copy
 *     races BY DESIGN (the counter decides afterwards whether it was torn), which is a data
 *     race unless every access is atomic. Same instructions, defined behaviour,
 *     ThreadSanitizer-clean.
 *
 * Core tier: no allocation, no container. The region is the caller's — mmap'd, static, or
 * malloc'd.
 */
#ifndef DAGR_SHARED_BUFFER_H
#define DAGR_SHARED_BUFFER_H

#include "sb_core.h"

#if !defined(__GNUC__) && !defined(__clang__)
#include <stdatomic.h>
#endif

/* ── Unsigned values of a given width (lengths, union tags) ─────────────────── */

static inline uint64_t dagr_sb_get_uint(const uint8_t *p, size_t at, size_t width) {
  switch (width) {
    case 1: return p[at];
    case 2: return dagr_sb_get_u16(p, at);
    case 4: return dagr_sb_get_u32(p, at);
    default: return dagr_sb_get_u64(p, at);
  }
}

static inline void dagr_sb_put_uint(uint8_t *p, size_t at, size_t width, uint64_t v) {
  switch (width) {
    case 1: p[at] = (uint8_t)v; break;
    case 2: dagr_sb_put_u16(p, at, (uint16_t)v); break;
    case 4: dagr_sb_put_u32(p, at, (uint32_t)v); break;
    default: dagr_sb_put_u64(p, at, v); break;
  }
}

/** A length stored in `width` bytes at `p + at`, clamped to `cap`. */
static inline size_t dagr_sb_len(const uint8_t *p, size_t at, size_t width, size_t cap) {
  const uint64_t n = dagr_sb_get_uint(p, at, width);
  return n > cap ? cap : (size_t)n;
}

/* ── Bits ───────────────────────────────────────────────────────────────────── */

static inline bool dagr_sb_bit(const uint8_t *p, size_t byte, unsigned bit) { return ((p[byte] >> bit) & 1u) != 0; }
static inline void dagr_sb_set_bit(uint8_t *p, size_t byte, unsigned bit) { p[byte] = (uint8_t)(p[byte] | (1u << bit)); }
static inline void dagr_sb_clear_bit(uint8_t *p, size_t byte, unsigned bit) {
  p[byte] = (uint8_t)(p[byte] & ~(1u << bit));
}
static inline void dagr_sb_put_bit(uint8_t *p, size_t byte, unsigned bit, bool v) {
  if (v) {
    dagr_sb_set_bit(p, byte, bit);
  } else {
    dagr_sb_clear_bit(p, byte, bit);
  }
}

/** Bit `i` of a bitset starting at byte `base` (bool arrays, presence bitsets). */
static inline bool dagr_sb_ibit(const uint8_t *p, size_t base, size_t i) {
  return dagr_sb_bit(p, base + (i >> 3), (unsigned)(i & 7u));
}
static inline void dagr_sb_set_ibit(uint8_t *p, size_t base, size_t i) { dagr_sb_set_bit(p, base + (i >> 3), (unsigned)(i & 7u)); }
static inline void dagr_sb_clear_ibit(uint8_t *p, size_t base, size_t i) {
  dagr_sb_clear_bit(p, base + (i >> 3), (unsigned)(i & 7u));
}
static inline void dagr_sb_put_ibit(uint8_t *p, size_t base, size_t i, bool v) {
  dagr_sb_put_bit(p, base + (i >> 3), (unsigned)(i & 7u), v);
}

/** `bits` bits at bit `bit` of byte `byte` (a sub-byte enum or tag; never crosses a byte). */
static inline unsigned dagr_sb_bits(const uint8_t *p, size_t byte, unsigned bit, unsigned bits) {
  return ((unsigned)p[byte] >> bit) & ((1u << bits) - 1u);
}
static inline void dagr_sb_put_bits(uint8_t *p, size_t byte, unsigned bit, unsigned bits, unsigned v) {
  const unsigned mask = (1u << bits) - 1u;
  p[byte] = (uint8_t)(((unsigned)p[byte] & ~(mask << bit)) | ((v & mask) << bit));
}

/** The `i`-th of an array of `bits`-wide elements starting at byte `base`. */
static inline unsigned dagr_sb_elem_bits(const uint8_t *p, size_t base, size_t i, unsigned bits) {
  const size_t bit = i * bits;
  return dagr_sb_bits(p, base + (bit >> 3), (unsigned)(bit & 7u), bits);
}
static inline void dagr_sb_put_elem_bits(uint8_t *p, size_t base, size_t i, unsigned bits, unsigned v) {
  const size_t bit = i * bits;
  dagr_sb_put_bits(p, base + (bit >> 3), (unsigned)(bit & 7u), bits, v);
}

/* ── Byte ranges ────────────────────────────────────────────────────────────── */

static inline void dagr_sb_zero(uint8_t *p, size_t at, size_t n) { memset(p + at, 0, n); }

/** `n` bytes at `p + at`, as a view of the region (valid as long as the region is). */
static inline dagr_bytes dagr_sb_view(const uint8_t *p, size_t at, size_t n) { return dagr_bytes_of(p + at, n); }
static inline dagr_str dagr_sb_text(const uint8_t *p, size_t at, size_t n) {
  return dagr_str_of((const char *)(const void *)(p + at), n);
}
static inline void dagr_sb_put_bytes(uint8_t *p, size_t at, const void *src, size_t n) {
  if (n != 0) memcpy(p + at, src, n);
}

/* ── Atomics ────────────────────────────────────────────────────────────────────
 * On a naturally aligned 4- or 8-byte word at `p + at`. Sequentially consistent unless the
 * name says otherwise: every SharedBuffer protocol here is a handful of operations per
 * record, and the cost of a weaker order is a correctness argument per call site. The word
 * is reached through `(W *)(void *)`, the runtime's one pointer cast: the layout made it
 * aligned. */

#if defined(__GNUC__) || defined(__clang__)
static inline uint32_t dagr_atomic_load_u32(const uint8_t *p, size_t at) {
  return __atomic_load_n((const uint32_t *)(const void *)(p + at), __ATOMIC_SEQ_CST);
}
static inline uint32_t dagr_atomic_load_acquire_u32(const uint8_t *p, size_t at) {
  return __atomic_load_n((const uint32_t *)(const void *)(p + at), __ATOMIC_ACQUIRE);
}
static inline void dagr_atomic_store_u32(uint8_t *p, size_t at, uint32_t v) {
  __atomic_store_n((uint32_t *)(void *)(p + at), v, __ATOMIC_SEQ_CST);
}
static inline void dagr_atomic_store_release_u32(uint8_t *p, size_t at, uint32_t v) {
  __atomic_store_n((uint32_t *)(void *)(p + at), v, __ATOMIC_RELEASE);
}
/** Adds `d` and returns the NEW value. */
static inline uint32_t dagr_atomic_add_u32(uint8_t *p, size_t at, uint32_t d) {
  return __atomic_add_fetch((uint32_t *)(void *)(p + at), d, __ATOMIC_SEQ_CST);
}
/** Stores `v` and returns the old value. */
static inline uint32_t dagr_atomic_swap_u32(uint8_t *p, size_t at, uint32_t v) {
  return __atomic_exchange_n((uint32_t *)(void *)(p + at), v, __ATOMIC_SEQ_CST);
}
/** Stores `desired` if the word holds `expected`; whether it did. */
static inline bool dagr_atomic_cas_u32(uint8_t *p, size_t at, uint32_t expected, uint32_t desired) {
  return __atomic_compare_exchange_n((uint32_t *)(void *)(p + at), &expected, desired, false, __ATOMIC_SEQ_CST,
                                     __ATOMIC_SEQ_CST);
}

static inline uint64_t dagr_atomic_load_u64(const uint8_t *p, size_t at) {
  return __atomic_load_n((const uint64_t *)(const void *)(p + at), __ATOMIC_SEQ_CST);
}
static inline uint64_t dagr_atomic_load_acquire_u64(const uint8_t *p, size_t at) {
  return __atomic_load_n((const uint64_t *)(const void *)(p + at), __ATOMIC_ACQUIRE);
}
static inline void dagr_atomic_store_u64(uint8_t *p, size_t at, uint64_t v) {
  __atomic_store_n((uint64_t *)(void *)(p + at), v, __ATOMIC_SEQ_CST);
}
static inline void dagr_atomic_store_release_u64(uint8_t *p, size_t at, uint64_t v) {
  __atomic_store_n((uint64_t *)(void *)(p + at), v, __ATOMIC_RELEASE);
}
/** Adds `d` and returns the NEW value. */
static inline uint64_t dagr_atomic_add_u64(uint8_t *p, size_t at, uint64_t d) {
  return __atomic_add_fetch((uint64_t *)(void *)(p + at), d, __ATOMIC_SEQ_CST);
}
/** Stores `v` and returns the old value. */
static inline uint64_t dagr_atomic_swap_u64(uint8_t *p, size_t at, uint64_t v) {
  return __atomic_exchange_n((uint64_t *)(void *)(p + at), v, __ATOMIC_SEQ_CST);
}
/** Stores `desired` if the word holds `expected`; whether it did. */
static inline bool dagr_atomic_cas_u64(uint8_t *p, size_t at, uint64_t expected, uint64_t desired) {
  return __atomic_compare_exchange_n((uint64_t *)(void *)(p + at), &expected, desired, false, __ATOMIC_SEQ_CST,
                                     __ATOMIC_SEQ_CST);
}
#else
static inline uint32_t dagr_atomic_load_u32(const uint8_t *p, size_t at) { return atomic_load((_Atomic uint32_t *)(void *)(uintptr_t)(p + at)); }
static inline uint32_t dagr_atomic_load_acquire_u32(const uint8_t *p, size_t at) {
  return atomic_load_explicit((_Atomic uint32_t *)(void *)(uintptr_t)(p + at), memory_order_acquire);
}
static inline void dagr_atomic_store_u32(uint8_t *p, size_t at, uint32_t v) { atomic_store((_Atomic uint32_t *)(void *)(p + at), v); }
static inline void dagr_atomic_store_release_u32(uint8_t *p, size_t at, uint32_t v) {
  atomic_store_explicit((_Atomic uint32_t *)(void *)(p + at), v, memory_order_release);
}
static inline uint32_t dagr_atomic_add_u32(uint8_t *p, size_t at, uint32_t d) { return (uint32_t)(atomic_fetch_add((_Atomic uint32_t *)(void *)(p + at), d) + d); }
static inline uint32_t dagr_atomic_swap_u32(uint8_t *p, size_t at, uint32_t v) { return atomic_exchange((_Atomic uint32_t *)(void *)(p + at), v); }
static inline bool dagr_atomic_cas_u32(uint8_t *p, size_t at, uint32_t expected, uint32_t desired) {
  return atomic_compare_exchange_strong((_Atomic uint32_t *)(void *)(p + at), &expected, desired);
}

static inline uint64_t dagr_atomic_load_u64(const uint8_t *p, size_t at) { return atomic_load((_Atomic uint64_t *)(void *)(uintptr_t)(p + at)); }
static inline uint64_t dagr_atomic_load_acquire_u64(const uint8_t *p, size_t at) {
  return atomic_load_explicit((_Atomic uint64_t *)(void *)(uintptr_t)(p + at), memory_order_acquire);
}
static inline void dagr_atomic_store_u64(uint8_t *p, size_t at, uint64_t v) { atomic_store((_Atomic uint64_t *)(void *)(p + at), v); }
static inline void dagr_atomic_store_release_u64(uint8_t *p, size_t at, uint64_t v) {
  atomic_store_explicit((_Atomic uint64_t *)(void *)(p + at), v, memory_order_release);
}
static inline uint64_t dagr_atomic_add_u64(uint8_t *p, size_t at, uint64_t d) { return (uint64_t)(atomic_fetch_add((_Atomic uint64_t *)(void *)(p + at), d) + d); }
static inline uint64_t dagr_atomic_swap_u64(uint8_t *p, size_t at, uint64_t v) { return atomic_exchange((_Atomic uint64_t *)(void *)(p + at), v); }
static inline bool dagr_atomic_cas_u64(uint8_t *p, size_t at, uint64_t expected, uint64_t desired) {
  return atomic_compare_exchange_strong((_Atomic uint64_t *)(void *)(p + at), &expected, desired);
}
#endif

/** A float as the word an `atomic` region stores it in, and back. */
static inline uint32_t dagr_sb_word_f32(float v) { return dagr_f32_bits(v); }
static inline uint64_t dagr_sb_word_f64(double v) { return dagr_f64_bits(v); }
static inline float dagr_sb_f32_of_word(uint32_t w) { return dagr_f32_from_bits(w); }
static inline double dagr_sb_f64_of_word(uint64_t w) { return dagr_f64_from_bits(w); }

/** Whether `p` is a multiple of `align` — what a region's base must be for its atomics. */
static inline bool dagr_sb_aligned(const void *p, size_t align) {
  return align <= 1 || ((uintptr_t)p & (align - 1)) == 0;
}

/** The seqlock's payload copy (spec/44 §0.4): `n` bytes from `src` to `dst`, every access a
 * relaxed atomic — word-wise where both sides are 8-byte aligned, byte-wise for the rest.
 * The copy may race with a writer; whoever calls it decides afterwards from the counter
 * whether to keep it. */
static inline void dagr_racy_copy(uint8_t *dst, const uint8_t *src, size_t n) {
  size_t i = 0;
#if defined(__GNUC__) || defined(__clang__)
  if (dagr_sb_aligned(dst, 8) && dagr_sb_aligned(src, 8)) {
    for (; i + 8 <= n; i += 8) {
      const uint64_t w = __atomic_load_n((const uint64_t *)(const void *)(src + i), __ATOMIC_RELAXED);
      __atomic_store_n((uint64_t *)(void *)(dst + i), w, __ATOMIC_RELAXED);
    }
  }
  for (; i < n; i++) {
    __atomic_store_n(dst + i, __atomic_load_n(src + i, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
  }
#else
  for (; i < n; i++) {
    const uint8_t b = atomic_load_explicit((_Atomic uint8_t *)(void *)(uintptr_t)(src + i),
                                           memory_order_relaxed);
    atomic_store_explicit((_Atomic uint8_t *)(void *)(dst + i), b, memory_order_relaxed);
  }
#endif
}

/** A full fence: what orders the seqlock writer's payload stores against its counter. */
static inline void dagr_atomic_fence(void) {
#if defined(__GNUC__) || defined(__clang__)
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
#else
  atomic_thread_fence(memory_order_seq_cst);
#endif
}

#endif /* DAGR_SHARED_BUFFER_H */
