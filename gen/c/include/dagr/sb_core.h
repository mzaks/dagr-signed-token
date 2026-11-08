/* dagr/sb_core.h — the primitives every Dagr C header shares (spec/44 §8.1): byte and text
 * views, little-endian loads and stores of every fixed-width kind, and the half-float
 * conversions. A future C reader keeps these names (spec/44 §12).
 *
 * Core tier: <stdbool.h> <stddef.h> <stdint.h> <string.h> only — no allocation, no libc
 * beyond memcpy / memset. Every function is `static inline`; the header defines no macro
 * but its include guard.
 *
 * Loads and stores take a region and an ABSOLUTE position in it and go through memcpy:
 * one unaligned load or store, no alignment or aliasing precondition. The positions a
 * generated header passes are constants of the layout, correct by construction; what the
 * region itself says (a length, a tag) is clamped where it is read (dagr/shared_buffer.h).
 */
#ifndef DAGR_SB_CORE_H
#define DAGR_SB_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#error "dagr: the C target needs C11 or newer (spec/44 §3.1)"
#endif

/** `len` bytes of text at `ptr` — a view, not NUL-terminated, not validated as UTF-8. */
typedef struct dagr_str {
  const char *ptr;
  size_t len;
} dagr_str;

/** `len` bytes at `ptr` — a view. */
typedef struct dagr_bytes {
  const uint8_t *ptr;
  size_t len;
} dagr_bytes;

static inline dagr_str dagr_str_of(const char *ptr, size_t len) {
  dagr_str s;
  s.ptr = ptr;
  s.len = len;
  return s;
}

static inline dagr_bytes dagr_bytes_of(const uint8_t *ptr, size_t len) {
  dagr_bytes b;
  b.ptr = ptr;
  b.len = len;
  return b;
}

/** Whether two views hold the same bytes. */
static inline bool dagr_str_eq(dagr_str a, dagr_str b) {
  return a.len == b.len && (a.len == 0 || memcmp(a.ptr, b.ptr, a.len) == 0);
}
static inline bool dagr_bytes_eq(dagr_bytes a, dagr_bytes b) {
  return a.len == b.len && (a.len == 0 || memcmp(a.ptr, b.ptr, a.len) == 0);
}

/* ── Byte order ─────────────────────────────────────────────────────────────── */

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint16_t dagr_le16(uint16_t v) { return __builtin_bswap16(v); }
static inline uint32_t dagr_le32(uint32_t v) { return __builtin_bswap32(v); }
static inline uint64_t dagr_le64(uint64_t v) { return __builtin_bswap64(v); }
#else
static inline uint16_t dagr_le16(uint16_t v) { return v; }
static inline uint32_t dagr_le32(uint32_t v) { return v; }
static inline uint64_t dagr_le64(uint64_t v) { return v; }
#endif

/* ── Bit casts ──────────────────────────────────────────────────────────────── */

static inline uint32_t dagr_f32_bits(float v) {
  uint32_t b;
  memcpy(&b, &v, 4);
  return b;
}
static inline float dagr_f32_from_bits(uint32_t b) {
  float v;
  memcpy(&v, &b, 4);
  return v;
}
static inline uint64_t dagr_f64_bits(double v) {
  uint64_t b;
  memcpy(&b, &v, 8);
  return b;
}
static inline double dagr_f64_from_bits(uint64_t b) {
  double v;
  memcpy(&v, &b, 8);
  return v;
}

/* ── Half floats (bit-exact with every other target) ───────────────────────── */

static inline float dagr_f16_to_f32(uint16_t h) {
  const uint32_t sign = (uint32_t)(h >> 15) << 31;
  const uint32_t exp = (uint32_t)(h >> 10) & 0x1fu;
  const uint32_t mant = (uint32_t)h & 0x3ffu;
  uint32_t out;
  if (exp == 0) {
    if (mant == 0) {
      out = sign;
    } else {
      uint32_t m = mant;
      uint32_t e = 127 - 14;
      while ((m & 0x400u) == 0) {
        m <<= 1;
        e--;
      }
      out = sign | (e << 23) | ((m & 0x3ffu) << 13);
    }
  } else if (exp == 31) {
    out = sign | 0x7f800000u | (mant << 13);
  } else {
    out = sign | ((exp + 112) << 23) | (mant << 13);
  }
  return dagr_f32_from_bits(out);
}

static inline float dagr_bf16_to_f32(uint16_t v) { return dagr_f32_from_bits((uint32_t)v << 16); }

/** float → bfloat16 bits: round-to-nearest-even on the top 16 bits. */
static inline uint16_t dagr_f32_to_bf16(float v) {
  const uint32_t b = dagr_f32_bits(v);
  const uint32_t lsb = (b >> 16) & 1u;
  return (uint16_t)((b + 0x7fffu + lsb) >> 16);
}

/** float → IEEE-754 half bits: round-to-nearest-even, subnormals, overflow to infinity. */
static inline uint16_t dagr_f32_to_f16(float v) {
  if (v != v) return 0x7e00u;
  const uint32_t b = dagr_f32_bits(v);
  const uint32_t sign = (b >> 16) & 0x8000u;
  const int exp32 = (int)((b >> 23) & 0xffu);
  const uint32_t mant32 = b & 0x7fffffu;
  if (exp32 == 0xff) return (uint16_t)(sign | 0x7c00u);
  if ((b & 0x7fffffffu) == 0) return (uint16_t)sign;
  const int exp16 = exp32 - 127 + 15;
  if (exp16 >= 0x1f) return (uint16_t)(sign | 0x7c00u);
  if (exp16 <= 0) {
    if (exp16 < -10) return (uint16_t)sign;
    const uint32_t m = mant32 | 0x800000u;
    const unsigned shift = (unsigned)(14 - exp16);
    const uint32_t low = m & ((UINT32_C(1) << shift) - 1u);
    const uint32_t half = UINT32_C(1) << (shift - 1);
    uint32_t r = m >> shift;
    if (low > half || (low == half && (r & 1u) == 1u)) r++;
    return (uint16_t)(sign | r);
  }
  uint32_t half16 = ((uint32_t)exp16 << 10) | (mant32 >> 13);
  const uint32_t round = (mant32 >> 12) & 1u;
  const bool sticky = (mant32 & 0xfffu) != 0;
  if (round == 1u && (sticky || (half16 & 1u) == 1u)) half16++;
  return (uint16_t)(sign | half16);
}

/* ── Loads and stores, one function per kind ───────────────────────────────── */

static inline uint8_t dagr_sb_get_u8(const uint8_t *p, size_t at) { return p[at]; }
static inline void dagr_sb_put_u8(uint8_t *p, size_t at, uint8_t v) { p[at] = v; }
static inline int8_t dagr_sb_get_i8(const uint8_t *p, size_t at) { return (int8_t)p[at]; }
static inline void dagr_sb_put_i8(uint8_t *p, size_t at, int8_t v) { p[at] = (uint8_t)v; }

static inline uint16_t dagr_sb_get_u16(const uint8_t *p, size_t at) {
  uint16_t v;
  memcpy(&v, p + at, 2);
  return dagr_le16(v);
}
static inline void dagr_sb_put_u16(uint8_t *p, size_t at, uint16_t v) {
  v = dagr_le16(v);
  memcpy(p + at, &v, 2);
}
static inline uint32_t dagr_sb_get_u32(const uint8_t *p, size_t at) {
  uint32_t v;
  memcpy(&v, p + at, 4);
  return dagr_le32(v);
}
static inline void dagr_sb_put_u32(uint8_t *p, size_t at, uint32_t v) {
  v = dagr_le32(v);
  memcpy(p + at, &v, 4);
}
static inline uint64_t dagr_sb_get_u64(const uint8_t *p, size_t at) {
  uint64_t v;
  memcpy(&v, p + at, 8);
  return dagr_le64(v);
}
static inline void dagr_sb_put_u64(uint8_t *p, size_t at, uint64_t v) {
  v = dagr_le64(v);
  memcpy(p + at, &v, 8);
}

static inline int16_t dagr_sb_get_i16(const uint8_t *p, size_t at) { return (int16_t)dagr_sb_get_u16(p, at); }
static inline void dagr_sb_put_i16(uint8_t *p, size_t at, int16_t v) { dagr_sb_put_u16(p, at, (uint16_t)v); }
static inline int32_t dagr_sb_get_i32(const uint8_t *p, size_t at) { return (int32_t)dagr_sb_get_u32(p, at); }
static inline void dagr_sb_put_i32(uint8_t *p, size_t at, int32_t v) { dagr_sb_put_u32(p, at, (uint32_t)v); }
static inline int64_t dagr_sb_get_i64(const uint8_t *p, size_t at) { return (int64_t)dagr_sb_get_u64(p, at); }
static inline void dagr_sb_put_i64(uint8_t *p, size_t at, int64_t v) { dagr_sb_put_u64(p, at, (uint64_t)v); }

static inline float dagr_sb_get_f32(const uint8_t *p, size_t at) { return dagr_f32_from_bits(dagr_sb_get_u32(p, at)); }
static inline void dagr_sb_put_f32(uint8_t *p, size_t at, float v) { dagr_sb_put_u32(p, at, dagr_f32_bits(v)); }
static inline double dagr_sb_get_f64(const uint8_t *p, size_t at) { return dagr_f64_from_bits(dagr_sb_get_u64(p, at)); }
static inline void dagr_sb_put_f64(uint8_t *p, size_t at, double v) { dagr_sb_put_u64(p, at, dagr_f64_bits(v)); }

static inline float dagr_sb_get_f16(const uint8_t *p, size_t at) { return dagr_f16_to_f32(dagr_sb_get_u16(p, at)); }
static inline void dagr_sb_put_f16(uint8_t *p, size_t at, float v) { dagr_sb_put_u16(p, at, dagr_f32_to_f16(v)); }
static inline float dagr_sb_get_bf16(const uint8_t *p, size_t at) { return dagr_bf16_to_f32(dagr_sb_get_u16(p, at)); }
static inline void dagr_sb_put_bf16(uint8_t *p, size_t at, float v) { dagr_sb_put_u16(p, at, dagr_f32_to_bf16(v)); }

/** A bool stored as a whole byte (a union variant); fields use the bit pool instead. */
static inline bool dagr_sb_get_bool(const uint8_t *p, size_t at) { return p[at] != 0; }
static inline void dagr_sb_put_bool(uint8_t *p, size_t at, bool v) { p[at] = v ? 1 : 0; }

#endif /* DAGR_SB_CORE_H */
