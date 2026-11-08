/* Hand-rolled SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104): C has no standard crypto,
 * and the example stays dependency-free. Header-only, C99/C11 and C++ compatible. The block
 * function uses the ARMv8 SHA-256 instructions when the compiler targets them (Apple silicon
 * does by default), else portable scalar code. Checked against the NIST and RFC 4231 vectors
 * by `dst_hmac_selftest` (the C example's `test`). */
#ifndef DST_HMAC_SHA256_H
#define DST_HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if defined(__ARM_FEATURE_SHA2) && defined(__aarch64__)
#include <arm_neon.h>
#define DST_SHA256_ARMV8 1
#endif

typedef struct {
  uint32_t h[8];
  uint8_t block[64];
  size_t used;
  uint64_t total;
} dst_sha256;

static const uint32_t dst_sha256_k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t dst_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

#ifdef DST_SHA256_ARMV8
/* One block with the ARMv8 SHA-256 instructions: four rounds per SHA256H/SHA256H2 pair, the
 * message schedule four words at a time with SHA256SU0/SHA256SU1. */
static inline void dst_sha256_compress(dst_sha256* s, const uint8_t* p) {
  uint32x4_t abcd = vld1q_u32(&s->h[0]), efgh = vld1q_u32(&s->h[4]);
  const uint32x4_t abcd0 = abcd, efgh0 = efgh;
  uint32x4_t m[4];
  for (int j = 0; j < 4; j++) m[j] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16 * j)));
  for (int i = 0; i < 16; i++) {
    const uint32x4_t wk = vaddq_u32(m[i & 3], vld1q_u32(&dst_sha256_k[4 * i]));
    const uint32x4_t prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, wk);
    efgh = vsha256h2q_u32(efgh, prev, wk);
    if (i < 12) m[i & 3] = vsha256su1q_u32(vsha256su0q_u32(m[i & 3], m[(i + 1) & 3]), m[(i + 2) & 3], m[(i + 3) & 3]);
  }
  vst1q_u32(&s->h[0], vaddq_u32(abcd, abcd0));
  vst1q_u32(&s->h[4], vaddq_u32(efgh, efgh0));
}
#else
static inline void dst_sha256_compress(dst_sha256* s, const uint8_t* p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = dst_rotr(w[i - 15], 7) ^ dst_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = dst_rotr(w[i - 2], 17) ^ dst_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + (dst_rotr(e, 6) ^ dst_rotr(e, 11) ^ dst_rotr(e, 25)) + ((e & f) ^ (~e & g)) + dst_sha256_k[i] + w[i];
    uint32_t t2 = (dst_rotr(a, 2) ^ dst_rotr(a, 13) ^ dst_rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
#endif

static inline void dst_sha256_init(dst_sha256* s) {
  static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memcpy(s->h, iv, sizeof iv);
  s->used = 0;
  s->total = 0;
}

static inline void dst_sha256_update(dst_sha256* s, const uint8_t* p, size_t n) {
  s->total += n;
  while (n > 0) {
    size_t take = 64 - s->used < n ? 64 - s->used : n;
    memcpy(s->block + s->used, p, take);
    s->used += take; p += take; n -= take;
    if (s->used == 64) { dst_sha256_compress(s, s->block); s->used = 0; }
  }
}

static inline void dst_sha256_final(dst_sha256* s, uint8_t out[32]) {
  uint64_t bits = s->total * 8;
  uint8_t pad = 0x80;
  dst_sha256_update(s, &pad, 1);
  uint8_t zero = 0;
  while (s->used != 56) dst_sha256_update(s, &zero, 1);
  uint8_t len[8];
  for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
  dst_sha256_update(s, len, 8);
  for (int i = 0; i < 8; i++) {
    out[4 * i] = (uint8_t)(s->h[i] >> 24); out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
    out[4 * i + 2] = (uint8_t)(s->h[i] >> 8); out[4 * i + 3] = (uint8_t)s->h[i];
  }
}

/* HMAC-SHA256 over `a ++ b` (two parts, so the preimage needs no copy). */
static inline void dst_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* a, size_t a_len,
                                   const uint8_t* b, size_t b_len, uint8_t out[32]) {
  uint8_t k[64] = {0};
  if (key_len > 64) {
    dst_sha256 s; dst_sha256_init(&s); dst_sha256_update(&s, key, key_len); dst_sha256_final(&s, k);
  } else {
    memcpy(k, key, key_len);
  }
  uint8_t ipad[64], opad[64], inner[32];
  for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
  dst_sha256 s;
  dst_sha256_init(&s); dst_sha256_update(&s, ipad, 64); dst_sha256_update(&s, a, a_len); dst_sha256_update(&s, b, b_len);
  dst_sha256_final(&s, inner);
  dst_sha256_init(&s); dst_sha256_update(&s, opad, 64); dst_sha256_update(&s, inner, 32); dst_sha256_final(&s, out);
}

/* Constant-time comparison of two 32-byte MACs. */
static inline int dst_mac_equal(const uint8_t* a, size_t a_len, const uint8_t* b) {
  if (a_len != 32) return 0;
  uint8_t d = 0;
  for (int i = 0; i < 32; i++) d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}

/* NIST "abc" and RFC 4231 test cases 1 and 2. Returns 1 when all pass. */
static inline int dst_hmac_selftest(void) {
  static const uint8_t abc_want[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  static const uint8_t tc1_want[32] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
  static const uint8_t tc2_want[32] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
    0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
  uint8_t out[32];
  dst_sha256 s; dst_sha256_init(&s); dst_sha256_update(&s, (const uint8_t*)"abc", 3); dst_sha256_final(&s, out);
  if (memcmp(out, abc_want, 32) != 0) return 0;
  uint8_t key1[20]; memset(key1, 0x0b, 20);
  dst_hmac_sha256(key1, 20, (const uint8_t*)"Hi There", 8, NULL, 0, out);
  if (memcmp(out, tc1_want, 32) != 0) return 0;
  dst_hmac_sha256((const uint8_t*)"Jefe", 4, (const uint8_t*)"what do ya want ", 16,
                  (const uint8_t*)"for nothing?", 12, out);
  return memcmp(out, tc2_want, 32) == 0;
}

#endif
