/* dagr-signed-token — C example. Mints and verifies the shared token (see ../../CONTRACT.md).
 * The codec is the generated header-only library (gen/c): the arena writes the token with its
 * header, and the verifier's gate checks the header through the lazy reader before the body is
 * read. HMAC-SHA256 is the hand-rolled hmac_sha256.h.
 *
 * CLI:  dst-c             → run the showcase (mint, verify, tamper, alg:none, expiry)
 *       dst-c emit   PATH → write a valid token to PATH
 *       dst-c verify PATH → verify+decode a token minted by any language
 *       dst-c test        → the SHA-256 / HMAC self-test (NIST, RFC 4231)
 *       dst-c bench       → mint + verify, 50k reps each, ns/op (for run_bench.sh) */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dagr/heap.h>
#include <dagr_signed_token/token.h>
#include <dagr_signed_token/token_arena.h>

#include "hmac_sha256.h"

static const char SECRET[] = "dagr-signed-token-demo-secret-2026";
static const char KID[] = "hmac-key-2026";
#define NOW UINT64_C(1760000000)
#define EXP (NOW + 3600)

static dagr_str str(const char *s) { return dagr_str_of(s, strlen(s)); }

/* HMAC-SHA256(key, preimage(rootOffset, body)), preimage = LE_u64(rootOffset) ++ body. */
static void sign(const char *key, size_t key_len, size_t root_offset, dagr_bytes body, uint8_t out[32]) {
  uint8_t le[8];
  for (int i = 0; i < 8; i++) le[i] = (uint8_t)((uint64_t)root_offset >> (8 * i));
  dst_hmac_sha256((const uint8_t *)key, key_len, le, 8, body.ptr, body.len, out);
}

typedef struct {
  const char *key;
  size_t key_len;
  const char *alg;
  uint8_t mac[32];
} mint_ctx;

static void header_fn(void *context, size_t root_offset, dagr_bytes body, token_Jws *out) {
  mint_ctx *m = (mint_ctx *)context;
  sign(m->key, m->key_len, root_offset, body, m->mac);
  out->algorithm = str(m->alg);
  out->has_key_id = true;
  out->key_id = str(KID);
  out->signature = dagr_bytes_of(m->mac, 32);
}

typedef struct {
  uint8_t *data;
  size_t len;
} buffer;

static buffer mint(const char *key, size_t key_len, const char *alg, uint64_t exp) {
  token_Arena a;
  token_Arena_init(&a, dagr_default_allocator());
  /* custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef } */
  static const uint8_t fp[] = {0xDE, 0xAD, 0xBE, 0xEF};
  const token_JsonValue roles[2] = {token_JsonValue_string(str("admin")), token_JsonValue_string(str("billing"))};
  const bool roles_present[2] = {true, true};
  token_JsonMemberHandle m[4];
  const char *keys[4] = {"tenant", "roles", "mfa", "fp"};
  token_JsonValue values[4];
  values[0] = token_JsonValue_string(str("acme"));
  values[1] = token_JsonValue_array((token_JsonValueArray){roles, roles_present, 2});
  values[2] = token_JsonValue_bool(true);
  values[3] = token_JsonValue_data(dagr_bytes_of(fp, 4));
  uint64_t ids[4];
  for (int i = 0; i < 4; i++) {
    m[i] = token_Arena_new_json_member(&a);
    token_JsonMemberHandle_set_key(m[i], str(keys[i]));
    token_JsonMemberHandle_set_value(m[i], &values[i]);
    ids[i] = m[i].id;
  }
  const token_JsonValue custom = token_JsonValue_object((dagr_u64_opt_slice){ids, NULL, 4});
  const dagr_str scopes[2] = {str("read:profile"), str("write:posts")};
  token_ClaimsHandle c = token_Arena_new_claims(&a);
  token_ClaimsHandle_set_subject(c, str("user-42"));
  token_ClaimsHandle_set_issuer(c, str("https://issuer.dagr.one"));
  token_ClaimsHandle_set_audience(c, str("dagr-api"));
  token_ClaimsHandle_set_issued_at(c, NOW);
  token_ClaimsHandle_set_expires_at(c, exp);
  token_ClaimsHandle_set_scopes(c, scopes, 2);
  token_ClaimsHandle_set_custom(c, &custom);
  token_Arena_set_root(&a, c);

  mint_ctx ctx = {key, key_len, alg, {0}};
  dagr_builder b = dagr_builder_heap();
  dagr_graph_caches caches = dagr_graph_caches_default();
  const dagr_bytes out = token_Arena_serialize_with_header(&a, &b, &caches, header_fn, &ctx);
  if (!dagr_builder_ok(&b)) {
    fprintf(stderr, "mint failed\n");
    exit(2);
  }
  buffer r = {malloc(out.len), out.len};
  memcpy(r.data, out.ptr, out.len);
  dagr_graph_caches_free(&caches);
  dagr_builder_heap_free(&b);
  token_Arena_free(&a);
  return r;
}

typedef enum { REJ_NONE, REJ_BAD_ALG, REJ_BAD_SIGNATURE, REJ_EXPIRED, REJ_WRONG_AUDIENCE } rejected;

static const char *rej_name(rejected r) {
  switch (r) {
    case REJ_BAD_ALG: return "BadAlg";
    case REJ_BAD_SIGNATURE: return "BadSignature";
    case REJ_EXPIRED: return "Expired";
    case REJ_WRONG_AUDIENCE: return "WrongAudience";
    default: return "None";
  }
}

static const char *rej_stage(rejected r) {
  return r == REJ_BAD_ALG || r == REJ_BAD_SIGNATURE ? "GATE (verify-before-parse)" : "post-decode claim check";
}

/* Verify-before-parse through the lazy reader: the gate reads only the header, then the claims
 * are read in place — no restore. */
static rejected verify(buffer t, const char *key, size_t key_len, uint64_t now) {
  const dagr_bytes buf = dagr_bytes_of(t.data, t.len);
  dagr_header_frame frame;
  token_JwsAccessor h;
  if (dagr_read_header_frame(buf, &frame) != dagr_ok || token_open_header(buf, &h) != dagr_ok) return REJ_BAD_SIGNATURE;
  if (!dagr_str_eq(token_JwsAccessor_algorithm(&h), str("HS256"))) return REJ_BAD_ALG;
  const size_t body_at = frame.start + frame.span;
  uint8_t want[32];
  sign(key, key_len, frame.root_offset, dagr_bytes_of(t.data + body_at, t.len - body_at), want);
  const dagr_bytes sig = token_JwsAccessor_signature(&h);
  if (!dst_mac_equal(sig.ptr, sig.len, want)) return REJ_BAD_SIGNATURE;
  token_ClaimsAccessor c;
  if (token_open(buf, &c) != dagr_ok) return REJ_BAD_SIGNATURE;
  if (now >= token_ClaimsAccessor_expires_at(&c)) return REJ_EXPIRED;
  if (!token_ClaimsAccessor_has_audience(&c) || !dagr_str_eq(token_ClaimsAccessor_audience(&c), str("dagr-api")))
    return REJ_WRONG_AUDIENCE;
  return REJ_NONE;
}

static void put_quoted(dagr_str s) {
  putchar('"');
  for (size_t i = 0; i < s.len; i++) {
    if (s.ptr[i] == '"' || s.ptr[i] == '\\') putchar('\\');
    putchar(s.ptr[i]);
  }
  putchar('"');
}

static void put_json(token_JsonPackedView v) {
  switch (token_JsonPackedView_tag(v)) {
    case token_JsonTag_String: put_quoted(token_JsonPackedView_string(v)); break;
    case token_JsonTag_Number: {
      const double n = token_JsonPackedView_number(v);
      if (n == floor(n)) printf("%.0f", n); else printf("%g", n);
      break;
    }
    case token_JsonTag_Bool: fputs(token_JsonPackedView_bool(v) ? "true" : "false", stdout); break;
    case token_JsonTag_Array: {
      dagr_pk_array arr = token_JsonPackedView_array(v);
      dagr_pk_union_header uh;
      bool present, first = true;
      putchar('[');
      while (dagr_pk_next_union(&arr, &uh, &present)) {
        if (!first) putchar(',');
        first = false;
        if (present) put_json(token_JsonPackedView_of(arr.buf, uh)); else fputs("null", stdout);
      }
      putchar(']');
      break;
    }
    case token_JsonTag_Object: {
      dagr_pk_array arr = token_JsonPackedView_object(v);
      size_t at;
      bool present, first = true;
      putchar('{');
      while (dagr_pk_next_blob(&arr, &at, &present)) {
        if (!first) putchar(',');
        first = false;
        const token_JsonMemberAccessor m = token_JsonMemberAccessor_at(arr.buf, at);
        put_quoted(token_JsonMemberAccessor_key(&m));
        putchar(':');
        if (token_JsonMemberAccessor_has_value(&m)) put_json(token_JsonMemberAccessor_value(&m)); else fputs("null", stdout);
      }
      putchar('}');
      break;
    }
    case token_JsonTag_Data: {
      const dagr_bytes d = token_JsonPackedView_data(v);
      fputs("0x", stdout);
      for (size_t i = 0; i < d.len; i++) printf("%02x", d.ptr[i]);
      break;
    }
    default: putchar('?');
  }
}

static void report(const char *label, buffer t, rejected r) {
  if (r != REJ_NONE) {
    printf("  %-20s REJECT  [%s] %s\n", label, rej_stage(r), rej_name(r));
    return;
  }
  token_ClaimsAccessor c;
  token_open(dagr_bytes_of(t.data, t.len), &c);
  printf("  %-20s ACCEPT  sub=", label);
  put_quoted(token_ClaimsAccessor_subject(&c));
  fputs(" custom=", stdout);
  if (token_ClaimsAccessor_has_custom(&c)) put_json(token_ClaimsAccessor_custom(&c)); else putchar('-');
  putchar('\n');
}

static size_t body_start(buffer t) {
  dagr_header_frame frame;
  dagr_read_header_frame(dagr_bytes_of(t.data, t.len), &frame);
  return frame.start + frame.span;
}

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static volatile size_t bench_sink;

/* mint (arena + serialize_with_header + HMAC) and verify (header gate + lazy reads), 50k reps
 * each after a warm-up, correctness-gated first. Prints the line run_bench.sh tabulates. */
static int bench(void) {
  const size_t key_len = sizeof SECRET - 1;
  const int n = 50000;
  buffer tok = mint(SECRET, key_len, "HS256", EXP);
  buffer expired = mint(SECRET, key_len, "HS256", NOW - 1);
  if (verify(tok, SECRET, key_len, NOW) != REJ_NONE || verify(expired, SECRET, key_len, NOW) == REJ_NONE) {
    fprintf(stderr, "bench: correctness gate failed\n");
    return 1;
  }
  for (int i = 0; i < n / 10; i++) { buffer t = mint(SECRET, key_len, "HS256", EXP); bench_sink += t.len; free(t.data); }
  uint64_t t0 = now_ns();
  for (int i = 0; i < n; i++) { buffer t = mint(SECRET, key_len, "HS256", EXP); bench_sink += t.len; free(t.data); }
  const uint64_t mint_ns = (now_ns() - t0) / (uint64_t)n;
  for (int i = 0; i < n / 10; i++) bench_sink += verify(tok, SECRET, key_len, NOW);
  t0 = now_ns();
  for (int i = 0; i < n; i++) bench_sink += verify(tok, SECRET, key_len, NOW);
  const uint64_t verify_ns = (now_ns() - t0) / (uint64_t)n;
  printf("BENCH c dagr mint=%llu verify=%llu size=%zu\n", (unsigned long long)mint_ns, (unsigned long long)verify_ns, tok.len);
  free(tok.data);
  free(expired.data);
  return 0;
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "bench") == 0) return bench();
  const size_t key_len = sizeof SECRET - 1;
  if (argc > 1 && strcmp(argv[1], "test") == 0) {
    const int ok = dst_hmac_selftest();
    printf("[c] SHA-256 / HMAC self-test: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
  }
  if (argc > 2 && strcmp(argv[1], "emit") == 0) {
    buffer t = mint(SECRET, key_len, "HS256", EXP);
    FILE *f = fopen(argv[2], "wb");
    if (f == NULL || fwrite(t.data, 1, t.len, f) != t.len) return 2;
    fclose(f);
    printf("[c] emitted -> %s\n", argv[2]);
    free(t.data);
    return 0;
  }
  if (argc > 2 && strcmp(argv[1], "verify") == 0) {
    FILE *f = fopen(argv[2], "rb");
    if (f == NULL) return 2;
    fseek(f, 0, SEEK_END);
    buffer t = {NULL, (size_t)ftell(f)};
    fseek(f, 0, SEEK_SET);
    t.data = malloc(t.len ? t.len : 1);
    if (fread(t.data, 1, t.len, f) != t.len) return 2;
    fclose(f);
    const rejected r = verify(t, SECRET, key_len, NOW);
    char label[512];
    snprintf(label, sizeof label, "[c] %s", argv[2]);
    report(label, t, r);
    free(t.data);
    return r == REJ_NONE ? 0 : 1;
  }

  printf("== dagr-signed-token — C ==\n\n");
  buffer token = mint(SECRET, key_len, "HS256", EXP);
  printf("Minted token: %zu bytes\n\nVerification:\n", token.len);
  report("valid token", token, verify(token, SECRET, key_len, NOW));
  buffer tampered = {malloc(token.len), token.len};
  memcpy(tampered.data, token.data, token.len);
  tampered.data[body_start(tampered)] ^= 0x01;
  report("tampered body", tampered, verify(tampered, SECRET, key_len, NOW));
  report("wrong key", token, verify(token, "not-the-secret", 14, NOW));
  buffer none = mint(SECRET, key_len, "none", EXP);
  report("alg:none token", none, verify(none, SECRET, key_len, NOW));
  buffer expired = mint(SECRET, key_len, "HS256", NOW - 1);
  report("expired token", expired, verify(expired, SECRET, key_len, NOW));
  free(token.data); free(tampered.data); free(none.data); free(expired.data);
  return 0;
}
