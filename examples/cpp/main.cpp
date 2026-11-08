// dagr-signed-token — C++ example. Mints and verifies the shared token (see
// ../../CONTRACT.md). The codec is the generated header-only library (gen/cpp): the arena
// writes the token with its header, and the verifier's gate checks the header through the
// lazy reader before the body is read. HMAC-SHA256 is the hand-rolled ../c/hmac_sha256.h.
//
// CLI:  dst-cpp             → run the showcase (mint, verify, tamper, alg:none, expiry)
//       dst-cpp emit   PATH → write a valid token to PATH
//       dst-cpp verify PATH → verify+decode a token minted by any language
//       dst-cpp bench       → mint + verify, 50k reps each, ns/op (for run_bench.sh)

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <dagr/writer.hpp>
#include <dagr_signed_token/token.hpp>
#include <dagr_signed_token/token_arena.hpp>

#include "../c/hmac_sha256.h"

namespace tok = dagr_signed_token::token;
namespace ar = dagr_signed_token::token::arena;

namespace {

const std::string_view SECRET = "dagr-signed-token-demo-secret-2026";
const std::string_view KID = "hmac-key-2026";
constexpr std::uint64_t NOW = 1760000000;
constexpr std::uint64_t EXP = NOW + 3600;

// HMAC-SHA256(key, preimage(rootOffset, body)), preimage = LE_u64(rootOffset) ++ body.
std::array<std::uint8_t, 32> sign(std::string_view key, std::size_t root_offset, dagr::Bytes body) {
  std::uint8_t le[8];
  for (int i = 0; i < 8; i++) le[i] = static_cast<std::uint8_t>(static_cast<std::uint64_t>(root_offset) >> (8 * i));
  std::array<std::uint8_t, 32> mac{};
  dst_hmac_sha256(reinterpret_cast<const std::uint8_t*>(key.data()), key.size(), le, 8, body.data(), body.size(), mac.data());
  return mac;
}

std::vector<std::uint8_t> mint(std::string_view key, std::string_view alg, std::uint64_t exp) {
  ar::Arena a;
  // custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }
  const std::optional<ar::JsonValue> roles[] = {ar::JsonValue::string("admin"), ar::JsonValue::string("billing")};
  static const std::uint8_t fp[] = {0xDE, 0xAD, 0xBE, 0xEF};
  const ar::JsonMember members[] = {a.new_json_member(), a.new_json_member(), a.new_json_member(), a.new_json_member()};
  members[0].set_key("tenant");
  members[0].set_value(ar::JsonValue::string("acme"));
  members[1].set_key("roles");
  members[1].set_value(ar::JsonValue::array(dagr::Span<const std::optional<ar::JsonValue>>(roles, 2)));
  members[2].set_key("mfa");
  members[2].set_value(ar::JsonValue::bool_(true));
  members[3].set_key("fp");
  members[3].set_value(ar::JsonValue::data(dagr::Bytes(fp, 4)));
  const std::string_view scopes[] = {"read:profile", "write:posts"};
  const ar::Claims c = a.new_claims();
  c.set_subject("user-42");
  c.set_issuer("https://issuer.dagr.one");
  c.set_audience("dagr-api");
  c.set_issued_at(NOW);
  c.set_expires_at(exp);
  c.set_scopes(dagr::Span<const std::string_view>(scopes, 2));
  c.set_custom(ar::JsonValue::object(dagr::Span<const ar::JsonMember>(members, 4)));
  a.set_root(c);

  std::array<std::uint8_t, 32> mac{};   // outlives the call: the header stores a view of it
  dagr::Builder b;
  dagr::GraphCaches caches;
  const dagr::Bytes out = a.serialize_with_header(b, caches, [&](std::size_t root_offset, dagr::Bytes body) {
    mac = sign(key, root_offset, body);
    return ar::Jws{alg, KID, dagr::Bytes(mac.data(), mac.size())};
  });
  if (!b.ok()) {
    std::fprintf(stderr, "mint failed\n");
    std::exit(2);
  }
  return std::vector<std::uint8_t>(out.data(), out.data() + out.size());
}

enum class Rejected { None, BadAlg, BadSignature, Expired, WrongAudience };

const char* name(Rejected r) {
  switch (r) {
    case Rejected::BadAlg: return "BadAlg";
    case Rejected::BadSignature: return "BadSignature";
    case Rejected::Expired: return "Expired";
    case Rejected::WrongAudience: return "WrongAudience";
    default: return "None";
  }
}

const char* stage(Rejected r) {
  return r == Rejected::BadAlg || r == Rejected::BadSignature ? "GATE (verify-before-parse)" : "post-decode claim check";
}

std::size_t body_start(const std::vector<std::uint8_t>& token) {
  const dagr::Bytes buf(token.data(), token.size());
  const auto frame = dagr::header_frame(buf);
  return frame.value().start + frame.value().span;
}

// Verify-before-parse through the lazy reader: the gate reads only the header, then the
// claims are read in place — no restore.
Rejected verify(const std::vector<std::uint8_t>& token, std::string_view key, std::uint64_t now) {
  const dagr::Bytes buf(token.data(), token.size());
  const auto frame = dagr::header_frame(buf);
  const auto h = tok::open_token_header(buf);
  if (!frame || !h) return Rejected::BadSignature;
  if (h.value().algorithm() != "HS256") return Rejected::BadAlg;
  const std::size_t body_at = frame.value().start + frame.value().span;
  const dagr::Bytes body(token.data() + body_at, token.size() - body_at);
  const auto want = sign(key, frame.value().root_offset, body);
  const dagr::Bytes sig = h.value().signature();
  if (!dst_mac_equal(sig.data(), sig.size(), want.data())) return Rejected::BadSignature;
  const auto c = tok::open_token(buf);
  if (!c) return Rejected::BadSignature;
  if (now >= c.value().expires_at()) return Rejected::Expired;
  if (c.value().audience() != std::optional<std::string_view>("dagr-api")) return Rejected::WrongAudience;
  return Rejected::None;
}

std::string quote(std::string_view s) {
  std::string out = "\"";
  for (char ch : s) {
    if (ch == '"' || ch == '\\') out += '\\';
    out += ch;
  }
  return out + "\"";
}

std::string json(const tok::JsonPackedView& j) {
  switch (j.tag()) {
    case tok::JsonTag::String: return quote(j.string().value_or(""));
    case tok::JsonTag::Number: {
      const double n = j.number().value_or(0);
      char buf[64];
      if (n == std::floor(n)) std::snprintf(buf, sizeof buf, "%.0f", n); else std::snprintf(buf, sizeof buf, "%g", n);
      return buf;
    }
    case tok::JsonTag::Bool: return j.bool_().value_or(false) ? "true" : "false";
    case tok::JsonTag::Array: {
      std::string out = "[";
      bool first = true;
      if (const auto a = j.array()) {
        for (const std::optional<tok::JsonPackedView>& e : *a) {
          if (!first) out += ",";
          first = false;
          out += e ? json(*e) : "null";
        }
      }
      return out + "]";
    }
    case tok::JsonTag::Object: {
      std::string out = "{";
      bool first = true;
      if (const auto o = j.object()) {
        for (const tok::JsonMemberAccessor& m : *o) {
          if (!first) out += ",";
          first = false;
          const auto v = m.value();
          out += quote(m.key()) + ":" + (v ? json(*v) : "null");
        }
      }
      return out + "}";
    }
    case tok::JsonTag::Data: {
      std::string out = "0x";
      char hex[3];
      if (const auto d = j.data()) {
        for (std::uint8_t byte : *d) {
          std::snprintf(hex, sizeof hex, "%02x", byte);
          out += hex;
        }
      }
      return out;
    }
  }
  return "?";
}

void report(const std::string& label, const std::vector<std::uint8_t>& token, Rejected r) {
  if (r != Rejected::None) {
    std::printf("  %-20s REJECT  [%s] %s\n", label.c_str(), stage(r), name(r));
    return;
  }
  const auto c = tok::open_token(dagr::Bytes(token.data(), token.size())).value();
  const auto custom = c.custom();
  std::printf("  %-20s ACCEPT  sub=%s custom=%s\n", label.c_str(), quote(c.subject().value_or("")).c_str(),
              custom ? json(*custom).c_str() : "-");
}

template <class F>
long long time_ns(int iters, F&& f) {
  for (int i = 0; i < iters / 10; i++) f();
  const auto t = std::chrono::steady_clock::now();
  for (int i = 0; i < iters; i++) f();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - t).count() / iters;
}

volatile std::size_t bench_sink = 0;

// mint (arena + serialize_with_header + HMAC) and verify (header gate + lazy reads), 50k reps
// each after a warm-up, correctness-gated first. Prints the line run_bench.sh tabulates.
int bench() {
  const int n = 50000;
  const auto tok = mint(SECRET, "HS256", EXP);
  if (verify(tok, SECRET, NOW) != Rejected::None || verify(mint(SECRET, "HS256", NOW - 1), SECRET, NOW) == Rejected::None) {
    std::fprintf(stderr, "bench: correctness gate failed\n");
    return 1;
  }
  const long long m = time_ns(n, [] { bench_sink = bench_sink + mint(SECRET, "HS256", EXP).size(); });
  const long long v = time_ns(n, [&] { bench_sink = bench_sink + static_cast<std::size_t>(verify(tok, SECRET, NOW)); });
  std::printf("BENCH cpp dagr mint=%lld verify=%lld size=%zu\n", m, v, tok.size());
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 1 && std::string_view(argv[1]) == "bench") return bench();
  if (argc > 2 && std::string_view(argv[1]) == "emit") {
    const auto token = mint(SECRET, "HS256", EXP);
    std::ofstream(argv[2], std::ios::binary).write(reinterpret_cast<const char*>(token.data()), static_cast<std::streamsize>(token.size()));
    std::printf("[cpp] emitted -> %s\n", argv[2]);
    return 0;
  }
  if (argc > 2 && std::string_view(argv[1]) == "verify") {
    std::ifstream in(argv[2], std::ios::binary);
    const std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const Rejected r = verify(data, SECRET, NOW);
    report(std::string("[cpp] ") + argv[2], data, r);
    return r == Rejected::None ? 0 : 1;
  }

  std::printf("== dagr-signed-token — C++ ==\n\n");
  const auto token = mint(SECRET, "HS256", EXP);
  std::printf("Minted token: %zu bytes\n\nVerification:\n", token.size());
  report("valid token", token, verify(token, SECRET, NOW));
  auto tampered = token;
  tampered[body_start(tampered)] ^= 0x01;
  report("tampered body", tampered, verify(tampered, SECRET, NOW));
  report("wrong key", token, verify(token, "not-the-secret", NOW));
  const auto none = mint(SECRET, "none", EXP);
  report("alg:none token", none, verify(none, SECRET, NOW));
  const auto expired = mint(SECRET, "HS256", NOW - 1);
  report("expired token", expired, verify(expired, SECRET, NOW));
  return 0;
}
