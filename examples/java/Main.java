// dagr-signed-token — Java example. Mints and verifies the shared token (see
// ../../CONTRACT.md). The codec is the generated `token` package (gen/java): the arena
// writes the token with its header, and the verifier's gate checks the header through the
// lazy reader before the body is read. HMAC-SHA256 is the JDK's (javax.crypto).
//
// CLI:  Main             → run the showcase (mint, verify, tamper, alg:none, expiry)
//       Main emit   PATH → write a valid token to PATH
//       Main verify PATH → verify+decode a token minted by any language
//       Main bench       → mint + verify, 50k reps each, ns/op (for run_bench.sh)

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import dagr.runtime.Builder;
import dagr.runtime.GraphWriter;
import dagr.runtime.Reader;
import token.Token;
import token.TokenArena;

public final class Main {
  static final byte[] SECRET = "dagr-signed-token-demo-secret-2026".getBytes(StandardCharsets.US_ASCII);
  static final String KID = "hmac-key-2026";
  static final long NOW = 1_760_000_000L;
  static final long EXP = NOW + 3600;

  /** preimage(rootOffset, body) = LE_u64(rootOffset) ++ body  (see CONTRACT.md). */
  static byte[] preimage(long rootOffset, byte[] body) {
    return ByteBuffer.allocate(8 + body.length).order(ByteOrder.LITTLE_ENDIAN)
        .putLong(rootOffset).put(body).array();
  }

  static byte[] hmacSha256(byte[] key, byte[] msg) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(msg);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static TokenArena.JsonMemberHandle member(TokenArena a, String key, TokenArena.JsonValue value) {
    TokenArena.JsonMemberHandle m = a.newJsonMember();
    m.setKey(key);
    m.setValue(value);
    return m;
  }

  static byte[] mint(byte[] key, String alg, long exp) {
    TokenArena a = new TokenArena();
    // custom = { "tenant": "acme", "roles": ["admin", "billing"], "mfa": true, "fp": 0xdeadbeef }
    TokenArena.JsonValue custom = new TokenArena.JsonValue.Object_(new TokenArena.JsonMemberHandle[] {
        member(a, "tenant", new TokenArena.JsonValue.String_("acme")),
        member(a, "roles", new TokenArena.JsonValue.Array(new TokenArena.JsonValue[] {
            new TokenArena.JsonValue.String_("admin"),
            new TokenArena.JsonValue.String_("billing"),
        })),
        member(a, "mfa", new TokenArena.JsonValue.Bool(true)),
        member(a, "fp", new TokenArena.JsonValue.Data(new byte[] {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF})),
    });
    TokenArena.ClaimsHandle c = a.newClaims();
    c.setSubject("user-42");
    c.setIssuer("https://issuer.dagr.one");
    c.setAudience("dagr-api");
    c.setIssuedAt(NOW);
    c.setExpiresAt(exp);
    c.setScopes(new String[] {"read:profile", "write:posts"});
    c.setCustom(custom);
    a.setRoot(c);
    MemorySegment out = a.serializeWithHeader(new GraphWriter(Builder.growing()), (rootOffset, body) -> {
      TokenArena.Jws h = new TokenArena.Jws();
      h.algorithm = alg;
      h.keyId = KID;
      h.signature = MemorySegment.ofArray(hmacSha256(key, preimage(rootOffset, body.toArray(ValueLayout.JAVA_BYTE))));
      return h;
    });
    return out.toArray(ValueLayout.JAVA_BYTE);
  }

  enum Rejected {
    BadAlg, BadSignature, Expired, WrongAudience;

    String stage() {
      return this == BadAlg || this == BadSignature ? "GATE (verify-before-parse)" : "post-decode claim check";
    }
  }

  static long bodyStart(MemorySegment buf) {
    return Reader.headerStart(buf) + Reader.headerSpan(buf);
  }

  /** Verify-before-parse through the lazy reader: the gate reads only the header, then the
   *  claims are read in place — no restore. Returns null when the token is accepted. */
  static Rejected verify(byte[] token, byte[] key, long now) {
    MemorySegment buf = MemorySegment.ofArray(token);
    if (Token.headerStatus(buf) != dagr.runtime.Status.OK) return Rejected.BadSignature;
    Token.JwsAccessor h = Token.openHeader(buf);
    if (!h.algorithm().equals("HS256")) return Rejected.BadAlg;
    byte[] body = buf.asSlice(bodyStart(buf)).toArray(ValueLayout.JAVA_BYTE);
    byte[] expected = hmacSha256(key, preimage(Reader.headerRootOffset(buf), body));
    if (!MessageDigest.isEqual(h.signature().toArray(ValueLayout.JAVA_BYTE), expected)) return Rejected.BadSignature;
    Token.ClaimsAccessor c = Token.open(buf);
    if (now >= c.expiresAt()) return Rejected.Expired;
    if (!c.hasAudience() || !c.audience().equals("dagr-api")) return Rejected.WrongAudience;
    return null;
  }

  static String quote(String s) {
    return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }

  static String json(Token.JsonPackedView j) {
    switch (j.tag()) {
      case 0: return quote(j.string());
      case 1: {
        double n = j.number();
        return n == Math.rint(n) ? Long.toString((long) n) : Double.toString(n);
      }
      case 2: return Boolean.toString(j.bool());
      case 3: {
        List<String> parts = new ArrayList<>();
        Token.JsonPackedArray a = j.array();
        while (a.next()) parts.add(a.present() ? json(a.value()) : "null");
        return "[" + String.join(",", parts) + "]";
      }
      case 4: {
        List<String> parts = new ArrayList<>();
        Token.JsonMemberPackedArray o = j.object();
        while (o.next()) {
          Token.JsonMemberAccessor m = o.value();
          parts.add(quote(m.key()) + ":" + (m.hasValue() ? json(m.value()) : "null"));
        }
        return "{" + String.join(",", parts) + "}";
      }
      case 5: {
        StringBuilder sb = new StringBuilder("0x");
        for (byte b : j.data().toArray(ValueLayout.JAVA_BYTE)) sb.append(String.format("%02x", b));
        return sb.toString();
      }
      default: return "?";
    }
  }

  static void report(String label, byte[] token, Rejected r) {
    if (r != null) {
      System.out.printf("  %-20s REJECT  [%s] %s%n", label, r.stage(), r);
      return;
    }
    Token.ClaimsAccessor c = Token.open(MemorySegment.ofArray(token));
    System.out.printf("  %-20s ACCEPT  sub=%s custom=%s%n", label, quote(c.subject()),
        c.hasCustom() ? json(c.custom()) : "-");
  }

  static long sink;

  static long timeNs(int iters, Runnable f) {
    for (int i = 0; i < iters; i++) f.run();   // a full round of warm-up: the JIT compiles first
    long t = System.nanoTime();
    for (int i = 0; i < iters; i++) f.run();
    return (System.nanoTime() - t) / iters;
  }

  /** mint (arena + serializeWithHeader + HMAC) and verify (header gate + lazy reads), 50k
   *  reps each after a warm-up, correctness-gated first. Prints the line run_bench.sh tabulates. */
  static void bench() {
    final int n = 50_000;
    final byte[] tok = mint(SECRET, "HS256", EXP);
    if (verify(tok, SECRET, NOW) != null || verify(mint(SECRET, "HS256", NOW - 1), SECRET, NOW) == null) {
      throw new IllegalStateException("bench: correctness gate failed");
    }
    long m = timeNs(n, () -> sink += mint(SECRET, "HS256", EXP).length);
    long v = timeNs(n, () -> sink += verify(tok, SECRET, NOW) == null ? 1 : 0);
    System.out.printf("BENCH java dagr mint=%d verify=%d size=%d%n", m, v, tok.length);
  }

  public static void main(String[] args) throws Exception {
    if (args.length > 0 && args[0].equals("bench")) {
      bench();
      return;
    }
    if (args.length > 1 && args[0].equals("emit")) {
      Files.write(Path.of(args[1]), mint(SECRET, "HS256", EXP));
      System.out.println("[java] emitted -> " + args[1]);
      return;
    }
    if (args.length > 1 && args[0].equals("verify")) {
      byte[] data = Files.readAllBytes(Path.of(args[1]));
      Rejected r = verify(data, SECRET, NOW);
      report("[java] " + args[1], data, r);
      System.exit(r == null ? 0 : 1);
    }

    System.out.println("== dagr-signed-token — Java ==\n");
    byte[] token = mint(SECRET, "HS256", EXP);
    System.out.println("Minted token: " + token.length + " bytes\n");
    System.out.println("Verification:");
    report("valid token", token, verify(token, SECRET, NOW));
    byte[] tampered = token.clone();
    tampered[(int) bodyStart(MemorySegment.ofArray(tampered))] ^= 0x01;
    report("tampered body", tampered, verify(tampered, SECRET, NOW));
    report("wrong key", token, verify(token, "not-the-secret".getBytes(StandardCharsets.US_ASCII), NOW));
    byte[] none = mint(SECRET, "none", EXP);
    report("alg:none token", none, verify(none, SECRET, NOW));
    byte[] expired = mint(SECRET, "HS256", NOW - 1);
    report("expired token", expired, verify(expired, SECRET, NOW));
  }
}
