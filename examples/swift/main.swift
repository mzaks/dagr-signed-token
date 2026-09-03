// dagr-signed-token — Swift example (see ../../CONTRACT.md). Compiled together with
// the generated sources in gen/swift/Sources/dagr_signed_token/ (see run_cross_lang.sh),
// so the `Token` namespace is available directly.
//
// CLI:  dst-swift            → showcase
//       dst-swift emit  PATH → write a valid token
//       dst-swift verify PATH → verify+decode a token minted by any language
import Foundation

enum B {}

let SECRET = Data("dagr-signed-token-demo-secret-2026".utf8)
let KID = "hmac-key-2026"
let NOW: UInt64 = 1_760_000_000
let EXP: UInt64 = NOW + 3600

func preimage(_ rootOffset: Int, _ body: Data) -> Data {
    var m = Data()
    var off = UInt64(rootOffset).littleEndian
    withUnsafeBytes(of: &off) { m.append(contentsOf: $0) }
    m.append(body)
    return m
}

func mint(secret: Data, alg: String, exp: UInt64) throws -> Data {
    let a = Token.Arena<B>()
    let custom = Token.Json<Token.Arena<B>>.object([
        a.newJsonMember(key: "tenant", value: .string("acme")),
        a.newJsonMember(key: "roles", value: .array([.string("admin"), .string("billing")])),
        a.newJsonMember(key: "mfa", value: .bool(true)),
    ])
    a.root = a.newClaims(
        subject: "user-42",
        issuer: "https://issuer.dagr.one",
        audience: "dagr-api",
        issuedAt: NOW,
        expiresAt: exp,
        scopes: ["read:profile", "write:posts"],
        custom: custom)
    return try a.toData(header: { rootOffset, body in
        Token.Jws(algorithm: alg, keyId: KID,
                  signature: hmacSHA256(key: secret, msg: preimage(rootOffset, body)))
    })
}

// Direct Graph Builder ("31 Direct Graph Builder.md"): mint the SAME token from a plain
// value tree, arena-free. Must be byte-identical to `mint` (spec §6 gate).
func mintDirect(secret: Data, alg: String, exp: UInt64) throws -> Data {
    let custom = Token.Direct.Json.object([
        Token.Direct.JsonMember(key: "tenant", value: .string("acme")),
        Token.Direct.JsonMember(key: "roles", value: .array([.string("admin"), .string("billing")])),
        Token.Direct.JsonMember(key: "mfa", value: .bool(true)),
    ])
    let claims = Token.Direct.Claims(
        subject: "user-42",
        issuer: "https://issuer.dagr.one",
        audience: "dagr-api",
        issuedAt: NOW,
        expiresAt: exp,
        scopes: ["read:profile", "write:posts"],
        custom: custom)
    return try Token.Direct.toData(claims, header: { rootOffset, body in
        Token.Jws(algorithm: alg, keyId: KID,
                  signature: hmacSHA256(key: secret, msg: preimage(rootOffset, body)))
    })
}

enum Rejected: String, Error {
    case badAlg, badSignature, expired, wrongAudience
    var stage: String {
        switch self {
        case .badAlg, .badSignature: return "GATE (verify-before-parse)"
        case .expired, .wrongAudience: return "post-decode claim check"
        }
    }
}

// Verify-before-parse, then read claims with ZERO-ALLOC LAZY ACCESSORS — no arena restore.
// `Token.lazyRoot(from:header:)` runs the crypto GATE before returning a `ClaimsAccessor`
// that reads fields straight off the token buffer on demand.
func verify(_ token: Data, secret: Data, now: UInt64) -> Result<Token.ClaimsAccessor, Rejected> {
    var reason: Rejected?
    do {
        let c = try Token.lazyRoot(from: token, header: { h, rootOffset, body in
            if h.algorithm != "HS256" { reason = .badAlg; throw Rejected.badAlg }
            if !hmacValid(key: secret, msg: preimage(rootOffset, body), tag: h.signature) {
                reason = .badSignature; throw Rejected.badSignature
            }
        })
        if now >= (try c.expiresAt) { return .failure(.expired) }
        if (try c.audience) != "dagr-api" { return .failure(.wrongAudience) }
        return .success(c)
    } catch {
        return .failure(reason ?? .badSignature)
    }
}

// Lazy render of the packed-JSON `custom` claim — walks the buffer, no owned graph.
// The lazy accessors are `get throws` (malformed-buffer safe), hence `throws` here.
func jsonStr(_ j: Token.JsonPackedAccessor?) throws -> String {
    switch j {
    case .string(let s): return "\"\(s)\""
    case .number(let n): return "\(n)"
    case .bool(let b):   return "\(b)"
    case .array(let a):  return try "[" + a.map { try jsonStr($0) }.joined(separator: ",") + "]"
    case .object(let o): return try "{" + o.map { try "\"\($0.key)\":\(jsonStr($0.value))" }.joined(separator: ",") + "}"
    case .none: return "-"
    }
}

func report(_ label: String, _ r: Result<Token.ClaimsAccessor, Rejected>) {
    let tag = label.padding(toLength: 22, withPad: " ", startingAt: 0)
    switch r {
    case .success(let c):
        let customStr = (try? jsonStr((try? c.custom) ?? nil)) ?? "-"
        print("  \(tag) ACCEPT  sub=\(c.subject ?? "-") custom=\(customStr)")
    case .failure(let e):
        print("  \(tag) REJECT  [\(e.stage)] \(e.rawValue)")
    }
}

do {
    let args = CommandLine.arguments
    if args.count >= 2, args[1] == "direct" {
        let a = try mint(secret: SECRET, alg: "HS256", exp: EXP)
        let d = try mintDirect(secret: SECRET, alg: "HS256", exp: EXP)
        if a == d {
            print("[swift] direct == arena (\(d.count) bytes) — spec 31 gate OK")
        } else {
            print("[swift] direct != arena (arena \(a.count) vs direct \(d.count))")
            exit(1)
        }
    } else if args.count >= 3, args[1] == "emit" {
        try mint(secret: SECRET, alg: "HS256", exp: EXP).write(to: URL(fileURLWithPath: args[2]))
        print("[swift] emitted -> \(args[2])")
    } else if args.count >= 3, args[1] == "verify" {
        let data = try Data(contentsOf: URL(fileURLWithPath: args[2]))
        let r = verify(data, secret: SECRET, now: NOW)
        report("[swift] \(args[2])", r)
        if case .failure = r { exit(1) }
    } else {
        print("== dagr-signed-token — Swift ==\n")
        let token = try mint(secret: SECRET, alg: "HS256", exp: EXP)
        print("Minted token: \(token.count) bytes\n")
        print("Verification:")
        report("valid token", verify(token, secret: SECRET, now: NOW))
        var tampered = token
        let (_, rl) = try restoreLEB(from: token, at: 0)
        let (hcs, hcsB) = try restoreLEB(from: token, at: rl)
        tampered[rl + hcsB + Int(hcs)] ^= 0x01
        report("tampered body", verify(tampered, secret: SECRET, now: NOW))
        report("wrong key", verify(token, secret: Data("not-the-secret".utf8), now: NOW))
        report("alg:none token", verify(try mint(secret: SECRET, alg: "none", exp: EXP), secret: SECRET, now: NOW))
        report("expired token", verify(try mint(secret: SECRET, alg: "HS256", exp: NOW - 1), secret: SECRET, now: NOW))
    }
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(2)
}
