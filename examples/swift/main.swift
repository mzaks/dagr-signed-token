// dagr-web-token — Swift example (see ../../CONTRACT.md). Compiled together with
// the generated sources in gen/swift/Sources/dagr_web_token/ (see run_cross_lang.sh),
// so the `Token` namespace is available directly.
//
// CLI:  dwt-swift            → showcase
//       dwt-swift emit  PATH → write a valid token
//       dwt-swift verify PATH → verify+decode a token minted by any language
import Foundation

enum B {}

let SECRET = Data("dagr-web-token-demo-secret-2026".utf8)
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

enum Rejected: String, Error {
    case badAlg, badSignature, expired, wrongAudience
    var stage: String {
        switch self {
        case .badAlg, .badSignature: return "GATE (verify-before-parse)"
        case .expired, .wrongAudience: return "post-decode claim check"
        }
    }
}

func verify(_ token: Data, secret: Data, now: UInt64) -> Result<Token.Arena<B>, Rejected> {
    var reason: Rejected?
    do {
        let a = try Token.Arena<B>.restore(from: token, header: { h, rootOffset, body in
            if h.algorithm != "HS256" { reason = .badAlg; throw Rejected.badAlg }
            if !hmacValid(key: secret, msg: preimage(rootOffset, body), tag: h.signature) {
                reason = .badSignature; throw Rejected.badSignature
            }
        })
        let c = a.root!
        if now >= c.expiresAt { return .failure(.expired) }
        if c.audience != "dagr-api" { return .failure(.wrongAudience) }
        return .success(a)
    } catch {
        return .failure(reason ?? .badSignature)
    }
}

func jsonStr(_ j: Token.Json<Token.Arena<B>>?) -> String {
    switch j {
    case .string(let s): return "\"\(s)\""
    case .number(let n): return "\(n)"
    case .bool(let b):   return "\(b)"
    case .array(let a):  return "[" + a.map { jsonStr($0) }.joined(separator: ",") + "]"
    case .object(let o): return "{" + o.map { "\"\($0.key)\":\(jsonStr($0.value))" }.joined(separator: ",") + "}"
    case .unknown, .none: return "-"
    }
}

func report(_ label: String, _ r: Result<Token.Arena<B>, Rejected>) {
    let tag = label.padding(toLength: 22, withPad: " ", startingAt: 0)
    switch r {
    case .success(let a):
        let c = a.root!
        print("  \(tag) ACCEPT  sub=\(c.subject ?? "-") custom=\(jsonStr(c.custom))")
    case .failure(let e):
        print("  \(tag) REJECT  [\(e.stage)] \(e.rawValue)")
    }
}

do {
    let args = CommandLine.arguments
    if args.count >= 3, args[1] == "emit" {
        try mint(secret: SECRET, alg: "HS256", exp: EXP).write(to: URL(fileURLWithPath: args[2]))
        print("[swift] emitted -> \(args[2])")
    } else if args.count >= 3, args[1] == "verify" {
        let data = try Data(contentsOf: URL(fileURLWithPath: args[2]))
        let r = verify(data, secret: SECRET, now: NOW)
        report("[swift] \(args[2])", r)
        if case .failure = r { exit(1) }
    } else {
        print("== dagr-web-token — Swift ==\n")
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
