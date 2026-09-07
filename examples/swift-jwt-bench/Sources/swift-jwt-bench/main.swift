// JWT baseline (JWTKit / HS256) — same claims as the Dagr token, real signing library.
// Mirrors examples/rust/src/jwt.rs (jsonwebtoken): flat registered + custom claims, HMAC.
// Prints `BENCH swift jwt mint=<ns> verify=<ns> size=<bytes>` for run_bench.sh.
import Foundation
import JWTKit

let SECRET = "dagr-signed-token-demo-secret-2026"
let NOW: Int = 1_760_000_000

struct Expired: Error {}

struct TokenPayload: JWTPayload {
    var sub: String
    var iss: String
    var aud: String
    var iat: Int
    var exp: Int
    var scopes: [String]
    var tenant: String
    var roles: [String]
    var mfa: Bool
    var fp: String

    func verify(using key: some JWTAlgorithm) async throws {
        // jsonwebtoken validates signature (done by JWTKit) + exp; match that.
        if Double(exp) < Date().timeIntervalSince1970 { throw Expired() }
    }
}

func claims(_ exp: Int) -> TokenPayload {
    TokenPayload(
        sub: "user-42", iss: "https://issuer.dagr.one", aud: "dagr-api",
        iat: NOW, exp: exp,
        scopes: ["read:profile", "write:posts"],
        tenant: "acme", roles: ["admin", "billing"], mfa: true, fp: "0xdeadbeef")
}

func nowSecs() -> Int { Int(Date().timeIntervalSince1970) }

// Top-level async entry (main.swift supports top-level `await`).
let keys = JWTKeyCollection()
await keys.add(hmac: .init(from: SECRET), digestAlgorithm: .sha256)

// JWTKit validates exp against wall clock → mint valid at now + 1h.
let exp = nowSecs() + 3600
let tok = try await keys.sign(claims(exp))
_ = try await keys.verify(tok, as: TokenPayload.self)   // correctness gate

let n = 50_000
// mint
for _ in 0..<(n / 10) { _ = try await keys.sign(claims(exp)) }
var t0 = DispatchTime.now().uptimeNanoseconds
for _ in 0..<n { _ = try await keys.sign(claims(exp)) }
let mintNs = (DispatchTime.now().uptimeNanoseconds - t0) / UInt64(n)
// verify
for _ in 0..<(n / 10) { _ = try await keys.verify(tok, as: TokenPayload.self) }
t0 = DispatchTime.now().uptimeNanoseconds
for _ in 0..<n { _ = try await keys.verify(tok, as: TokenPayload.self) }
let verifyNs = (DispatchTime.now().uptimeNanoseconds - t0) / UInt64(n)

print("BENCH swift jwt mint=\(mintNs) verify=\(verifyNs) size=\(tok.utf8.count)")
