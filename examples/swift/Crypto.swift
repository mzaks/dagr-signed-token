// HS256 via CryptoKit (an Apple system framework — no package dependency). That
// this and Rust's hand-rolled HMAC produce the same signature is the point:
// HMAC-SHA256 is a standard, so the tokens come out byte-identical.
import Foundation
import CryptoKit

func hmacSHA256(key: Data, msg: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
}

func hmacValid(key: Data, msg: Data, tag: Data) -> Bool {
    HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: msg, using: SymmetricKey(data: key))
}
