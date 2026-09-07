// HS256 via CommonCrypto's `CCHmac` (an Apple system framework — no package dependency).
// CommonCrypto is a thin C API: one call writing the tag into a stack buffer, with none of
// CryptoKit's per-call `SymmetricKey`/`Data` bridging overhead (which measured ~1.5–1.8µs/op
// and dominated both mint and verify). The signature is still standard HMAC-SHA256, so the
// tokens stay byte-identical to Rust's hand-rolled HMAC.
import Foundation
import CommonCrypto

@inline(__always)
func hmacSHA256(key: Data, msg: Data) -> Data {
    var out = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    out.withUnsafeMutableBytes { (o: UnsafeMutableRawBufferPointer) in
        key.withUnsafeBytes { (k: UnsafeRawBufferPointer) in
            msg.withUnsafeBytes { (m: UnsafeRawBufferPointer) in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
                       k.baseAddress, k.count, m.baseAddress, m.count,
                       o.baseAddress)
            }
        }
    }
    return out
}

func hmacValid(key: Data, msg: Data, tag: Data) -> Bool {
    let mac = hmacSHA256(key: key, msg: msg)
    guard mac.count == tag.count else { return false }
    var diff: UInt8 = 0                                  // constant-time compare
    for i in 0..<mac.count { diff |= mac[mac.startIndex + i] ^ tag[tag.startIndex + i] }
    return diff == 0
}
