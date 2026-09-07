// HS256 for the Swift example — zero package dependencies on BOTH platforms, so the demo
// and the cross-language gate keep building with plain `swiftc` (no SwiftPM, no swift-crypto).
//
// macOS: CommonCrypto's `CCHmac` (an Apple system framework — no package dependency).
// CommonCrypto is a thin C API: one call writing the tag into a stack buffer, with none of
// CryptoKit's per-call `SymmetricKey`/`Data` bridging overhead (which measured ~1.5–1.8µs/op
// and dominated both mint and verify).
//
// Linux: CommonCrypto does not exist, so SHA-256/HMAC are hand-rolled below — exactly what
// the Rust demo does in `src/sha256.rs`, and for the same reason. Small and readable, NOT
// hardened production crypto; for real systems use a vetted library (swift-crypto here).
//
// Either way the signature is standard HMAC-SHA256, so the tokens stay byte-identical to
// every other language's.
import Foundation

#if canImport(CommonCrypto)
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

#else

// ── Hand-rolled SHA-256 (FIPS 180-4) + HMAC-SHA256 (RFC 2104) ─────────────────

private let K: [UInt32] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

/// The eight-word running state, kept in stored properties rather than an array so the
/// compression loop is register traffic with no bounds checks.
private struct SHA256State {
    var a: UInt32 = 0x6a09e667, b: UInt32 = 0xbb67ae85, c: UInt32 = 0x3c6ef372, d: UInt32 = 0xa54ff53a
    var e: UInt32 = 0x510e527f, f: UInt32 = 0x9b05688c, g: UInt32 = 0x1f83d9ab, h: UInt32 = 0x5be0cd19
}

@inline(__always)
private func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 &- n)) }

/// Compress one 64-byte block at `p` into `st`. `w` (64 words of schedule scratch) and `k`
/// (the round constants) are caller-owned, so a multi-block hash pays for neither per block.
@inline(__always)
private func compress(_ st: inout SHA256State,
                      _ p: UnsafeRawPointer,
                      _ w: UnsafeMutablePointer<UInt32>,
                      _ k: UnsafePointer<UInt32>) {
    for i in 0..<16 {                                   // W[0..15] = the block, big-endian
        w[i] = UInt32(bigEndian: p.loadUnaligned(fromByteOffset: i * 4, as: UInt32.self))
    }
    for i in 16..<64 {                                  // W[16..63] = the schedule expansion
        let x = w[i - 15], y = w[i - 2]
        let s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
        let s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10)
        w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
    }
    var a = st.a, b = st.b, c = st.c, d = st.d
    var e = st.e, f = st.f, g = st.g, h = st.h
    for i in 0..<64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        let ch = (e & f) ^ (~e & g)
        let t1 = h &+ s1 &+ ch &+ k[i] &+ w[i]
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        let maj = (a & b) ^ (a & c) ^ (b & c)
        let t2 = s0 &+ maj
        h = g; g = f; f = e; e = d &+ t1
        d = c; c = b; b = a; a = t1 &+ t2
    }
    st.a &+= a; st.b &+= b; st.c &+= c; st.d &+= d
    st.e &+= e; st.f &+= f; st.g &+= g; st.h &+= h
}

/// SHA-256 over `block ++ message`, written as 32 bytes to `out`. `block`, when given, is
/// exactly 64 bytes (an HMAC ipad/opad key block), so the concatenation is never
/// materialised — it is simply the first compression. Pass `nil` for a plain SHA-256.
/// Writing into caller memory keeps the whole HMAC free of intermediate heap buffers.
private func sha256(block: UnsafeRawPointer?,
                    message: UnsafeRawBufferPointer,
                    into out: UnsafeMutablePointer<UInt8>) {
    var st = SHA256State()
    let prefixLen = block == nil ? 0 : 64
    let msgLen = message.count
    K.withUnsafeBufferPointer { kbuf in
        let k = kbuf.baseAddress!
        withUnsafeTemporaryAllocation(of: UInt32.self, capacity: 64) { wbuf in
            let w = wbuf.baseAddress!
            if let block { compress(&st, block, w, k) }
            var off = 0
            while off + 64 <= msgLen {                  // full blocks straight from the caller
                compress(&st, message.baseAddress! + off, w, k)
                off += 64
            }
            // Tail: the remainder, 0x80, zero padding, and the 64-bit big-endian bit length.
            // Two blocks of scratch cover the case where the length field does not fit.
            let rem = msgLen - off
            withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 128) { padbuf in
                let pad = padbuf.baseAddress!
                pad.update(repeating: 0, count: 128)
                if rem > 0 {
                    UnsafeMutableRawPointer(pad).copyMemory(from: message.baseAddress! + off, byteCount: rem)
                }
                pad[rem] = 0x80
                let padLen = rem < 56 ? 64 : 128
                var bits = (UInt64(prefixLen + msgLen) &* 8).bigEndian
                withUnsafeBytes(of: &bits) {
                    UnsafeMutableRawPointer(pad + padLen - 8).copyMemory(from: $0.baseAddress!, byteCount: 8)
                }
                compress(&st, pad, w, k)
                if padLen == 128 { compress(&st, pad + 64, w, k) }
            }
        }
    }
    let o = UnsafeMutableRawPointer(out)                 // H0..H7, big-endian
    o.storeBytes(of: st.a.bigEndian, toByteOffset:  0, as: UInt32.self)
    o.storeBytes(of: st.b.bigEndian, toByteOffset:  4, as: UInt32.self)
    o.storeBytes(of: st.c.bigEndian, toByteOffset:  8, as: UInt32.self)
    o.storeBytes(of: st.d.bigEndian, toByteOffset: 12, as: UInt32.self)
    o.storeBytes(of: st.e.bigEndian, toByteOffset: 16, as: UInt32.self)
    o.storeBytes(of: st.f.bigEndian, toByteOffset: 20, as: UInt32.self)
    o.storeBytes(of: st.g.bigEndian, toByteOffset: 24, as: UInt32.self)
    o.storeBytes(of: st.h.bigEndian, toByteOffset: 28, as: UInt32.self)
}

/// HMAC-SHA256 (RFC 2104) -> 32-byte tag. The ipad/opad key blocks and the inner digest all
/// live in one temporary allocation, so the only heap traffic is the returned `Data`.
func hmacSHA256(key: Data, msg: Data) -> Data {
    var tag = Data(count: 32)
    withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 160) { scratch in
        let ipad = scratch.baseAddress!, opad = ipad + 64, inner = opad + 64
        ipad.update(repeating: 0x36, count: 64)          // 0x36 where the key runs out
        opad.update(repeating: 0x5c, count: 64)
        key.withUnsafeBytes { (k: UnsafeRawBufferPointer) in
            if k.count > 64 {                            // over-long keys are replaced by their digest
                sha256(block: nil, message: k, into: inner)
                for i in 0..<32 { ipad[i] ^= inner[i]; opad[i] ^= inner[i] }
            } else {
                for i in 0..<k.count { ipad[i] ^= k[i]; opad[i] ^= k[i] }
            }
        }
        msg.withUnsafeBytes { m in sha256(block: ipad, message: m, into: inner) }
        tag.withUnsafeMutableBytes { t in
            sha256(block: opad,
                   message: UnsafeRawBufferPointer(start: inner, count: 32),
                   into: t.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }
    }
    return tag
}

#endif

func hmacValid(key: Data, msg: Data, tag: Data) -> Bool {
    let mac = hmacSHA256(key: key, msg: msg)
    guard mac.count == tag.count else { return false }
    // Constant-time compare: XOR-accumulate every byte, no early exit. Both sides are read
    // through `withUnsafeBytes` — `Data`'s own subscript re-resolves its (possibly
    // discontiguous) backing on each access, which measured as most of verify's HMAC cost.
    var diff: UInt8 = 0
    mac.withUnsafeBytes { (m: UnsafeRawBufferPointer) in
        tag.withUnsafeBytes { (t: UnsafeRawBufferPointer) in
            for i in 0..<m.count { diff |= m[i] ^ t[i] }
        }
    }
    return diff == 0
}
