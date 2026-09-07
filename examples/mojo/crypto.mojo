# dagr-signed-token — native HMAC-SHA256 for the Mojo example (see ../../CONTRACT.md).
#
# This is the "HS256" of JWT, hand-rolled in plain Mojo: no FFI, no third-party crate, no
# system crypto library — the same zero-dependency stance the Rust example takes in
# `src/sha256.rs` and the Swift one in `Crypto.swift`. Because HMAC-SHA256 is a standard,
# the tags — and so the whole 207-byte token — stay byte-identical to every other language.
#
# Public surface (all the example needs):
#   Sha256                  streaming hash — update(Span) / finalize() -> 32 bytes
#   hmac_sha256             HMAC over a message List
#   hmac_sha256_preimage    HMAC over `LE_u64(root_off) ++ body`, the token's signing
#                           preimage, streamed so the preimage is never materialised
#
# NOT hardened production crypto (no key zeroisation, no side-channel review beyond the
# constant-time tag compare in the caller's gate). For real systems use a vetted library.
from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic
from std.memory import unsafe_memcpy, unsafe_memset_zero
from std.bit import rotate_bits_right

# ── Native hardware SHA-256 + HMAC-SHA256 (zero dependencies) ──────────────────
# SHA-256 built directly on whatever SHA acceleration the TARGET has, chosen at comptime
# so exactly one core is instantiated — the other backends' intrinsics never reach codegen
# on a machine that cannot execute them:
#
#   ARMv8-A + crypto  →  sha256h / sha256h2 / sha256su0 / sha256su1   (Apple Silicon, …)
#   x86-64 + SHA-NI   →  sha256rnds2 / sha256msg1 / sha256msg2        (AMD Zen, Intel …)
#   anything else     →  a portable scalar core (FIPS 180-4 straight, ~4-5× slower)
#
# Both hardware cores reach the SAME instructions `ring` gets to through hand-written asm,
# but in plain Mojo — no FFI, no third-party crate.
comptime _u32x4 = SIMD[DType.uint32, 4]

# (`is_apple_silicon` is listed first so Apple M parts keep the ARM core even if the
# toolchain ever stops reporting the generic `sha2` feature bit for them.)
comptime _ARM_SHA = CompilationTarget.is_apple_silicon() or (CompilationTarget.has_neon() and CompilationTarget._has_feature["sha2"]())
comptime _X86_SHA = CompilationTarget.is_x86() and CompilationTarget._has_feature["sha"]()

# ARMv8-A crypto extensions.
@always_inline
def _sha256h(a: _u32x4, b: _u32x4, c: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h", _u32x4, has_side_effect=False](a, b, c)
@always_inline
def _sha256h2(a: _u32x4, b: _u32x4, c: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h2", _u32x4, has_side_effect=False](a, b, c)
@always_inline
def _sha256su0(a: _u32x4, b: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su0", _u32x4, has_side_effect=False](a, b)
@always_inline
def _sha256su1(a: _u32x4, b: _u32x4, c: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su1", _u32x4, has_side_effect=False](a, b, c)

# x86-64 SHA-NI. `sha256rnds2` does two rounds: `a` carries (C,D,G,H), `b` carries
# (A,B,E,F), and `wk` supplies the two W+K dwords in its LOW two lanes (the implicit xmm0).
@always_inline
def _sha256rnds2(a: _u32x4, b: _u32x4, wk: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.x86.sha256rnds2", _u32x4, has_side_effect=False](a, b, wk)
@always_inline
def _sha256msg1(a: _u32x4, b: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.x86.sha256msg1", _u32x4, has_side_effect=False](a, b)
@always_inline
def _sha256msg2(a: _u32x4, b: _u32x4) -> _u32x4:
    return llvm_intrinsic["llvm.x86.sha256msg2", _u32x4, has_side_effect=False](a, b)

@always_inline
def _bswap4(w: _u32x4) -> _u32x4:                # byte-swap 4 lanes: LE-loaded words -> big-endian (rev32)
    return llvm_intrinsic["llvm.bswap.v4i32", _u32x4, has_side_effect=False](w)
@always_inline
def _bswap8(w: UInt64) -> UInt64:                # byte-swap a u64 (host-LE store of this = big-endian)
    return llvm_intrinsic["llvm.bswap.i64", UInt64, has_side_effect=False](w)

# The 64 round constants as 16 comptime vectors of 4 — baked in as immediates (like ring's
# static K table). No per-call heap List, no bounds-checked loads in the compression loop.
comptime _K0  = _u32x4(0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5)
comptime _K1  = _u32x4(0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5)
comptime _K2  = _u32x4(0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3)
comptime _K3  = _u32x4(0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174)
comptime _K4  = _u32x4(0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc)
comptime _K5  = _u32x4(0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da)
comptime _K6  = _u32x4(0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7)
comptime _K7  = _u32x4(0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967)
comptime _K8  = _u32x4(0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13)
comptime _K9  = _u32x4(0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85)
comptime _K10 = _u32x4(0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3)
comptime _K11 = _u32x4(0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070)
comptime _K12 = _u32x4(0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5)
comptime _K13 = _u32x4(0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3)
comptime _K14 = _u32x4(0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208)
comptime _K15 = _u32x4(0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

# Compress one 64-byte block into the running state, in whichever register layout this
# build's core uses (see _IV0/_IV1 below). Comptime dispatch: only the selected backend is
# instantiated, so e.g. an x86 build never asks LLVM to lower an aarch64 intrinsic.
@always_inline
def _block(mut s0: _u32x4, mut s1: _u32x4, blk: Span[UInt8, _], off: Int):
    comptime if _ARM_SHA:
        _block_arm(s0, s1, blk, off)
    elif _X86_SHA:
        _block_x86(s0, s1, blk, off)
    else:
        _block_scalar(s0, s1, blk, off)

# ── ARMv8 core — state (s0, s1) = (A..D, E..H) ────────────────────────────────
# The canonical 16-quad ARMv8 SHA-256 sequence (msg schedule via su0/su1, rounds via
# sha256h/h2).
@always_inline
def _block_arm(mut s0: _u32x4, mut s1: _u32x4, blk: Span[UInt8, _], off: Int):
    var abcd = s0
    var efgh = s1
    var bp = blk.unsafe_ptr()                    # vectorized big-endian load: 16-byte SIMD load + rev32 per quad
    var m0 = _bswap4(bp.unsafe_offset(off + 0 ).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]())
    var m1 = _bswap4(bp.unsafe_offset(off + 16).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]())
    var m2 = _bswap4(bp.unsafe_offset(off + 32).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]())
    var m3 = _bswap4(bp.unsafe_offset(off + 48).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]())
    var t0 = m0 + _K0; var t1: _u32x4; var t2: _u32x4
    m0 = _sha256su0(m0, m1); t2 = s0; t1 = m1 + _K1;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m0 = _sha256su1(m0, m2, m3)
    m1 = _sha256su0(m1, m2); t2 = s0; t0 = m2 + _K2;  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m1 = _sha256su1(m1, m3, m0)
    m2 = _sha256su0(m2, m3); t2 = s0; t1 = m3 + _K3;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m2 = _sha256su1(m2, m0, m1)
    m3 = _sha256su0(m3, m0); t2 = s0; t0 = m0 + _K4;  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m3 = _sha256su1(m3, m1, m2)
    m0 = _sha256su0(m0, m1); t2 = s0; t1 = m1 + _K5;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m0 = _sha256su1(m0, m2, m3)
    m1 = _sha256su0(m1, m2); t2 = s0; t0 = m2 + _K6;  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m1 = _sha256su1(m1, m3, m0)
    m2 = _sha256su0(m2, m3); t2 = s0; t1 = m3 + _K7;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m2 = _sha256su1(m2, m0, m1)
    m3 = _sha256su0(m3, m0); t2 = s0; t0 = m0 + _K8;  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m3 = _sha256su1(m3, m1, m2)
    m0 = _sha256su0(m0, m1); t2 = s0; t1 = m1 + _K9;  s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m0 = _sha256su1(m0, m2, m3)
    m1 = _sha256su0(m1, m2); t2 = s0; t0 = m2 + _K10; s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m1 = _sha256su1(m1, m3, m0)
    m2 = _sha256su0(m2, m3); t2 = s0; t1 = m3 + _K11; s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0); m2 = _sha256su1(m2, m0, m1)
    m3 = _sha256su0(m3, m0); t2 = s0; t0 = m0 + _K12; s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1); m3 = _sha256su1(m3, m1, m2)
    t2 = s0; t1 = m1 + _K13; s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0)
    t2 = s0; t0 = m2 + _K14; s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1)
    t2 = s0; t1 = m3 + _K15; s0 = _sha256h(s0, s1, t0); s1 = _sha256h2(s1, t2, t0)
    t2 = s0;                  s0 = _sha256h(s0, s1, t1); s1 = _sha256h2(s1, t2, t1)
    s0 = s0 + abcd
    s1 = s1 + efgh

# ── x86-64 SHA-NI core — state (s0, s1) = ((F,E,B,A), (H,G,D,C)) ──────────────
# The canonical Intel sequence: each quad is `wk = W + K` then two sha256rnds2 (the second
# fed the HIGH pair of `wk`, rotated down), with the next message quad prepared by
# sha256msg1 / sha256msg2. `_alignr(a, b)` is `palignr(a, b, 4)`, which supplies the
# W[t-7..t-4] window msg2 adds in. The state stays in the instruction's own (ABEF, CDGH)
# order across blocks — see _IV0/_IV1.
@always_inline
def _alignr(a: _u32x4, b: _u32x4) -> _u32x4:
    return b.shuffle[1, 2, 3, 4](a)

@always_inline
def _rnds2q(mut s0: _u32x4, mut s1: _u32x4, wk: _u32x4):
    s1 = _sha256rnds2(s1, s0, wk)
    s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]())

@always_inline
def _block_x86(mut s0: _u32x4, mut s1: _u32x4, blk: Span[UInt8, _], off: Int):
    var abef = s0
    var cdgh = s1
    var bp = blk.unsafe_ptr()                    # vectorized big-endian load: 16-byte SIMD load + bswap per quad
    var m0 = _bswap4(bp.unsafe_offset(off + 0 ).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]())
    var m1 = _bswap4(bp.unsafe_offset(off + 16).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]())
    var m2 = _bswap4(bp.unsafe_offset(off + 32).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]())
    var m3 = _bswap4(bp.unsafe_offset(off + 48).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]())
    # Rounds 0-11: the first four message quads are the block itself; msg1 starts warming
    # the schedule one quad behind.
    _rnds2q(s0, s1, m0 + _K0)
    _rnds2q(s0, s1, m1 + _K1); m0 = _sha256msg1(m0, m1)
    _rnds2q(s0, s1, m2 + _K2); m1 = _sha256msg1(m1, m2)
    # Rounds 12-59: steady state — round on m[i], finish m[i+1] with msg2, start m[i+3]
    # with msg1. The msg1 half drops off once the last quad (W60..63) is in flight.
    var wk = m3 + _K3;  s1 = _sha256rnds2(s1, s0, wk); m0 = _sha256msg2(m0 + _alignr(m3, m2), m3); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m2 = _sha256msg1(m2, m3)
    wk = m0 + _K4;      s1 = _sha256rnds2(s1, s0, wk); m1 = _sha256msg2(m1 + _alignr(m0, m3), m0); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m3 = _sha256msg1(m3, m0)
    wk = m1 + _K5;      s1 = _sha256rnds2(s1, s0, wk); m2 = _sha256msg2(m2 + _alignr(m1, m0), m1); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m0 = _sha256msg1(m0, m1)
    wk = m2 + _K6;      s1 = _sha256rnds2(s1, s0, wk); m3 = _sha256msg2(m3 + _alignr(m2, m1), m2); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m1 = _sha256msg1(m1, m2)
    wk = m3 + _K7;      s1 = _sha256rnds2(s1, s0, wk); m0 = _sha256msg2(m0 + _alignr(m3, m2), m3); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m2 = _sha256msg1(m2, m3)
    wk = m0 + _K8;      s1 = _sha256rnds2(s1, s0, wk); m1 = _sha256msg2(m1 + _alignr(m0, m3), m0); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m3 = _sha256msg1(m3, m0)
    wk = m1 + _K9;      s1 = _sha256rnds2(s1, s0, wk); m2 = _sha256msg2(m2 + _alignr(m1, m0), m1); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m0 = _sha256msg1(m0, m1)
    wk = m2 + _K10;     s1 = _sha256rnds2(s1, s0, wk); m3 = _sha256msg2(m3 + _alignr(m2, m1), m2); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m1 = _sha256msg1(m1, m2)
    wk = m3 + _K11;     s1 = _sha256rnds2(s1, s0, wk); m0 = _sha256msg2(m0 + _alignr(m3, m2), m3); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m2 = _sha256msg1(m2, m3)
    wk = m0 + _K12;     s1 = _sha256rnds2(s1, s0, wk); m1 = _sha256msg2(m1 + _alignr(m0, m3), m0); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]()); m3 = _sha256msg1(m3, m0)
    wk = m1 + _K13;     s1 = _sha256rnds2(s1, s0, wk); m2 = _sha256msg2(m2 + _alignr(m1, m0), m1); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]())
    wk = m2 + _K14;     s1 = _sha256rnds2(s1, s0, wk); m3 = _sha256msg2(m3 + _alignr(m2, m1), m2); s0 = _sha256rnds2(s0, s1, wk.shuffle[2, 3, 0, 0]())
    # Rounds 60-63: schedule complete, just the last quad of rounds.
    _rnds2q(s0, s1, m3 + _K15)
    s0 = s0 + abef
    s1 = s1 + cdgh

# ── Portable scalar core — state (s0, s1) = (A..D, E..H) ──────────────────────
# FIPS 180-4 straight: expand the 64-word schedule, then 64 rounds over (a..h). Compiled
# only where neither hardware core exists, so it trades speed for "runs anywhere" — the K
# schedule is flattened from the same 16 vectors, so there is still one table in this file.
@always_inline
def _ror32[n: Int](x: UInt32) -> UInt32:
    return rotate_bits_right[n](x)

def _block_scalar(mut s0: _u32x4, mut s1: _u32x4, blk: Span[UInt8, _], off: Int):
    var kk = InlineArray[UInt32, 64](uninitialized=True)     # fully overwritten by the 16 stores
    var kp = kk.unsafe_ptr()
    kp.unsafe_offset( 0).unsafe_store[alignment=4](_K0);  kp.unsafe_offset( 4).unsafe_store[alignment=4](_K1)
    kp.unsafe_offset( 8).unsafe_store[alignment=4](_K2);  kp.unsafe_offset(12).unsafe_store[alignment=4](_K3)
    kp.unsafe_offset(16).unsafe_store[alignment=4](_K4);  kp.unsafe_offset(20).unsafe_store[alignment=4](_K5)
    kp.unsafe_offset(24).unsafe_store[alignment=4](_K6);  kp.unsafe_offset(28).unsafe_store[alignment=4](_K7)
    kp.unsafe_offset(32).unsafe_store[alignment=4](_K8);  kp.unsafe_offset(36).unsafe_store[alignment=4](_K9)
    kp.unsafe_offset(40).unsafe_store[alignment=4](_K10); kp.unsafe_offset(44).unsafe_store[alignment=4](_K11)
    kp.unsafe_offset(48).unsafe_store[alignment=4](_K12); kp.unsafe_offset(52).unsafe_store[alignment=4](_K13)
    kp.unsafe_offset(56).unsafe_store[alignment=4](_K14); kp.unsafe_offset(60).unsafe_store[alignment=4](_K15)

    var w = InlineArray[UInt32, 64](uninitialized=True)      # W[0..15] from the block, W[16..63] expanded
    var wp = w.unsafe_ptr()
    var bp = blk.unsafe_ptr()
    for q in range(4):
        wp.unsafe_offset(q * 4).unsafe_store[alignment=4](
            _bswap4(bp.unsafe_offset(off + q * 16).unsafe_bitcast[UInt32]().unsafe_load[width=4, alignment=1]()))
    for i in range(16, 64):
        var x = w[i - 15]
        var y = w[i - 2]
        var s_0 = _ror32[7](x) ^ _ror32[18](x) ^ (x >> 3)
        var s_1 = _ror32[17](y) ^ _ror32[19](y) ^ (y >> 10)
        w[i] = w[i - 16] + s_0 + w[i - 7] + s_1

    var a = s0[0]; var b = s0[1]; var c = s0[2]; var d = s0[3]
    var e = s1[0]; var f = s1[1]; var g = s1[2]; var h = s1[3]
    for i in range(64):
        var S1 = _ror32[6](e) ^ _ror32[11](e) ^ _ror32[25](e)
        var ch = (e & f) ^ (~e & g)
        var t1 = h + S1 + ch + kk[i] + w[i]
        var S0 = _ror32[2](a) ^ _ror32[13](a) ^ _ror32[22](a)
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var t2 = S0 + maj
        h = g; g = f; f = e; e = d + t1
        d = c; c = b; b = a; a = t1 + t2
    s0 = s0 + _u32x4(a, b, c, d)
    s1 = s1 + _u32x4(e, f, g, h)

# Streaming SHA-256: keep the partial block on the STACK (InlineArray) and feed full
# 64-byte blocks straight from the caller's Span — no per-message heap copy, no padding
# List. `kw` = the round-constant vectors (built once by the caller; HMAC reuses across 3
# hashes). The digest is returned in a stack InlineArray so intermediate hashes never touch
# the heap either.
# The state lives in the SELECTED core's own register layout for the whole hash — ARM and
# the scalar core want (A,B,C,D)/(E,F,G,H); x86's sha256rnds2 wants (F,E,B,A)/(H,G,D,C) —
# so the swizzle is paid once here in the IV and once in `_digest_words` on the way out,
# never per block.
comptime _IV0 = _u32x4(0x9b05688c, 0x510e527f, 0xbb67ae85, 0x6a09e667) if _X86_SHA else _u32x4(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a)
comptime _IV1 = _u32x4(0x5be0cd19, 0x1f83d9ab, 0xa54ff53a, 0x3c6ef372) if _X86_SHA else _u32x4(0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

# Running state -> (H0..H3, H4..H7) in digest order. A no-op except on the x86 core.
@always_inline
def _digest_words(s0: _u32x4, s1: _u32x4) -> Tuple[_u32x4, _u32x4]:
    comptime if _X86_SHA:
        return (_u32x4(s0[3], s0[2], s1[3], s1[2]), _u32x4(s0[1], s0[0], s1[1], s1[0]))
    else:
        return (s0, s1)

struct Sha256(Copyable, Movable):
    var s0: _u32x4
    var s1: _u32x4
    var buf: InlineArray[UInt8, 64]
    var n: Int
    var total: UInt64

    def __init__(out self):
        self.s0 = _IV0
        self.s1 = _IV1
        self.buf = InlineArray[UInt8, 64](fill=0)
        self.n = 0
        self.total = 0

    # Continue a hash whose first 64-byte block was already absorbed into (s0, s1) — used to
    # seed inner/outer from the interleaved ipad/opad compressions (total preset to that block).
    @staticmethod
    @always_inline
    def _seeded(s0: _u32x4, s1: _u32x4) -> Sha256:
        var h = Sha256()
        h.s0 = s0; h.s1 = s1; h.total = 64
        return h^

    def update(mut self, data: Span[UInt8, _]):
        var ln = len(data)
        self.total += UInt64(ln)
        var i = 0
        var dp = data.unsafe_ptr()
        var bp = self.buf.unsafe_ptr()
        if self.n > 0:                                   # top up the partial block first (bulk copy)
            var take = 64 - self.n
            if ln < take: take = ln
            unsafe_memcpy(dest=bp.unsafe_offset(self.n), src=dp, count=take)
            self.n += take; i += take
            if self.n == 64:
                _block(self.s0, self.s1, Span(self.buf), 0); self.n = 0
        while i + 64 <= ln:                              # full blocks straight from the Span
            _block(self.s0, self.s1, data, i); i += 64
        if i < ln:                                       # buffer the remainder (bulk copy)
            unsafe_memcpy(dest=bp.unsafe_offset(self.n), src=dp.unsafe_offset(i), count=ln - i)
            self.n += ln - i

    def finalize(mut self) -> InlineArray[UInt8, 32]:
        var bits = self.total * 8
        var bp = self.buf.unsafe_ptr()
        self.buf[self.n] = 0x80; self.n += 1
        if self.n > 56:                                                       # pad spills into an extra block
            unsafe_memset_zero(bp.unsafe_offset(self.n), 64 - self.n)
            _block(self.s0, self.s1, Span(self.buf), 0); self.n = 0
        unsafe_memset_zero(bp.unsafe_offset(self.n), 56 - self.n)             # zero-pad up to the length field
        (bp.unsafe_offset(56)).unsafe_bitcast[UInt64]().unsafe_store[alignment=1](_bswap8(bits))  # 64-bit BE length
        _block(self.s0, self.s1, Span(self.buf), 0)
        var d = _digest_words(self.s0, self.s1)                              # -> (H0..H3, H4..H7)
        var out = InlineArray[UInt8, 32](uninitialized=True)                 # fully overwritten by the two stores
        var op = out.unsafe_ptr()
        op.unsafe_bitcast[UInt32]().unsafe_store[alignment=1](_bswap4(d[0]))                  # H0..H3 big-endian
        (op.unsafe_offset(16)).unsafe_bitcast[UInt32]().unsafe_store[alignment=1](_bswap4(d[1]))  # H4..H7
        return out^

# HMAC-SHA256 (RFC 2104) → 32-byte tag. This is the "HS256" of JWT. Streaming: the ipad/
# opad key blocks live on the STACK (InlineArray) and the message is fed directly to the
# hash — no inner/outer/key Lists, only the final 32-byte tag is heap-allocated.
def hmac_sha256(key: String, msg: List[UInt8]) -> List[UInt8]:
    var kb = key.as_bytes()
    var ipad = InlineArray[UInt8, 64](fill=0x36)     # ipad[i] = 0x36 ^ key[i] (0x36 where key runs out)
    var opad = InlineArray[UInt8, 64](fill=0x5c)
    if len(kb) > 64:
        var d = Sha256(); d.update(kb); var dh = d.finalize()
        for i in range(32):
            ipad[i] = 0x36 ^ dh[i]; opad[i] = 0x5c ^ dh[i]
    else:
        for i in range(len(kb)):
            ipad[i] = 0x36 ^ kb[i]; opad[i] = 0x5c ^ kb[i]

    var si0 = _IV0; var si1 = _IV1              # ipad + opad first-blocks are independent →
    _block(si0, si1, Span(ipad), 0)             # issue both adjacently (inlined, no data dep)
    var so0 = _IV0; var so1 = _IV1              # so the OoO engine overlaps their sha256h latency
    _block(so0, so1, Span(opad), 0)
    var inner = Sha256._seeded(si0, si1); inner.update(Span(msg))
    var ih = inner.finalize()
    var outer = Sha256._seeded(so0, so1); outer.update(Span(ih))
    var fh = outer.finalize()
    var out = List[UInt8](unsafe_uninit_length=32)
    unsafe_memcpy(dest=out.unsafe_ptr(), src=fh.unsafe_ptr(), count=32)   # 32-byte tag, one copy
    return out^

# HMAC over the signing preimage `LE_u64(root_off) ++ body` — streamed, so the preimage
# is never materialised as a List (the 8-byte prefix lives on the stack; the body Span is
# hashed in place). Assumes a <=64-byte key (the demo secret). This is the verify/mint hot path.
def hmac_sha256_preimage(key: String, root_off: Int, body: Span[UInt8, _]) -> List[UInt8]:
    var kb = key.as_bytes()
    var ipad = InlineArray[UInt8, 64](fill=0x36)
    var opad = InlineArray[UInt8, 64](fill=0x5c)
    for i in range(len(kb)):
        ipad[i] = 0x36 ^ kb[i]; opad[i] = 0x5c ^ kb[i]
    var le = InlineArray[UInt8, 8](uninitialized=True)   # LE_u64(root_off): one native-LE store, no byte loop
    le.unsafe_ptr().unsafe_bitcast[UInt64]().unsafe_store[alignment=1](UInt64(root_off))
    # ipad + opad first-blocks are independent → issue both adjacently so the OoO engine
    # overlaps their sha256h latency, then seed inner/outer from the resulting states.
    var si0 = _IV0; var si1 = _IV1
    _block(si0, si1, Span(ipad), 0)
    var so0 = _IV0; var so1 = _IV1
    _block(so0, so1, Span(opad), 0)
    var inner = Sha256._seeded(si0, si1)
    inner.update(Span(le)); inner.update(body)
    var ih = inner.finalize()
    var outer = Sha256._seeded(so0, so1)
    outer.update(Span(ih))
    var fh = outer.finalize()
    var out = List[UInt8](unsafe_uninit_length=32)
    unsafe_memcpy(dest=out.unsafe_ptr(), src=fh.unsafe_ptr(), count=32)   # 32-byte tag, one copy
    return out^
