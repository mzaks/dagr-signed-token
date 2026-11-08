package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/**
 * The Java target's read runtime (spec/45 §4): what a generated accessor calls. A port of the C
 * target's dagr/reader.h.
 *
 * <p>THE CONTRACT: every method here is TOTAL — for any bytes and any position it returns without
 * throwing. What it returns for malformed input is unspecified but safe: a zero, an empty view,
 * {@link #NPOS} (no position), a zero length. The JVM's own bounds check is the backstop, never the
 * rule: an escaped {@code IndexOutOfBoundsException} is a failure of the gate (the malformed sweep).
 *
 * <ol>
 *   <li>A read takes an ABSOLUTE position and is checked at that position. Positions are {@code
 *       long}; arithmetic may wrap, and a wrapped (negative) position fails the check like any
 *       other. {@link #NPOS} ({@code -1}) is "no position" — reading through it yields zeros.
 *   <li>A length or count read from the buffer is clamped against the bytes that remain WHERE IT
 *       IS RECORDED.
 *   <li>A varint read that fails reports length 0, and a scan stops on it.
 * </ol>
 *
 * <p>Varints come back in two halves — {@link #leb} (the value) and {@link #lebLen} (its length,
 * 0 when unreadable) — since a Java method returns one value.
 */
public final class Reader {
  private Reader() {}

  /** No position: reading through it yields zeros. */
  public static final long NPOS = -1L;

  static final ValueLayout.OfShort U16 = ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
  static final ValueLayout.OfInt U32 = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
  static final ValueLayout.OfLong U64 = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

  // ── Bounds ──────────────────────────────────────────────────────────────────

  /** Whether {@code [at, at + len)} lies inside the buffer — neither a wrapped {@code at} nor a huge {@code len} can pass. */
  public static boolean inBounds(MemorySegment b, long at, long len) {
    final long size = b.byteSize();
    return at >= 0 && len >= 0 && at <= size && len <= size - at;
  }

  /** Bytes left from {@code at} to the end of the buffer (0 when {@code at} is out of range). */
  public static long remaining(MemorySegment b, long at) {
    final long size = b.byteSize();
    return at >= 0 && at <= size ? size - at : 0;
  }

  // ── Checked fixed-width loads ───────────────────────────────────────────────

  public static int u8(MemorySegment b, long at) {
    return at >= 0 && at < b.byteSize() ? Byte.toUnsignedInt(b.get(ValueLayout.JAVA_BYTE, at)) : 0;
  }

  public static int u16(MemorySegment b, long at) {
    return inBounds(b, at, 2) ? Short.toUnsignedInt(b.get(U16, at)) : 0;
  }

  /** A u32, widened (spec/45 O-J2). */
  public static long u32(MemorySegment b, long at) {
    return inBounds(b, at, 4) ? Integer.toUnsignedLong(b.get(U32, at)) : 0;
  }

  /** A u64's bits. */
  public static long u64(MemorySegment b, long at) {
    return inBounds(b, at, 8) ? b.get(U64, at) : 0;
  }

  public static byte i8(MemorySegment b, long at) { return (byte) u8(b, at); }

  public static short i16(MemorySegment b, long at) { return (short) u16(b, at); }

  public static int i32(MemorySegment b, long at) { return inBounds(b, at, 4) ? b.get(U32, at) : 0; }

  public static long i64(MemorySegment b, long at) { return u64(b, at); }

  public static boolean bool(MemorySegment b, long at) { return u8(b, at) != 0; }

  public static float f32(MemorySegment b, long at) { return Float.intBitsToFloat(i32(b, at)); }

  public static double f64(MemorySegment b, long at) { return Double.longBitsToDouble(u64(b, at)); }

  public static float f16(MemorySegment b, long at) { return f16ToFloat(u16(b, at)); }

  /**
   * An IEEE half's bits as a float. The JDK's conversion, except for a NaN: there it keeps the
   * payload the way every other target does (the C runtime's {@code dagr_f16_to_f32}), so that a
   * NaN reads as the same bits in every language (spec/45 §14, milestone 0).
   */
  public static float f16ToFloat(int bits) {
    if ((bits & 0x7c00) == 0x7c00 && (bits & 0x3ff) != 0) {
      return Float.intBitsToFloat(((bits & 0x8000) << 16) | 0x7f800000 | ((bits & 0x3ff) << 13));
    }
    return Float.float16ToFloat((short) bits);
  }

  /** A float as IEEE half bits, round to nearest even; every NaN is {@code 0x7e00}, as every other writer has it. */
  public static int floatToF16(float v) {
    return Float.isNaN(v) ? 0x7e00 : Float.floatToFloat16(v) & 0xffff;
  }

  public static float bf16(MemorySegment b, long at) { return bf16ToFloat(u16(b, at)); }

  /** A bfloat16 is the high half of an f32. */
  public static float bf16ToFloat(int bits) { return Float.intBitsToFloat((bits & 0xffff) << 16); }

  /** An f32 from the low 32 bits of a union-array slot (the bit pattern, zero-extended to the slot). */
  public static float f32FromBits(long slot) { return Float.intBitsToFloat((int) slot); }

  /** An f64 from a union-array slot's bits. */
  public static double f64FromBits(long slot) { return Double.longBitsToDouble(slot); }

  /** An unsigned {@code width}-byte little-endian integer (width ≤ 8). */
  public static long uintLe(MemorySegment b, long at, int width) {
    long v = 0;
    if (width <= 8 && inBounds(b, at, width)) {
      for (int k = 0; k < width; k++) v |= (long) Byte.toUnsignedInt(b.get(ValueLayout.JAVA_BYTE, at + k)) << (8 * k);
    }
    return v;
  }

  /** The low {@code width} bytes of {@code v} — a two's-complement integer of that width — sign-extended. */
  public static long signExtend(long v, int width) {
    if (width >= 8) return v;
    final int shift = 64 - 8 * width;
    return (v << shift) >> shift;
  }

  /** Bit {@code i} of a bitset starting at {@code base}. */
  public static boolean bitAt(MemorySegment b, long base, long i) {
    return ((u8(b, base + (i >>> 3)) >>> (i & 7)) & 1) != 0;
  }

  /** {@code bits} bits (1, 2 or 4) of element {@code i} of a bit-packed array at {@code base}. */
  public static int packedBits(MemorySegment b, long base, long i, int bits) {
    final long bit = i * bits;
    return (u8(b, base + (bit >>> 3)) >>> (bit & 7)) & ((1 << bits) - 1);
  }

  // ── Varints ─────────────────────────────────────────────────────────────────

  /** The unsigned LEB128 at {@code at} (0 when unreadable: truncated, out of range, longer than a u64 allows). */
  public static long leb(MemorySegment b, long at) {
    long result = 0;
    int shift = 0;
    long pos = at;
    final long size = b.byteSize();
    while (true) {
      if (pos < 0 || pos >= size || shift > 63) return 0;
      final int x = Byte.toUnsignedInt(b.get(ValueLayout.JAVA_BYTE, pos));
      result |= (long) (x & 0x7f) << shift;
      pos++;
      shift += 7;
      if ((x & 0x80) == 0) return result;
    }
  }

  /** The length of the LEB128 at {@code at}; 0 when it cannot be read. */
  public static int lebLen(MemorySegment b, long at) {
    long pos = at;
    final long size = b.byteSize();
    for (int n = 1; n <= 10; n++, pos++) {
      if (pos < 0 || pos >= size) return 0;
      if ((b.get(ValueLayout.JAVA_BYTE, pos) & 0x80) == 0) return n;
    }
    return 0;
  }

  /** Values a {@link #lebPacked} result can carry: below 2⁵⁹ — no position or length in a buffer reaches it. */
  public static final long PACKED_LEB_MAX = 1L << 59;

  /**
   * The LEB128 at {@code at} in ONE pass, as {@code (value << 4) | length}; {@code -1} when it
   * cannot be read or its value is {@link #PACKED_LEB_MAX} or more. For the LEBs a reader walks
   * through to find a position (offsets, sizes, vtable headers): a value that large is malformed
   * there anyway, and reads as "no position". {@link #lebValue} / {@link #lebLength} unpack it.
   */
  public static long lebPacked(MemorySegment b, long at) {
    final long size = b.byteSize();
    if (at < 0 || at >= size) return -1;
    final int b0 = b.get(ValueLayout.JAVA_BYTE, at);
    if (b0 >= 0) return ((long) b0 << 4) | 1;
    long result = b0 & 0x7f;
    long pos = at + 1;
    for (int shift = 7; shift < 63; shift += 7, pos++) {
      if (pos >= size) return -1;
      final int x = b.get(ValueLayout.JAVA_BYTE, pos);
      result |= (long) (x & 0x7f) << shift;
      if (x >= 0) {
        return result >= 0 && result < PACKED_LEB_MAX ? (result << 4) | (pos - at + 1) : -1;
      }
    }
    return -1;
  }

  public static long lebValue(long packed) { return packed >>> 4; }

  public static int lebLength(long packed) { return (int) (packed & 0xf); }

  public static long zigzagDecode(long n) { return (n >>> 1) ^ -(n & 1); }

  public static long zigzagEncode(long v) { return (v << 1) ^ (v >> 63); }

  /** End of a size-prefixed blob {@code [LEB N][N bytes]} at {@code at}, or {@link #NPOS}. */
  public static long skipBlob(MemorySegment b, long at) {
    final int len = lebLen(b, at);
    if (len == 0) return NPOS;
    final long n = leb(b, at);
    final long start = at + len;
    if (n < 0 || n > remaining(b, start)) return NPOS;
    return start + n;
  }

  /** The bytes of the {@code [LEB N][N bytes]} blob at {@code at}: a zero-copy slice, empty when unreadable or overlong. */
  public static MemorySegment blob(MemorySegment b, long at) {
    final long end = skipBlob(b, at);
    if (end == NPOS) return MemorySegment.NULL;
    return b.asSlice(at + lebLen(b, at), end - at - lebLen(b, at));
  }

  /**
   * What {@link #text} returns for bytes that are not well-formed UTF-8: one shared instance, so
   * that a restore can refuse it by identity (spec/49 U1) while a lazy getter, which has no error
   * channel, still returns a string (U3). A real U+FFFD in valid text is a different object.
   */
  @SuppressWarnings("StringOperationCanBeSimplified")
  public static final String INVALID_TEXT = new String("\uFFFD");

  /** A utf8 blob as text; {@link #INVALID_TEXT} when its bytes are not well-formed UTF-8. */
  public static String text(MemorySegment b, long at) {
    final MemorySegment v = blob(b, at);
    if (v.byteSize() == 0) return "";
    final byte[] bytes = v.toArray(ValueLayout.JAVA_BYTE);
    return validUtf8(bytes) ? new String(bytes, java.nio.charset.StandardCharsets.UTF_8) : INVALID_TEXT;
  }

  /** Whether {@code p} is well-formed UTF-8 (RFC 3629): no overlong form, no surrogate, nothing above U+10FFFF, no sequence cut short. */
  public static boolean validUtf8(byte[] p) {
    final int n = p.length;
    int i = 0;
    while (i < n) {
      final int c = p[i] & 0xFF;
      if (c < 0x80) {
        i++;
        continue;
      }
      final int len;
      int lo = 0x80, hi = 0xBF; // the bounds of the second byte
      if (c >= 0xC2 && c <= 0xDF) {
        len = 2;
      } else if (c >= 0xE0 && c <= 0xEF) {
        len = 3;
        if (c == 0xE0) lo = 0xA0; // no overlong 3-byte form
        if (c == 0xED) hi = 0x9F; // no surrogate
      } else if (c >= 0xF0 && c <= 0xF4) {
        len = 4;
        if (c == 0xF0) lo = 0x90; // no overlong 4-byte form
        if (c == 0xF4) hi = 0x8F; // nothing above U+10FFFF
      } else {
        return false;
      }
      if (n - i < len) return false;
      final int c1 = p[i + 1] & 0xFF;
      if (c1 < lo || c1 > hi) return false;
      for (int k = 2; k < len; k++) {
        final int ck = p[i + k] & 0xFF;
        if (ck < 0x80 || ck > 0xBF) return false;
      }
      i += len;
    }
    return true;
  }

  /** {@code p + n}, or {@link #NPOS} when {@code p} is: NPOS is -1, which a plain sum would turn into a real position. */
  public static long step(long p, long n) { return p < 0 ? NPOS : p + n; }

  /** Position just past the varint at {@code at}, or {@link #NPOS}. */
  public static long lebEnd(MemorySegment b, long at) {
    final int n = lebLen(b, at);
    return n == 0 ? NPOS : at + n;
  }

  // ── Packed nodes (spec 07) ───────────────────────────────────────────────────
  // NOTE: C's "no position" (SIZE_MAX) is past every block end and ends a scan by itself; Java's
  // is -1, BEFORE every end: every scan and step here tests for it.

  /** Where the entries of the packed block whose length LEB is at {@code start} begin; {@link #NPOS}: unreadable. */
  public static long blockBegin(MemorySegment b, long start) {
    return lebEnd(b, start);
  }

  /** Where they end: the block's own length, clamped to the buffer (a block that does not fit is empty). */
  public static long blockEnd(MemorySegment b, long start) {
    final long h = lebPacked(b, start);
    if (h < 0) return NPOS;
    final long begin = start + lebLength(h);
    final long n = lebValue(h);
    return n > remaining(b, begin) ? begin : begin + n;
  }

  /**
   * A self-describing packed float (spec 07 §12): 00 +0 · 01 -0 · 02 +inf · 03 -inf · 04 NaN · 05
   * zigzag-LEB integer · 06 f16 bits · 07 f32 · 08 f64. {@code single} decodes as an f32 would.
   * 0 when unreadable ({@link #packedFloatLen} says so).
   */
  public static double packedFloat(MemorySegment b, long at, boolean single) {
    switch (u8(b, at)) {
      case 0: return 0.0;
      case 1: return -0.0;
      case 2: return Double.POSITIVE_INFINITY;
      case 3: return Double.NEGATIVE_INFINITY;
      case 4: return single ? (double) Float.intBitsToFloat(0x7fc00000) : Double.longBitsToDouble(0x7ff8000000000000L);
      case 5: {
        if (lebLen(b, at + 1) == 0) return 0.0;
        final long iv = zigzagDecode(leb(b, at + 1));
        return single ? (double) (float) iv : (double) iv;
      }
      case 6: return inBounds(b, at + 1, 2) ? f16(b, at + 1) : 0.0;
      case 7: return inBounds(b, at + 1, 4) ? f32(b, at + 1) : 0.0;
      default:
        // as the C / C++ decoders: an f32 reads any other tag as 07, an f64 as 08
        if (single) return inBounds(b, at + 1, 4) ? f32(b, at + 1) : 0.0;
        return inBounds(b, at + 1, 8) ? f64(b, at + 1) : 0.0;
    }
  }

  /** The bytes the packed float at {@code at} occupies; 0 when unreadable. */
  public static int packedFloatLen(MemorySegment b, long at, boolean single) {
    if (at < 0 || at >= b.byteSize()) return 0;
    switch (u8(b, at)) {
      case 0, 1, 2, 3, 4: return 1;
      case 5: {
        final int n = lebLen(b, at + 1);
        return n == 0 ? 0 : 1 + n;
      }
      case 6: return inBounds(b, at + 1, 2) ? 3 : 0;
      case 7: return inBounds(b, at + 1, 4) ? 5 : 0;
      default:
        if (single) return inBounds(b, at + 1, 4) ? 5 : 0;
        return inBounds(b, at + 1, 8) ? 9 : 0;
    }
  }

  /** The encoded (special-value, one byte) form of a packed f16 / bf16. */
  public static float packedHalf(MemorySegment b, long at) {
    switch (u8(b, at)) {
      case 1: return -0.0f;
      case 2: return Float.POSITIVE_INFINITY;
      case 3: return Float.NEGATIVE_INFINITY;
      case 4: return Float.intBitsToFloat(0x7fc00000);
      default: return 0.0f;
    }
  }

  // Packed scalars: the payload is a varint or the raw fixed-width form; `raw` comes from the
  // field's tag bit (packed nodes), its encoding bit (frozen+packed) or a union header's code.

  public static long packedUint(MemorySegment b, long at, boolean raw, int width) {
    return raw ? uintLe(b, at, width) : leb(b, at);
  }

  public static long packedInt(MemorySegment b, long at, boolean raw, int width) {
    return raw ? signExtend(uintLe(b, at, width), width) : zigzagDecode(leb(b, at));
  }

  public static float packedF32(MemorySegment b, long at, boolean raw) {
    return raw ? f32(b, at) : (float) packedFloat(b, at, true);
  }

  public static double packedF64(MemorySegment b, long at, boolean raw) {
    return raw ? f64(b, at) : packedFloat(b, at, false);
  }

  public static float packedF16(MemorySegment b, long at, boolean raw) {
    return raw ? f16(b, at) : packedHalf(b, at);
  }

  public static float packedBf16(MemorySegment b, long at, boolean raw) {
    return raw ? bf16(b, at) : packedHalf(b, at);
  }

  /** A packed UNION variant's unsigned integer by its header's code (spec 07 §8): 0 a varint, 1 / 2 / 3 / 4 a fixed 1 / 2 / 4 / 8 bytes. */
  public static long packedUnionUint(MemorySegment b, long at, int code) {
    switch (code) {
      case 0: return leb(b, at);
      case 1: return u8(b, at);
      case 2: return u16(b, at);
      case 3: return u32(b, at);
      default: return u64(b, at);
    }
  }

  /** An f16 variant: its 16 bits as an unsigned integer — a varint under code 0, two raw bytes otherwise. */
  public static float packedUnionF16(MemorySegment b, long at, int code) {
    return f16ToFloat((int) packedUnionUint(b, at, code == 0 ? 0 : 2));
  }

  public static float packedUnionBf16(MemorySegment b, long at, int code) {
    return bf16ToFloat((int) packedUnionUint(b, at, code == 0 ? 0 : 2));
  }

  /** A packed union header {@code [LEB (typeId << 3) | code]} at {@code at}: its value, -1 when unreadable. */
  public static long packedUnionHead(MemorySegment b, long at) {
    final long h = lebPacked(b, at);
    return h < 0 ? -1 : lebValue(h);
  }

  /** Byte size of a packed-union payload after its header; 0 when it cannot be sized. */
  public static long packedUnionPayloadBytes(MemorySegment b, long ep, int code) {
    switch (code) {
      case 0: return lebLen(b, ep);
      case 1: return 1;
      case 2: return 2;
      case 3: return 4;
      case 4: return 8;
      case 5: return packedFloatLen(b, ep, false);
      default: {
        final long end = skipBlob(b, ep);
        return end != NPOS ? end - ep : 0;
      }
    }
  }

  // Scan steps: the position just past one field's payload, or NPOS when it cannot be sized.

  public static long skipPackedVarint(MemorySegment b, long at, boolean raw, int width) {
    return raw ? step(at, width) : lebEnd(b, at);
  }

  public static long skipPackedFloat(MemorySegment b, long at, boolean raw, int width) {
    if (raw) return step(at, width);
    final int n = packedFloatLen(b, at, width == 4);
    return n != 0 ? at + n : NPOS;
  }

  public static long skipPackedHalf(long at, boolean raw) { return step(at, raw ? 2 : 1); }

  public static long skipPackedUnion(MemorySegment b, long at) {
    final long h = lebPacked(b, at);
    if (h < 0) return NPOS;
    final long payload = at + lebLength(h);
    final long n = packedUnionPayloadBytes(b, payload, (int) (lebValue(h) & 7));
    return n != 0 ? payload + n : NPOS;
  }

  // ── Union slots of regular and frozen nodes (spec 05) ───────────────────────

  /** Total size of a union slot {@code [LEB (tag << 2) | wc][1 << wc bytes]}; 0 when unreadable. */
  public static long unionSlotBytes(MemorySegment b, long at) {
    final long h = lebPacked(b, at);
    return h < 0 ? 0 : lebLength(h) + (1L << (lebValue(h) & 3));
  }

  // ── Raw-embedded graphs (spec 18) ───────────────────────────────────────────

  /** Absolute root position inside a raw-embedded graph entry {@code [LEB payloadLen][pad?][standalone graph]} at {@code pos}; NPOS when unreadable. */
  public static long rawEmbeddedRoot(MemorySegment b, long pos, boolean hasPad) {
    final int pl = lebLen(b, pos);
    if (pl == 0) return NPOS;
    final long bs = pos + pl + (hasPad ? 1 : 0);
    final long fr = lebPacked(b, bs);
    if (fr < 0) return NPOS;
    final long from = bs + lebLength(fr);
    final long off = lebValue(fr) >>> 2;
    if (off >= remaining(b, from)) return NPOS;
    return from + off;
  }

  // ── Framing (spec 06, spec 15) ──────────────────────────────────────────────

  /** The absolute root-node position of a GRAPH buffer from its framing word, or {@link #NPOS}. */
  public static long rootOffset(MemorySegment b) {
    final int len = lebLen(b, 0);
    if (len == 0) return NPOS;
    final long framing = leb(b, 0);
    if ((framing & 2) != 0) return NPOS;
    final long off = framing >>> 2;
    if (off >= remaining(b, len)) return NPOS;
    return len + off;
  }

  /** Whether a graph buffer's framing word carries a spec-15 header. */
  public static boolean hasHeader(MemorySegment b) {
    return lebLen(b, 0) != 0 && (leb(b, 0) & 1) == 1;
  }

  /**
   * Where the spec-15 header starts (right after the framing word), or {@link #NPOS} when the
   * buffer has none or its framing is bad. {@link #headerSpan} / {@link #headerRootOffset} give
   * the rest of the frame.
   */
  public static long headerStart(MemorySegment b) {
    return headerSpan(b) < 0 ? NPOS : lebLen(b, 0);
  }

  /** The header's total span (size LEB + content); -1 without a well-formed header. */
  public static long headerSpan(MemorySegment b) {
    final long f = lebPacked(b, 0);
    if (f < 0) return -1;
    final long framing = lebValue(f);
    if ((framing & 2) != 0 || (framing & 1) == 0) return -1;
    final long at = lebLength(f);
    final long h = lebPacked(b, at);
    if (h < 0 || lebValue(h) > remaining(b, at + lebLength(h))) return -1;
    final long span = lebLength(h) + lebValue(h);
    return (framing >>> 2) < span ? -1 : span;
  }

  /** The header-free root offset the producer signed over (stored − span); -1 without a header. */
  public static long headerRootOffset(MemorySegment b) {
    final long span = headerSpan(b);
    return span < 0 ? -1 : (lebValue(lebPacked(b, 0)) >>> 2) - span;
  }

  /** {@code OK}, {@code NO_HEADER} or {@code BAD_FRAMING}. */
  public static Status headerStatus(MemorySegment b) {
    final long f = lebPacked(b, 0);
    if (f < 0 || (lebValue(f) & 2) != 0) return Status.BAD_FRAMING;
    if ((lebValue(f) & 1) == 0) return Status.NO_HEADER;
    return headerSpan(b) < 0 ? Status.BAD_FRAMING : Status.OK;
  }

  // ── V62 pointers (spec 06) ──────────────────────────────────────────────────

  /** Byte width of the V62 pointer at {@code at}; 0 when out of range. */
  public static int v62Bytes(MemorySegment b, long at) {
    return at >= 0 && at < b.byteSize() ? 1 << (b.get(ValueLayout.JAVA_BYTE, at) & 3) : 0;
  }

  /** The V62 value at {@code at} (raw >> 2); check {@link #v62Bytes} and {@link #inBounds} first. */
  public static long v62(MemorySegment b, long at) {
    final int w = v62Bytes(b, at);
    return w != 0 && inBounds(b, at, w) ? uintLe(b, at, w) >>> 2 : 0;
  }

  /** The position the V62 forward pointer at {@code slot} targets, or {@link #NPOS}. */
  public static long fwdTarget(MemorySegment b, long slot) {
    final int w = v62Bytes(b, slot);
    if (w == 0 || !inBounds(b, slot, w)) return NPOS;
    final long v = v62(b, slot);
    final long from = slot + w;
    if (v < 0 || v > remaining(b, from)) return NPOS;
    return from + v;
  }

  /** The position the bidirectional (ZigZag V62) node reference at {@code slot} targets, or {@link #NPOS}. */
  public static long refTarget(MemorySegment b, long slot) {
    final int w = v62Bytes(b, slot);
    if (w == 0 || !inBounds(b, slot, w)) return NPOS;
    return slot + w + zigzagDecode(v62(b, slot));
  }

  // ── Regular nodes: the vtable (spec 06) ─────────────────────────────────────

  /**
   * Absolute position of vtable field {@code idx} of the regular node at {@code start}, or {@link
   * #NPOS} when the field is absent or the vtable unreadable. The node-start LEB is ZigZag: even =
   * a dedup forward reference (+ its own width), odd = a fresh vtable; the vtable header LEB is
   * {@code (fieldCount << 1) | wide}.
   */
  public static long fieldPos(MemorySegment b, long start, int idx) {
    final long o = lebPacked(b, start);
    if (o < 0) return NPOS;
    final long ov = lebValue(o);
    final int olen = lebLength(o);
    final long adj = (ov & 1) == 0 ? olen : 0;
    final long vt = start + zigzagDecode(ov) + adj; // may wrap: the reads below are checked
    final long h = lebPacked(b, vt);
    if (h < 0) return NPOS;
    final long vs = lebValue(h);
    final int vlen = lebLength(h);
    if (idx < 0 || idx >= (vs >>> 1)) return NPOS;
    final long v = (vs & 1) != 0 ? u16(b, vt + vlen + idx * 2L) : u8(b, vt + vlen + idx);
    if (v == 0) return NPOS;
    return start + v - 1 + olen;
  }
}
