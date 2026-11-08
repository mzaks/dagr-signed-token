package dagr.runtime;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * The SharedBuffer runtime (spec/20, spec/40; spec/45 §6) — what a generated overlay calls to read
 * and write a fixed-layout region in place. A port of the C target's {@code dagr/shared_buffer.h}.
 *
 * <p>A SharedBuffer is a region of {@code BYTE_SIZE} bytes laid out by the language-neutral manifest
 * ({@code dagr/layout.py}), so every target reads and writes the same bytes at the same offsets. A
 * generated overlay holds the region and a node's offset and calls these methods; it never touches
 * the segment itself.
 *
 * <ul>
 *   <li>lengths read from the region are CLAMPED to their capacity: a region shared with another
 *       process is not trusted to be well-formed;
 *   <li>atomics: {@link VarHandle}s on a NATIVE region, every atomic word naturally aligned (the
 *       layout places it so, relative to a {@code REGION_ALIGN}-aligned base). Sequentially
 *       consistent ({@code getVolatile}, {@code getAndAdd}, {@code compareAndSet}) unless the name
 *       says otherwise. The words are in the host's order, as every target's — little-endian hosts;
 *   <li>{@link #racyCopy}: the seqlock's payload copy, every access OPAQUE (C's relaxed atomic) — the
 *       copy races BY DESIGN and the counter decides afterwards whether it was torn.
 * </ul>
 */
public final class SharedBuffer {
  private SharedBuffer() {}

  static final ValueLayout.OfShort U16 = ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
  static final ValueLayout.OfInt U32 = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
  static final ValueLayout.OfLong U64 = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
  private static final VarHandle A8 = ValueLayout.JAVA_BYTE.varHandle();
  private static final VarHandle A32 = ValueLayout.JAVA_INT.varHandle();
  private static final VarHandle A64 = ValueLayout.JAVA_LONG.varHandle();
  private static final MemorySegment EMPTY = MemorySegment.ofArray(new byte[0]);

  // ── The region ─────────────────────────────────────────────────────────────

  /**
   * Checks a region before an overlay wraps it — the caller's contract, not the region's bytes: at
   * least {@code size} bytes, and, when the overlay uses atomics, NATIVE (a VarHandle cannot update a
   * heap array's word atomically) and {@code align}-aligned.
   */
  public static MemorySegment region(MemorySegment region, long size, long align, boolean atomics) {
    if (region.byteSize() < size) {
      throw new IllegalArgumentException("a SharedBuffer region of " + size + " bytes, got " + region.byteSize());
    }
    if (atomics && !aligned(region, align)) {
      throw new IllegalArgumentException("a SharedBuffer region with atomics must be native and " + align + "-aligned");
    }
    return region;
  }

  /** Whether {@code region} is native and its address a multiple of {@code align}. */
  public static boolean aligned(MemorySegment region, long align) {
    return region.isNative() && (align <= 1 || (region.address() & (align - 1)) == 0);
  }

  /** A zeroed native region of {@code size} bytes aligned to {@code align} (freed by the GC). */
  public static MemorySegment allocate(long size, long align) {
    return Arena.ofAuto().allocate(Math.max(size, 1), Math.max(align, 8)).asSlice(0, size);
  }

  // ── Scalars (little-endian, unaligned) ─────────────────────────────────────

  public static int getU8(MemorySegment p, long at) {
    return Byte.toUnsignedInt(p.get(ValueLayout.JAVA_BYTE, at));
  }

  public static void putU8(MemorySegment p, long at, int v) {
    p.set(ValueLayout.JAVA_BYTE, at, (byte) v);
  }

  public static byte getI8(MemorySegment p, long at) {
    return p.get(ValueLayout.JAVA_BYTE, at);
  }

  public static void putI8(MemorySegment p, long at, byte v) {
    p.set(ValueLayout.JAVA_BYTE, at, v);
  }

  public static int getU16(MemorySegment p, long at) {
    return Short.toUnsignedInt(p.get(U16, at));
  }

  public static void putU16(MemorySegment p, long at, int v) {
    p.set(U16, at, (short) v);
  }

  public static short getI16(MemorySegment p, long at) {
    return p.get(U16, at);
  }

  public static void putI16(MemorySegment p, long at, short v) {
    p.set(U16, at, v);
  }

  public static long getU32(MemorySegment p, long at) {
    return Integer.toUnsignedLong(p.get(U32, at));
  }

  public static void putU32(MemorySegment p, long at, long v) {
    p.set(U32, at, (int) v);
  }

  public static int getI32(MemorySegment p, long at) {
    return p.get(U32, at);
  }

  public static void putI32(MemorySegment p, long at, int v) {
    p.set(U32, at, v);
  }

  public static long getU64(MemorySegment p, long at) {
    return p.get(U64, at);
  }

  public static void putU64(MemorySegment p, long at, long v) {
    p.set(U64, at, v);
  }

  public static long getI64(MemorySegment p, long at) {
    return p.get(U64, at);
  }

  public static void putI64(MemorySegment p, long at, long v) {
    p.set(U64, at, v);
  }

  public static float getF32(MemorySegment p, long at) {
    return Float.intBitsToFloat(p.get(U32, at));
  }

  public static void putF32(MemorySegment p, long at, float v) {
    p.set(U32, at, Float.floatToRawIntBits(v));
  }

  public static double getF64(MemorySegment p, long at) {
    return Double.longBitsToDouble(p.get(U64, at));
  }

  public static void putF64(MemorySegment p, long at, double v) {
    p.set(U64, at, Double.doubleToRawLongBits(v));
  }

  public static float getF16(MemorySegment p, long at) {
    return Reader.f16ToFloat(getU16(p, at));
  }

  public static void putF16(MemorySegment p, long at, float v) {
    putU16(p, at, Reader.floatToF16(v));
  }

  public static float getBf16(MemorySegment p, long at) {
    return Reader.bf16ToFloat(getU16(p, at));
  }

  public static void putBf16(MemorySegment p, long at, float v) {
    putU16(p, at, Writer.halfBits(v, true));
  }

  /** A bool stored as a whole byte (a union variant): any non-zero byte is true. */
  public static boolean getBool(MemorySegment p, long at) {
    return p.get(ValueLayout.JAVA_BYTE, at) != 0;
  }

  public static void putBool(MemorySegment p, long at, boolean v) {
    p.set(ValueLayout.JAVA_BYTE, at, (byte) (v ? 1 : 0));
  }

  // ── Unsigned values of a given width (lengths, union tags) ─────────────────

  public static long getUint(MemorySegment p, long at, int width) {
    return switch (width) {
      case 1 -> getU8(p, at);
      case 2 -> getU16(p, at);
      case 4 -> getU32(p, at);
      default -> getU64(p, at);
    };
  }

  public static void putUint(MemorySegment p, long at, int width, long v) {
    switch (width) {
      case 1 -> putU8(p, at, (int) v);
      case 2 -> putU16(p, at, (int) v);
      case 4 -> putU32(p, at, v);
      default -> putU64(p, at, v);
    }
  }

  /** A length stored in {@code width} bytes at {@code at}, clamped to {@code cap} (a u64 above 2^63 too). */
  public static int len(MemorySegment p, long at, int width, int cap) {
    final long n = getUint(p, at, width);
    return Long.compareUnsigned(n, cap) > 0 ? cap : (int) n;
  }

  // ── Bits ───────────────────────────────────────────────────────────────────

  public static boolean bit(MemorySegment p, long at, int bit) {
    return ((getU8(p, at) >>> bit) & 1) != 0;
  }

  public static void setBit(MemorySegment p, long at, int bit) {
    putU8(p, at, getU8(p, at) | (1 << bit));
  }

  public static void clearBit(MemorySegment p, long at, int bit) {
    putU8(p, at, getU8(p, at) & ~(1 << bit));
  }

  public static void putBit(MemorySegment p, long at, int bit, boolean v) {
    if (v) {
      setBit(p, at, bit);
    } else {
      clearBit(p, at, bit);
    }
  }

  /** Bit {@code i} of a bitset starting at byte {@code base} (bool arrays, presence bitsets). */
  public static boolean ibit(MemorySegment p, long base, int i) {
    return bit(p, base + (i >>> 3), i & 7);
  }

  public static void setIbit(MemorySegment p, long base, int i) {
    setBit(p, base + (i >>> 3), i & 7);
  }

  public static void clearIbit(MemorySegment p, long base, int i) {
    clearBit(p, base + (i >>> 3), i & 7);
  }

  public static void putIbit(MemorySegment p, long base, int i, boolean v) {
    putBit(p, base + (i >>> 3), i & 7, v);
  }

  /** {@code bits} bits at bit {@code bit} of byte {@code at} (a sub-byte enum or tag; never crosses a byte). */
  public static int bits(MemorySegment p, long at, int bit, int bits) {
    return (getU8(p, at) >>> bit) & ((1 << bits) - 1);
  }

  public static void putBits(MemorySegment p, long at, int bit, int bits, int v) {
    final int mask = (1 << bits) - 1;
    putU8(p, at, (getU8(p, at) & ~(mask << bit)) | ((v & mask) << bit));
  }

  /** The {@code i}-th of an array of {@code bits}-wide elements starting at byte {@code base}. */
  public static int elemBits(MemorySegment p, long base, int i, int bits) {
    final long bit = (long) i * bits;
    return bits(p, base + (bit >>> 3), (int) (bit & 7), bits);
  }

  public static void putElemBits(MemorySegment p, long base, int i, int bits, int v) {
    final long bit = (long) i * bits;
    putBits(p, base + (bit >>> 3), (int) (bit & 7), bits, v);
  }

  // ── Byte ranges ────────────────────────────────────────────────────────────

  public static void zero(MemorySegment p, long at, long n) {
    p.asSlice(at, n).fill((byte) 0);
  }

  /** {@code n} bytes at {@code at}, as a view of the region (valid as long as the region is). */
  public static MemorySegment view(MemorySegment p, long at, long n) {
    return p.asSlice(at, n);
  }

  /** {@code n} bytes at {@code at} as text (decoded; malformed UTF-8 becomes U+FFFD). */
  public static String text(MemorySegment p, long at, long n) {
    return new String(p.asSlice(at, n).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.UTF_8);
  }

  public static void putBytes(MemorySegment p, long at, byte[] src) {
    MemorySegment.copy(src, 0, p, ValueLayout.JAVA_BYTE, at, src.length);
  }

  public static void putBytes(MemorySegment p, long at, MemorySegment src) {
    MemorySegment.copy(src, 0, p, at, src.byteSize());
  }

  /** {@code s} as UTF-8 (what a utf8 setter stores and measures against its capacity). */
  public static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  /** The empty view: what a data getter of an EMPTY handle returns. */
  public static MemorySegment empty() {
    return EMPTY;
  }

  // ── Atomics ────────────────────────────────────────────────────────────────

  public static int atomicLoadU32(MemorySegment p, long at) {
    return (int) A32.getVolatile(p, at);
  }

  public static int atomicLoadAcquireU32(MemorySegment p, long at) {
    return (int) A32.getAcquire(p, at);
  }

  public static void atomicStoreU32(MemorySegment p, long at, int v) {
    A32.setVolatile(p, at, v);
  }

  public static void atomicStoreReleaseU32(MemorySegment p, long at, int v) {
    A32.setRelease(p, at, v);
  }

  /** Adds {@code d} and returns the NEW value. */
  public static int atomicAddU32(MemorySegment p, long at, int d) {
    return (int) A32.getAndAdd(p, at, d) + d;
  }

  /** Stores {@code v} and returns the old value. */
  public static int atomicSwapU32(MemorySegment p, long at, int v) {
    return (int) A32.getAndSet(p, at, v);
  }

  /** Stores {@code desired} if the word holds {@code expected}; whether it did. */
  public static boolean atomicCasU32(MemorySegment p, long at, int expected, int desired) {
    return A32.compareAndSet(p, at, expected, desired);
  }

  public static long atomicLoadU64(MemorySegment p, long at) {
    return (long) A64.getVolatile(p, at);
  }

  public static long atomicLoadAcquireU64(MemorySegment p, long at) {
    return (long) A64.getAcquire(p, at);
  }

  public static void atomicStoreU64(MemorySegment p, long at, long v) {
    A64.setVolatile(p, at, v);
  }

  public static void atomicStoreReleaseU64(MemorySegment p, long at, long v) {
    A64.setRelease(p, at, v);
  }

  /** Adds {@code d} and returns the NEW value. */
  public static long atomicAddU64(MemorySegment p, long at, long d) {
    return (long) A64.getAndAdd(p, at, d) + d;
  }

  /** Stores {@code v} and returns the old value. */
  public static long atomicSwapU64(MemorySegment p, long at, long v) {
    return (long) A64.getAndSet(p, at, v);
  }

  /** Stores {@code desired} if the word holds {@code expected}; whether it did. */
  public static boolean atomicCasU64(MemorySegment p, long at, long expected, long desired) {
    return A64.compareAndSet(p, at, expected, desired);
  }

  /** A float as the word an {@code atomic} region stores it in, and back. */
  public static int wordOfF32(float v) {
    return Float.floatToRawIntBits(v);
  }

  public static long wordOfF64(double v) {
    return Double.doubleToRawLongBits(v);
  }

  public static float f32OfWord(int w) {
    return Float.intBitsToFloat(w);
  }

  public static double f64OfWord(long w) {
    return Double.longBitsToDouble(w);
  }

  /**
   * The seqlock's payload copy: {@code n} bytes from {@code src} to {@code dst}, every access opaque —
   * word-wise where both sides are 8-byte aligned, byte-wise for the rest. The copy may race with a
   * writer; whoever calls it decides afterwards from the counter whether to keep it.
   */
  public static void racyCopy(MemorySegment dst, MemorySegment src, long n) {
    long i = 0;
    if (aligned(dst, 8) && aligned(src, 8)) {
      for (; i + 8 <= n; i += 8) {
        A64.setOpaque(dst, i, (long) A64.getOpaque(src, i));
      }
    }
    for (; i < n; i++) {
      A8.setOpaque(dst, i, (byte) A8.getOpaque(src, i));
    }
  }
}
