package dagr.runtime;

import java.lang.foreign.MemorySegment;

/**
 * The arrays of a regular or frozen node (spec 04, spec 05), read by index — a port of the C
 * target's dagr/arrays.h. Every such array indexes in O(1): a fixed element stride, a bit stride,
 * or a pointer table. ONE base parses every encoding; the typed views ({@code U32Array}, …,
 * {@code StrArray}, a generated {@code {Node}Array}) read elements of one value domain, with no
 * boxing.
 *
 * <p>{@link #has} is false past the end and for a nil element of an array with optionals; every
 * read of such an element yields zero / empty. Totality (spec/45 §4): opening clamps the count
 * against the buffer, every element read is a checked {@link Reader} call, and an index outside
 * {@code [0, size())} reads nothing.
 */
public abstract class ArrayBase {
  /** {@code [LEB count][elements]}: numerics, byte-aligned enums. */
  public static final int FIXED = 0;
  /** {@code [LEB count][bit-packed elements]}: bool, sub-byte enums ({@code width} = bits). */
  public static final int BITS = 1;
  /** {@code [LEB count][nil bitset][values]}, values at their index whether or not nil. */
  public static final int AWO = 2;
  /** {@link #AWO} with bit-packed values. */
  public static final int AWO_BITS = 3;
  /** {@code [LEB (count << 2) | wc][count slots][element data]}: utf8, data and node arrays. */
  public static final int PTRS = 4;

  protected final MemorySegment buf;
  /** The first element; a pointer table's first slot. */
  protected final long base;
  /** The nil bitset of an array with optionals; {@link Reader#NPOS}: none. */
  protected final long nil;
  /** A pointer table's data base (slot values are offsets from it, plus one). */
  protected final long data;
  /** Elements, clamped against the buffer. */
  protected final long count;
  /** Element width in bytes; bits per element of a bit-packed array; slot width. */
  protected final int width;
  /** A pointer table: a zero slot is a nil element. */
  protected final boolean table;

  /** The array of encoding {@code mode} whose payload starts at {@code ps}; empty when malformed. */
  protected ArrayBase(MemorySegment buf, long ps, int mode, int width) {
    this.buf = buf;
    long b = Reader.NPOS, n = Reader.NPOS, d = Reader.NPOS, c = 0;
    int w = width;
    final long h = Reader.lebPacked(buf, ps);
    if (h >= 0) {
      final long v = Reader.lebValue(h);
      final long at = ps + Reader.lebLength(h);
      final long rem = Reader.remaining(buf, at);
      switch (mode) {
        case FIXED -> {
          if (v <= rem / Math.max(width, 1)) {
            b = at;
            c = v;
          }
        }
        case BITS -> {
          final long bpe = Math.max(width, 1);
          if (v / 8 <= rem / bpe && (v * bpe + 7) / 8 <= rem) {
            b = at;
            c = v;
          }
        }
        case AWO, AWO_BITS -> {
          // v < 2^59 (lebPacked), so nothing below overflows. When the nil bitset alone does not
          // fit, `left` is negative and neither fit test can pass — no separate check (C needs one:
          // its arithmetic is unsigned).
          final long nilBytes = (v + 7) / 8;
          final long left = rem - nilBytes;
          final boolean fits = mode == AWO_BITS
              ? v / 8 <= left / Math.max(width, 1) && (v * width + 7) / 8 <= left
              : width == 0 || v <= left / width;
          if (fits) {
            n = at;
            b = at + nilBytes;
            c = v;
          }
        }
        case PTRS -> {
          final int es = 1 << (int) (v & 3);
          final long cnt = v >>> 2;
          w = es;
          if (cnt <= rem / es) {
            b = at;
            d = at + cnt * es;
            c = cnt;
          }
        }
        default -> {}
      }
    } else if (mode == PTRS) {
      w = 1;
    }
    this.base = b;
    this.nil = n;
    this.data = d;
    this.count = c;
    this.width = w;
    this.table = mode == PTRS;
  }

  /** {@code count} elements of {@code width} bytes at {@code base} — a default over its own constant bytes. */
  protected ArrayBase(MemorySegment buf, long base, long count, int width) {
    this.buf = buf;
    this.base = base;
    this.nil = Reader.NPOS;
    this.data = Reader.NPOS;
    this.count = Math.max(0, Math.min(count, Reader.remaining(buf, base) / Math.max(width, 1)));
    this.width = width;
    this.table = false;
  }

  /** The element count (clamped to what an {@code int} indexes). */
  public final int size() { return (int) Math.min(count, Integer.MAX_VALUE); }

  public final boolean isEmpty() { return count == 0; }

  /** Whether element {@code i} exists and is not nil. The nil bitset is tested only when there is one. */
  public final boolean has(int i) {
    if (i < 0 || i >= count) return false;
    if (nil != Reader.NPOS && Reader.bitAt(buf, nil, i)) return false;
    return !table || slot(i) != 0;
  }

  /** The raw slot value of element {@code i} of a pointer table (0: nil). */
  protected final long slot(int i) { return Reader.uintLe(buf, base + (long) i * width, width); }

  /** Where fixed-width element {@code i} sits; {@link Reader#NPOS} past the end or for a nil element. */
  protected final long at(int i) {
    if (i < 0 || i >= count) return Reader.NPOS;
    if (nil != Reader.NPOS && Reader.bitAt(buf, nil, i)) return Reader.NPOS;
    return base + (long) i * width;
  }

  /** {@code width} bits of element {@code i} of a bit-packed array (0 when absent). */
  protected final int bits(int i) {
    if (!has(i)) return 0;
    return Reader.packedBits(buf, base, i, width);
  }

  /** An unsigned element at the array's width (a byte-aligned enum element at its backing width). */
  protected final long uint(int i) { return Reader.uintLe(buf, at(i), width); }

  /**
   * The position of element {@code i} of a pointer table — {@link Reader#NPOS} past the end or for
   * a nil slot. {@code sign}: node slots are two's complement (a shared or cyclic node may sit
   * BEFORE the array); the sum wraps, and the reader of the position checks wherever it lands.
   */
  protected final long elem(int i, boolean sign) {
    if (i < 0 || i >= count || !table) return Reader.NPOS;
    final long s = slot(i);
    if (s == 0) return Reader.NPOS;
    return data + (sign ? Reader.signExtend(s, width) : s) - 1;
  }

  /** Where node element {@code i} of a {@code [Node]} / {@code [Node?]} array starts ({@link Reader#NPOS}: absent). */
  public final long nodeAt(int i) { return elem(i, true); }

  /**
   * The elements IN PLACE (spec 12): a slice of the buffer when they are one native block of
   * {@code size}-byte values whose ADDRESS keeps that alignment — read it with an aligned layout —
   * else {@code MemorySegment.NULL}; read by index then, which has no such precondition. An empty
   * array is an empty slice.
   */
  protected final MemorySegment view(int size) {
    if (count == 0) return buf.asSlice(0, 0);
    // a heap segment's alignment is its array's (maxByteAlignment is Java 23): only a native
    // segment's address says where the block really sits
    if (!isBlock(size) || (size > 1 && !buf.isNative()) || (buf.address() + base) % size != 0) {
      return MemorySegment.NULL;
    }
    return buf.asSlice(base, count * size);
  }

  /** Whether the elements are ONE native-LE block of {@code size}-byte values (spec/43): no nil bitset, no table. */
  protected final boolean isBlock(int size) {
    // inBounds, not `count <= remaining / size`: an empty array has no position (base NPOS), and
    // even a zero-length copy at -1 throws
    return width == size && nil == Reader.NPOS && !table && Reader.inBounds(buf, base, count * size);
  }
}
