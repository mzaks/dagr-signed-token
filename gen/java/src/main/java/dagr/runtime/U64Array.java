package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/** A {@code [u64]} / {@code [u64?]} of a regular or frozen node, read by index (the bits). */
public final class U64Array extends ArrayBase {
  private static final ValueLayout.OfLong LE = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

  /** The array whose payload starts at {@code ps}; {@code optionals}: the {@code [u64?]} form. */
  public U64Array(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO : FIXED, 8);
  }

  /** {@code count} elements at {@code base} — a default over its own constant bytes. */
  public U64Array(MemorySegment buf, long base, long count) {
    super(buf, base, count, 8);
  }

  /** The empty array. */
  public static U64Array empty(MemorySegment buf) { return new U64Array(buf, Reader.NPOS, false); }

  /** Element {@code i}; 0 past the end or for a nil element. */
  public long get(int i) { return Reader.u64(buf, at(i)); }

  /** Every element (a nil one as 0): ONE block copy when the elements are a native block (spec/43). */
  public long[] toArray() {
    final int n = size();
    final long[] out = new long[n];
    if (isBlock(8)) {
      MemorySegment.copy(buf, LE, base, out, 0, n);
      return out;
    }
    for (int i = 0; i < n; i++) out[i] = get(i);
    return out;
  }

  /**
   * The elements in place — the zero-copy view of an aligned(8) array (spec 12): a slice when the
   * elements are one raw block whose address keeps the 8-byte alignment (a native segment), else
   * {@code MemorySegment.NULL}. Little-endian values: read them with a little-endian layout.
   */
  public MemorySegment view() {
    return view(8);
  }
}
