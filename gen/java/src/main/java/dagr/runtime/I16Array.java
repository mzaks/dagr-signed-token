package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/** A {@code [i16]} / {@code [i16?]} of a regular or frozen node, read by index. */
public final class I16Array extends ArrayBase {
  private static final ValueLayout.OfShort LE = ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

  /** The array whose payload starts at {@code ps}; {@code optionals}: the {@code [i16?]} form. */
  public I16Array(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO : FIXED, 2);
  }

  /** {@code count} elements at {@code base} — a default over its own constant bytes. */
  public I16Array(MemorySegment buf, long base, long count) {
    super(buf, base, count, 2);
  }

  /** The empty array. */
  public static I16Array empty(MemorySegment buf) { return new I16Array(buf, Reader.NPOS, false); }

  /** Element {@code i}; 0 past the end or for a nil element. */
  public short get(int i) { return Reader.i16(buf, at(i)); }

  /** Every element (a nil one as 0): ONE block copy when the elements are a native block (spec/43). */
  public short[] toArray() {
    final int n = size();
    final short[] out = new short[n];
    if (isBlock(2)) {
      MemorySegment.copy(buf, LE, base, out, 0, n);
      return out;
    }
    for (int i = 0; i < n; i++) out[i] = get(i);
    return out;
  }

  /**
   * The elements in place — the zero-copy view of an aligned(2) array (spec 12): a slice when the
   * elements are one raw block whose address keeps the 2-byte alignment (a native segment), else
   * {@code MemorySegment.NULL}. Little-endian values: read them with a little-endian layout.
   */
  public MemorySegment view() {
    return view(2);
  }
}
