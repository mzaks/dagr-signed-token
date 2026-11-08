package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [u16]} / {@code [u16?]} of a regular or frozen node, read by index (widened). */
public final class U16Array extends ArrayBase {
  /** The array whose payload starts at {@code ps}; {@code optionals}: the {@code [u16?]} form. */
  public U16Array(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO : FIXED, 2);
  }

  /** {@code count} elements at {@code base} — a default over its own constant bytes. */
  public U16Array(MemorySegment buf, long base, long count) {
    super(buf, base, count, 2);
  }

  /** The empty array. */
  public static U16Array empty(MemorySegment buf) { return new U16Array(buf, Reader.NPOS, false); }

  /** Element {@code i}; 0 past the end or for a nil element. */
  public int get(int i) { return Reader.u16(buf, at(i)); }

  /** Every element (a nil one as 0). */
  public int[] toArray() {
    final int n = size();
    final int[] out = new int[n];
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
