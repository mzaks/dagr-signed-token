package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [u8]} / {@code [u8?]} of a regular or frozen node, read by index (widened). */
public final class U8Array extends ArrayBase {
  /** The array whose payload starts at {@code ps}; {@code optionals}: the {@code [u8?]} form. */
  public U8Array(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO : FIXED, 1);
  }

  /** {@code count} elements at {@code base} — a default over its own constant bytes. */
  public U8Array(MemorySegment buf, long base, long count) {
    super(buf, base, count, 1);
  }

  /** The empty array. */
  public static U8Array empty(MemorySegment buf) { return new U8Array(buf, Reader.NPOS, false); }

  /** Element {@code i}; 0 past the end or for a nil element. */
  public int get(int i) { return Reader.u8(buf, at(i)); }

  /** Every element (a nil one as 0). */
  public int[] toArray() {
    final int n = size();
    final int[] out = new int[n];
    for (int i = 0; i < n; i++) out[i] = get(i);
    return out;
  }

  /**
   * The elements in place — the zero-copy view of an aligned(1) array (spec 12): a slice when the
   * elements are one raw block whose address keeps the 1-byte alignment (a native segment), else
   * {@code MemorySegment.NULL}. Little-endian values: read them with a little-endian layout.
   */
  public MemorySegment view() {
    return view(1);
  }
}
