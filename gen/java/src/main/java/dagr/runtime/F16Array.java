package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [f16]} / {@code [f16?]} of a regular or frozen node, read by index (as floats). */
public final class F16Array extends ArrayBase {
  /** The array whose payload starts at {@code ps}; {@code optionals}: the {@code [f16?]} form. */
  public F16Array(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO : FIXED, 2);
  }

  /** {@code count} elements at {@code base} — a default over its own constant bytes. */
  public F16Array(MemorySegment buf, long base, long count) {
    super(buf, base, count, 2);
  }

  /** The empty array. */
  public static F16Array empty(MemorySegment buf) { return new F16Array(buf, Reader.NPOS, false); }

  /** Element {@code i}; 0 past the end or for a nil element. */
  public float get(int i) { return Reader.f16(buf, at(i)); }

  /** Every element (a nil one as 0). */
  public float[] toArray() {
    final int n = size();
    final float[] out = new float[n];
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
