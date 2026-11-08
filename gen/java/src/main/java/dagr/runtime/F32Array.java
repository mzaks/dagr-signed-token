package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/** A {@code [f32]} / {@code [f32?]} of a regular or frozen node, read by index. */
public final class F32Array extends ArrayBase {
  private static final ValueLayout.OfFloat LE = ValueLayout.JAVA_FLOAT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

  /** The array whose payload starts at {@code ps}; {@code optionals}: the {@code [f32?]} form. */
  public F32Array(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO : FIXED, 4);
  }

  /** {@code count} elements at {@code base} — a default over its own constant bytes. */
  public F32Array(MemorySegment buf, long base, long count) {
    super(buf, base, count, 4);
  }

  /** The empty array. */
  public static F32Array empty(MemorySegment buf) { return new F32Array(buf, Reader.NPOS, false); }

  /** Element {@code i}; 0 past the end or for a nil element. */
  public float get(int i) { return Reader.f32(buf, at(i)); }

  /** Every element (a nil one as 0): ONE block copy when the elements are a native block (spec/43). */
  public float[] toArray() {
    final int n = size();
    final float[] out = new float[n];
    if (isBlock(4)) {
      MemorySegment.copy(buf, LE, base, out, 0, n);
      return out;
    }
    for (int i = 0; i < n; i++) out[i] = get(i);
    return out;
  }

  /**
   * The elements in place — the zero-copy view of an aligned(4) array (spec 12): a slice when the
   * elements are one raw block whose address keeps the 4-byte alignment (a native segment), else
   * {@code MemorySegment.NULL}. Little-endian values: read them with a little-endian layout.
   */
  public MemorySegment view() {
    return view(4);
  }
}
