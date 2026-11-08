package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;


/** An {@code [f32]} / {@code [f32?]} of a packed node. */
public class PkF32Array extends PackedArray {
  private static final ValueLayout.OfFloat LE = ValueLayout.JAVA_FLOAT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

  private float value;

  /** The array of encoding {@code kind} (a {@link PackedArray} constant) whose codec starts at {@code c}. */
  public PkF32Array(MemorySegment buf, long c, int kind, int width) {
    super(buf, c, kind, width);
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    value = (float) nextFloat();
    return true;
  }

  /** The element {@link #next} stepped onto (zero for a nil one). */
  public float value() {
    return value;
  }

  /** Every element (a nil one as zero); ONE block copy when they are a raw native block (spec/43) — rewinds. */
  public float[] toArray() {
    rewind();
    final float[] out = new float[size()];
    if (out.length > 0 && isBlock(4)) {
      MemorySegment.copy(buf, LE, pos, out, 0, out.length);
      return out;
    }
    for (int k = 0; k < out.length && next(); k++) out[k] = value;
    rewind();
    return out;
  }
}
