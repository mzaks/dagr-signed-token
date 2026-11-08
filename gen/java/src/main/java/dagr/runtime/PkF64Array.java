package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;


/** An {@code [f64]} / {@code [f64?]} of a packed node. */
public class PkF64Array extends PackedArray {
  private static final ValueLayout.OfDouble LE = ValueLayout.JAVA_DOUBLE_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

  private double value;

  /** The array of encoding {@code kind} (a {@link PackedArray} constant) whose codec starts at {@code c}. */
  public PkF64Array(MemorySegment buf, long c, int kind, int width) {
    super(buf, c, kind, width);
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    value = nextFloat();
    return true;
  }

  /** The element {@link #next} stepped onto (zero for a nil one). */
  public double value() {
    return value;
  }

  /** Every element (a nil one as zero); ONE block copy when they are a raw native block (spec/43) — rewinds. */
  public double[] toArray() {
    rewind();
    final double[] out = new double[size()];
    if (out.length > 0 && isBlock(8)) {
      MemorySegment.copy(buf, LE, pos, out, 0, out.length);
      return out;
    }
    for (int k = 0; k < out.length && next(); k++) out[k] = value;
    rewind();
    return out;
  }
}
