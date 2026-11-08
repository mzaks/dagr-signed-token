package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** An {@code [f16]} / {@code [bf16]} (and their optional forms) of a packed node, as floats. */
public class PkHalfArray extends PackedArray {
  private final boolean bf16;
  private float value;

  public PkHalfArray(MemorySegment buf, long c, int kind, boolean bf16) {
    super(buf, c, kind, 2);
    this.bf16 = bf16;
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    value = nextHalf(bf16);
    return true;
  }

  /** The element {@link #next} stepped onto (zero for a nil one). */
  public float value() {
    return value;
  }

  /** Every element (a nil one as zero) — rewinds. */
  public float[] toArray() {
    rewind();
    final float[] out = new float[size()];
    for (int k = 0; k < out.length && next(); k++) out[k] = value;
    rewind();
    return out;
  }
}
