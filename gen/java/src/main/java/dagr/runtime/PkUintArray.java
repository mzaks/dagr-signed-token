package dagr.runtime;

import java.lang.foreign.MemorySegment;


/** An unsigned integer array of a packed node (u8 … u64 widened to long; also a wide enum array's varints). */
public class PkUintArray extends PackedArray {
  private long value;

  /** The array of encoding {@code kind} (a {@link PackedArray} constant) whose codec starts at {@code c}. */
  public PkUintArray(MemorySegment buf, long c, int kind, int width) {
    super(buf, c, kind, width);
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    value = nextUint();
    return true;
  }

  /** The element {@link #next} stepped onto (zero for a nil one). */
  public long value() {
    return value;
  }

  /** Every element (a nil one as zero) — rewinds. */
  public long[] toArray() {
    rewind();
    final long[] out = new long[size()];
    for (int k = 0; k < out.length && next(); k++) out[k] = value;
    rewind();
    return out;
  }
}
