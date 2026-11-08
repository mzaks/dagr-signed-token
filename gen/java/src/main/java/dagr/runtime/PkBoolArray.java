package dagr.runtime;

import java.lang.foreign.MemorySegment;


/** A {@code [bool]} / {@code [bool?]} of a packed node: one bit per present element. */
public class PkBoolArray extends PackedArray {
  private boolean value;

  /** The array of encoding {@code kind} (a {@link PackedArray} constant) whose codec starts at {@code c}. */
  public PkBoolArray(MemorySegment buf, long c, int kind, int width) {
    super(buf, c, kind, width);
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    value = nextBits() != 0;
    return true;
  }

  /** The element {@link #next} stepped onto (zero for a nil one). */
  public boolean value() {
    return value;
  }

  /** Every element (a nil one as zero) — rewinds. */
  public boolean[] toArray() {
    rewind();
    final boolean[] out = new boolean[size()];
    for (int k = 0; k < out.length && next(); k++) out[k] = value;
    rewind();
    return out;
  }
}
