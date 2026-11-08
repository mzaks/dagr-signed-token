package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** An enum array of a packed node as RAW codes (spec/45 O-J3): bit-packed (1, 2 or 4 bits), or a varint each. */
public class PkEnumArray extends PackedArray {
  private final boolean bits;
  private int value;

  /** {@code bits}: elements are {@code width} bits each, else varints. */
  public PkEnumArray(MemorySegment buf, long c, int kind, int width, boolean bits) {
    super(buf, c, kind, width);
    this.bits = bits;
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    value = bits ? nextBits() : (int) nextUint();
    return true;
  }

  /** The code of the element {@link #next} stepped onto (0 for a nil one). */
  public int value() {
    return value;
  }

  /** Every code (a nil one as 0) — rewinds. */
  public int[] toArray() {
    rewind();
    final int[] out = new int[size()];
    for (int k = 0; k < out.length && next(); k++) out[k] = value;
    rewind();
    return out;
  }
}
