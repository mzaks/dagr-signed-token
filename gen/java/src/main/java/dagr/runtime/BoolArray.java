package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [bool]} / {@code [bool?]} of a regular or frozen node: one bit per element. */
public final class BoolArray extends ArrayBase {
  public BoolArray(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO_BITS : BITS, 1);
  }

  public static BoolArray empty(MemorySegment buf) { return new BoolArray(buf, Reader.NPOS, false); }

  /** Element {@code i}; false past the end or for a nil element. */
  public boolean get(int i) { return bits(i) != 0; }

  public boolean[] toArray() {
    final boolean[] out = new boolean[size()];
    for (int i = 0; i < out.length; i++) out[i] = get(i);
    return out;
  }
}
