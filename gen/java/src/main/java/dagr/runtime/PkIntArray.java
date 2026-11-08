package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;


/** A signed integer array of a packed node (i8 … i64, as long). */
public class PkIntArray extends PackedArray {
  private static final ValueLayout.OfLong LE = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

  private long value;

  /** The array of encoding {@code kind} (a {@link PackedArray} constant) whose codec starts at {@code c}. */
  public PkIntArray(MemorySegment buf, long c, int kind, int width) {
    super(buf, c, kind, width);
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    value = nextInt();
    return true;
  }

  /** The element {@link #next} stepped onto (zero for a nil one). */
  public long value() {
    return value;
  }

  /** Every element (a nil one as zero); ONE block copy when they are a raw native block (spec/43) — rewinds. */
  public long[] toArray() {
    rewind();
    final long[] out = new long[size()];
    if (out.length > 0 && isBlock(8)) {
      MemorySegment.copy(buf, LE, pos, out, 0, out.length);
      return out;
    }
    for (int k = 0; k < out.length && next(); k++) out[k] = value;
    rewind();
    return out;
  }
}
