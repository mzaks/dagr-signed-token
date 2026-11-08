package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A blob array of a packed node — {@code [utf8]}, {@code [data]}, a generated {@code [Node]}: each element {@code [LEB size][bytes]}. */
public class PkBlobArray extends PackedArray {
  /** Where the element {@link #next} stepped onto starts; NPOS for a nil one. */
  protected long at = Reader.NPOS;

  public PkBlobArray(MemorySegment buf, long c, int kind) {
    super(buf, c, kind, 1);
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    at = nextBlob();
    return true;
  }
}
