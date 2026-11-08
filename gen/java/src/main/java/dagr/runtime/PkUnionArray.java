package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A union array of a packed node — a generated {@code {U}PackedArray} reads each element as its packed view. */
public class PkUnionArray extends PackedArray {
  /** The payload of the element {@link #next} stepped onto; NPOS for a nil or unreadable one. */
  protected long at = Reader.NPOS;

  public PkUnionArray(MemorySegment buf, long c, int kind) {
    super(buf, c, kind, 1);
  }

  @Override
  public boolean next() {
    if (!begin()) return false;
    at = nextUnion();
    return true;
  }
}
