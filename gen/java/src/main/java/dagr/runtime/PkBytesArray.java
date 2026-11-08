package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [data]} / {@code [data?]} of a packed node. */
public final class PkBytesArray extends PkBlobArray {
  public PkBytesArray(MemorySegment buf, long c, int kind) {
    super(buf, c, kind);
  }

  /** The element {@link #next} stepped onto, zero-copy (empty for a nil one). */
  public MemorySegment value() {
    return Reader.blob(buf, at);
  }
}
