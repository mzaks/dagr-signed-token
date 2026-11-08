package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [utf8]} / {@code [utf8?]} of a packed node. */
public final class PkStrArray extends PkBlobArray {
  public PkStrArray(MemorySegment buf, long c, int kind) {
    super(buf, c, kind);
  }

  /** The element {@link #next} stepped onto, decoded ("" for a nil one). */
  public String value() {
    return Reader.text(buf, at);
  }

  /** Its UTF-8 bytes, zero-copy. */
  public MemorySegment bytes() {
    return Reader.blob(buf, at);
  }
}
