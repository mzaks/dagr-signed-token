package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [data]} / {@code [data?]} of a regular or frozen node: a pointer table. */
public final class BytesArray extends ArrayBase {
  public BytesArray(MemorySegment buf, long ps) { super(buf, ps, PTRS, 1); }

  public static BytesArray empty(MemorySegment buf) { return new BytesArray(buf, Reader.NPOS); }

  /** Element {@code i}, zero-copy; empty past the end or for a nil element. */
  public MemorySegment get(int i) { return Reader.blob(buf, elem(i, false)); }
}
