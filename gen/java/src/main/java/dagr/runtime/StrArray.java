package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [utf8]} / {@code [utf8?]} of a regular or frozen node: a pointer table. */
public final class StrArray extends ArrayBase {
  public StrArray(MemorySegment buf, long ps) { super(buf, ps, PTRS, 1); }

  public static StrArray empty(MemorySegment buf) { return new StrArray(buf, Reader.NPOS); }

  /** Element {@code i}, decoded; "" past the end or for a nil element. */
  public String get(int i) { return Reader.text(buf, elem(i, false)); }

  /** Element {@code i}'s UTF-8 bytes, zero-copy; empty past the end or for a nil element. */
  public MemorySegment bytes(int i) { return Reader.blob(buf, elem(i, false)); }
}
