package dagr.runtime;

import java.lang.foreign.MemorySegment;

/** A {@code [u32]} / {@code [u32?]} of a regular or frozen node, read by index (widened, spec/45 O-J2). */
public final class U32Array extends ArrayBase {
  /** The array whose payload starts at {@code ps}; {@code optionals}: the {@code [u32?]} form. */
  public U32Array(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO : FIXED, 4);
  }

  /** {@code count} elements at {@code base} — a default over its own constant bytes. */
  public U32Array(MemorySegment buf, long base, long count) {
    super(buf, base, count, 4);
  }

  /** The empty array. */
  public static U32Array empty(MemorySegment buf) { return new U32Array(buf, Reader.NPOS, false); }

  /** Element {@code i}; 0 past the end or for a nil element. */
  public long get(int i) { return Reader.u32(buf, at(i)); }

  /** Every element (a nil one as 0). */
  public long[] toArray() {
    final int n = size();
    final long[] out = new long[n];
    for (int i = 0; i < n; i++) out[i] = get(i);
    return out;
  }

  /**
   * The elements in place — the zero-copy view of an aligned(4) array (spec 12): a slice when the
   * elements are one raw block whose address keeps the 4-byte alignment (a native segment), else
   * {@code MemorySegment.NULL}. Little-endian values: read them with a little-endian layout.
   */
  public MemorySegment view() {
    return view(4);
  }
}
