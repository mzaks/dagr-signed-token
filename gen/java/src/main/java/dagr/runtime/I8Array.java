package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/** A {@code [i8]} / {@code [i8?]} of a regular or frozen node, read by index. */
public final class I8Array extends ArrayBase {
  private static final ValueLayout.OfByte LE = ValueLayout.JAVA_BYTE;

  /** The array whose payload starts at {@code ps}; {@code optionals}: the {@code [i8?]} form. */
  public I8Array(MemorySegment buf, long ps, boolean optionals) {
    super(buf, ps, optionals ? AWO : FIXED, 1);
  }

  /** {@code count} elements at {@code base} — a default over its own constant bytes. */
  public I8Array(MemorySegment buf, long base, long count) {
    super(buf, base, count, 1);
  }

  /** The empty array. */
  public static I8Array empty(MemorySegment buf) { return new I8Array(buf, Reader.NPOS, false); }

  /** Element {@code i}; 0 past the end or for a nil element. */
  public byte get(int i) { return Reader.i8(buf, at(i)); }

  /** Every element (a nil one as 0): ONE block copy when the elements are a native block (spec/43). */
  public byte[] toArray() {
    final int n = size();
    final byte[] out = new byte[n];
    if (isBlock(1)) {
      MemorySegment.copy(buf, LE, base, out, 0, n);
      return out;
    }
    for (int i = 0; i < n; i++) out[i] = get(i);
    return out;
  }

  /**
   * The elements in place — the zero-copy view of an aligned(1) array (spec 12): a slice when the
   * elements are one raw block whose address keeps the 1-byte alignment (a native segment), else
   * {@code MemorySegment.NULL}. Little-endian values: read them with a little-endian layout.
   */
  public MemorySegment view() {
    return view(1);
  }
}
