package dagr.runtime;

import java.lang.foreign.MemorySegment;

/**
 * An enum array of a regular or frozen node, as RAW codes (spec/45 O-J3): byte-aligned elements
 * at the enum's backing width (1 or 2 bytes), or bit-packed (1, 2 or 4 bits). A u32 / u64 bitset
 * enum's array is a {@link U32Array} / {@link U64Array}.
 */
public final class EnumArray extends ArrayBase {
  private final boolean packedBits;

  /** {@code bits}: elements are {@code width} bits each, else {@code width} bytes. */
  public EnumArray(MemorySegment buf, long ps, boolean optionals, int width, boolean bits) {
    super(buf, ps, bits ? (optionals ? AWO_BITS : BITS) : (optionals ? AWO : FIXED), width);
    this.packedBits = bits;
  }

  public static EnumArray empty(MemorySegment buf) { return new EnumArray(buf, Reader.NPOS, false, 1, false); }

  /** The code of element {@code i}; 0 past the end or for a nil element. */
  public int get(int i) { return packedBits ? bits(i) : (int) uint(i); }

  public int[] toArray() {
    final int[] out = new int[size()];
    for (int i = 0; i < out.length; i++) out[i] = get(i);
    return out;
  }
}
