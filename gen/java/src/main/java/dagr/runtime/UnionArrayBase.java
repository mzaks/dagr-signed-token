package dagr.runtime;

import java.lang.foreign.MemorySegment;

/**
 * A union array of a regular or frozen node (spec 05), read by index — a port of the C target's
 * {@code dagr_union_array}: {@code [LEB (count << 2) | wc][type ids][nil bitset?][count slots of
 * 1 << wc bytes][payloads]}. Type ids are {@code tagBits} wide (1, 2 or 4 bits packed low first, or
 * whole bytes); the nil bitset exists only in the array-with-optionals form. A slot holds a small
 * scalar in place, or an offset from {@link #base}. A generated {@code {U}Array} reads element i as
 * a {@code {U}ArrayElem}. The count is clamped: type ids, the nil bitset and the slots must all fit.
 */
public abstract class UnionArrayBase {
  protected final MemorySegment buf;
  protected final long tid;
  protected final long nil;
  protected final long slots;
  /** Payload offsets in the slots are relative to this. */
  protected final long base;
  protected final long count;
  /** Slot width in bytes. */
  protected final int es;
  protected final int tagBits;

  protected UnionArrayBase(MemorySegment buf, long at, int tagBits, boolean optionals) {
    this.buf = buf;
    this.tagBits = tagBits;
    long t = Reader.NPOS, n = Reader.NPOS, s = Reader.NPOS, b = Reader.NPOS, c = 0;
    int w = 1;
    final long h = Reader.lebPacked(buf, at);
    if (h >= 0) {
      final long v = Reader.lebValue(h);
      final int width = 1 << (int) (v & 3);
      final long first = at + Reader.lebLength(h);
      final long rem = Reader.remaining(buf, first);
      final long cnt = v >>> 2;
      // cnt < 2^57 (lebPacked caps the header below 2^59): no product below overflows, so — unlike C,
      // whose arithmetic is unsigned and wraps — the count needs no separate bound first
      final long tidBytes = tagBits < 8 ? (cnt * tagBits + 7) / 8 : cnt * (tagBits / 8);
      final long nilBytes = optionals ? (cnt + 7) / 8 : 0;
      if (tidBytes <= rem && nilBytes <= rem - tidBytes && cnt * width <= rem - tidBytes - nilBytes) {
        t = first;
        n = optionals ? first + tidBytes : Reader.NPOS;
        s = first + tidBytes + nilBytes;
        b = s + cnt * width;
        c = cnt;
        w = width;
      }
    }
    this.tid = t;
    this.nil = n;
    this.slots = s;
    this.base = b;
    this.count = c;
    this.es = w;
  }

  public final int size() { return (int) Math.min(count, Integer.MAX_VALUE); }

  public final boolean isEmpty() { return count == 0; }

  /** Whether element {@code i} exists and is not nil. */
  public final boolean has(int i) {
    if (i < 0 || i >= count) return false;
    return nil == Reader.NPOS || !Reader.bitAt(buf, nil, i);
  }

  /** The type id of element {@code i}; -1 (no variant) past the end or for a nil element. */
  protected final int tag(int i) {
    if (!has(i)) return -1;
    if (tagBits < 8) {
      final long bit = (long) i * tagBits;
      return (Reader.u8(buf, tid + (bit >>> 3)) >>> (bit & 7)) & ((1 << tagBits) - 1);
    }
    final int w = tagBits / 8;
    return (int) Reader.uintLe(buf, tid + (long) i * w, w);
  }

  /** Where element {@code i}'s slot is; NPOS past the end or for a nil element. */
  protected final long slot(int i) { return has(i) ? slots + (long) i * es : Reader.NPOS; }
}
