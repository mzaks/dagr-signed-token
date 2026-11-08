package dagr.runtime;

import java.lang.foreign.MemorySegment;

/**
 * The arrays of a packed node (spec 04 §5, spec 07), read FORWARD — a port of the C target's
 * dagr/packed.h. A packed array is a run of self-sizing elements with no offset table: element i
 * is reached by walking the i before it, so there is no {@code get(i)} (an O(i) read under an O(1)
 * name is the Go bug, spec/45 §5.3) — a cursor:
 *
 * <pre>
 *   PkU32Array xs = click.ids();
 *   while (xs.next()) if (xs.present()) total += xs.value();
 * </pre>
 *
 * {@link #rewind} starts over; {@code toArray()} reads every element (and rewinds). A nil element
 * of an array with optionals reports {@code present() == false} and reads zero. Totality (spec/45
 * §4): opening clamps the count against the buffer (every element occupies at least one bit),
 * every read is a checked {@link Reader} call, and a cursor that cannot advance parks at NPOS,
 * where every read yields zero; iteration still ends after {@link #size} steps.
 */
public abstract class PackedArray {
  /** {@code [LEB (count << 2) | tag]}: integers — 0 varints, 1 raw, 2 an encoding bitset. */
  public static final int INTS = 0;
  /** {@code [LEB count][bytes]}: {@code [u8]} / {@code [i8]}. */
  public static final int BYTES = 1;
  /** {@code [LEB (count << 2) | mode]}: floats — mode 1 raw, else self-describing. */
  public static final int FLOATS = 2;
  /** {@code [LEB count][encoding bitset]}: f16 / bf16, two raw bytes or a one-byte special. */
  public static final int HALVES = 3;
  /** {@code [LEB count][packed bits]}: bool, sub-byte enums. */
  public static final int BITS = 4;
  /** {@code [LEB count]} then each element a blob (utf8, data, nodes) — or a varint (wide enums). */
  public static final int BLOBS = 5;
  /** {@code [LEB count][headers][payloads]}: unions. */
  public static final int UNIONS = 6;
  /** The forms with optionals: {@code [header][nil bitset]}, then the PRESENT elements only. */
  public static final int INTS_OPT = 7;
  /** {@code [u8?]}, {@code [i8?]} (width 1), {@code [f16?]}, {@code [bf16?]} (width 2): present elements at their width. */
  public static final int FIXED_OPT = 8;
  public static final int FLOATS_OPT = 9;
  public static final int BITS_OPT = 10;
  public static final int BLOBS_OPT = 11;
  /** {@code [LEB count][nil bitset][LEB header section size][headers][payloads]}. */
  public static final int UNIONS_OPT = 12;

  protected final MemorySegment buf;
  /** Elements (clamped). */
  protected long count;
  /** 0 every element compact, 1 every element raw, 2 per the encoding bitset. */
  protected int mode;
  /** An element's raw width in bytes; bits per element of a bit-packed array. */
  protected int width = 1;
  /** The encoding bitset (mode 2), or the bits of a bit-packed array. */
  protected long enc = Reader.NPOS;
  /** The nil bitset; NPOS when the array has none. */
  protected long nil = Reader.NPOS;
  private long pos0 = Reader.NPOS, payload0;

  /** The next element. */
  protected long i;
  /** The next element's bytes; for a union array, the next header. */
  protected long pos;
  /** A union array's next payload; the next present element's bit index. */
  protected long payload;
  /** Whether the element {@link #next} stepped onto is present (not nil). */
  protected boolean present;

  /** The array of encoding {@code kind} whose codec starts at {@code c}; empty when malformed. */
  protected PackedArray(MemorySegment buf, long c, int kind, int width) {
    this.buf = buf;
    this.pos = Reader.NPOS;
    final long h = Reader.lebPacked(buf, c);
    if (h >= 0) open(c, h, kind, width);
    pos0 = pos;
    payload0 = payload;
  }

  private static long clampCount(MemorySegment b, long base, long count, int minBits) {
    final long rem = Reader.remaining(b, base);
    if (minBits >= 8) return count <= rem ? count : 0;
    return count / 8 <= rem && (count + 7) / 8 <= rem ? count : 0;
  }

  private void open(long c, long h, int kind, int w) {
    final long v = Reader.lebValue(h);
    final long at = c + Reader.lebLength(h);
    pos = Reader.NPOS;
    switch (kind) {
      case INTS -> {
        width = w;
        mode = (int) (v & 3);
        enc = at;
        count = clampCount(buf, enc, v >>> 2, 8);
        pos = enc + (mode == 2 ? (count + 7) / 8 : 0);
      }
      case BYTES -> {
        mode = 1;
        width = 1;
        pos = at;
        count = clampCount(buf, pos, v, 8);
      }
      case FLOATS -> {
        width = w;
        mode = (v & 3) == 1 ? 1 : 0;
        pos = at;
        count = clampCount(buf, pos, v >>> 2, 8);
      }
      case HALVES -> {
        width = 2;
        mode = 2;
        enc = at;
        count = clampCount(buf, enc, v, 8);
        pos = enc + (count + 7) / 8;
      }
      case BITS -> {
        final int bpe = Math.max(w, 1);
        final long rem = Reader.remaining(buf, at);
        // count * bpe bits must fit in rem bytes; compared without multiplying the hostile count
        if (v / 8 <= rem / bpe && (v * bpe + 7) / 8 <= rem) {
          width = bpe;
          enc = at;
          count = v;
        }
      }
      case BLOBS -> {
        pos = at;
        count = clampCount(buf, pos, v, 8);
      }
      case UNIONS -> {
        pos = at;
        count = clampCount(buf, pos, v, 8);
        payload = unionPayloads(pos, count);
      }
      default -> openOpt(at, v, kind, w);
    }
  }

  private void openOpt(long nilAt, long v, int kind, int w) {
    final boolean tagged = kind == INTS_OPT || kind == FLOATS_OPT;
    final long n = clampCount(buf, nilAt, tagged ? v >>> 2 : v, 1);
    if (n == 0) return;
    count = n;
    mode = tagged ? (int) (v & 3) : 0;
    nil = nilAt;
    final long after = nilAt + (n + 7) / 8;
    switch (kind) {
      case INTS_OPT -> {
        width = w;
        enc = after;
        pos = after + (mode == 2 ? (n + 7) / 8 : 0);
      }
      case FIXED_OPT -> {
        width = w;
        mode = 1;
        pos = after;
      }
      case FLOATS_OPT -> {
        width = w;
        mode = mode == 1 ? 1 : 0;
        pos = after;
      }
      case BITS_OPT -> {
        width = Math.max(w, 1);
        enc = after;
      }
      case BLOBS_OPT -> pos = after;
      case UNIONS_OPT -> {
        pos = Reader.lebEnd(buf, after);
        long presentCount = 0;
        for (long k = 0; k < n; k++) presentCount += Reader.bitAt(buf, nil, k) ? 0 : 1;
        payload = unionPayloads(pos, presentCount);
      }
      default -> {}
    }
  }

  /** Where a union array's payloads start: past {@code n} header varints from {@code headers}. */
  private long unionPayloads(long headers, long n) {
    long p = headers;
    for (long k = 0; k < n; k++) {
      p = Reader.lebEnd(buf, p);
      if (p == Reader.NPOS) return Reader.NPOS;
    }
    return p;
  }

  /** The element count (clamped to what an {@code int} counts). */
  public final int size() { return (int) Math.min(count, Integer.MAX_VALUE); }

  public final boolean isEmpty() { return count == 0; }

  /** Back to before the first element. */
  public final void rewind() {
    i = 0;
    pos = pos0;
    payload = payload0;
    present = false;
  }

  /** Whether the element the last {@link #next} stepped onto is present (not nil). */
  public final boolean present() { return present; }

  /** Starts element {@code i}: false at the end; sets {@link #present}. */
  protected final boolean begin() {
    if (i >= count) return false;
    present = nil == Reader.NPOS || !Reader.bitAt(buf, nil, i);
    return true;
  }

  private boolean raw() { return mode == 1 || (mode == 2 && Reader.bitAt(buf, enc, i)); }

  /** The next unsigned integer (u8 … u64, wide enums); 0 for a nil element. */
  protected final long nextUint() {
    long v = 0;
    if (present) {
      if (raw()) {
        v = Reader.uintLe(buf, pos, width);
        pos = Reader.step(pos, width);
      } else {
        v = Reader.leb(buf, pos);
        pos = Reader.lebEnd(buf, pos);
      }
    }
    i++;
    return v;
  }

  /** The next signed integer: raw two's complement, or a zigzag varint. */
  protected final long nextInt() {
    long v = 0;
    if (present) {
      if (raw()) {
        v = Reader.signExtend(Reader.uintLe(buf, pos, width), width);
        pos = Reader.step(pos, width);
      } else {
        v = Reader.zigzagDecode(Reader.leb(buf, pos));
        pos = Reader.lebEnd(buf, pos);
      }
    }
    i++;
    return v;
  }

  /** The next f32 / f64 (an f32 widened exactly). */
  protected final double nextFloat() {
    double v = 0;
    if (present) {
      if (mode == 1) {
        v = width == 4 ? Reader.f32(buf, pos) : Reader.f64(buf, pos);
        pos = Reader.step(pos, width);
      } else {
        v = Reader.packedFloat(buf, pos, width == 4);
        final int n = Reader.packedFloatLen(buf, pos, width == 4);
        pos = n != 0 ? Reader.step(pos, n) : Reader.NPOS;
      }
    }
    i++;
    return v;
  }

  /** The next f16 / bf16. */
  protected final float nextHalf(boolean bf16) {
    float v = 0;
    if (present) {
      if (raw()) {
        v = bf16 ? Reader.bf16(buf, pos) : Reader.f16(buf, pos);
        pos = Reader.step(pos, 2);
      } else {
        v = Reader.packedHalf(buf, pos);
        pos = Reader.step(pos, 1);
      }
    }
    i++;
    return v;
  }

  /** The next bit-packed element (a bool, a sub-byte enum). */
  protected final int nextBits() {
    int v = 0;
    if (present) {
      v = Reader.packedBits(buf, enc, payload, width);
      payload++;
    }
    i++;
    return v;
  }

  /** The POSITION of the next blob element ({@code [LEB size][bytes]}); NPOS for a nil element. */
  protected final long nextBlob() {
    long at = Reader.NPOS;
    if (present) {
      at = pos;
      pos = Reader.skipBlob(buf, pos);
    }
    i++;
    return at;
  }

  /** The type id of the union element {@link #nextUnion} stepped onto (-1: none). */
  protected int unionTag = -1;
  /** Its header's code. */
  protected int unionCode;

  /** The payload position of the next union element (NPOS for a nil or unreadable one); sets {@link #unionTag} / {@link #unionCode}. */
  protected final long nextUnion() {
    long at = Reader.NPOS;
    unionTag = -1;
    unionCode = 0;
    if (present) {
      final long h = pos < 0 ? -1 : Reader.lebPacked(buf, pos);
      if (h < 0) {
        pos = Reader.NPOS; // every later element then fails here too: its payload is never reached
      } else if (payload >= 0) {
        at = payload;
        final long v = Reader.lebValue(h);
        unionTag = (int) ((v >>> 3) & 0xff);
        unionCode = (int) (v & 7);
        pos += Reader.lebLength(h);
        final long n = Reader.packedUnionPayloadBytes(buf, payload, unionCode);
        payload = n != 0 ? Reader.step(payload, n) : Reader.NPOS;
      }
    }
    i++;
    return at;
  }

  /** Whether the element {@link #next}'s reads come from is a whole raw native block ({@code size} bytes each, no nils). */
  protected final boolean isBlock(int size) {
    return mode == 1 && width == size && nil == Reader.NPOS && Reader.inBounds(buf, pos0, count * size);
  }

  /** Steps onto the next element: false at the end. */
  public abstract boolean next();
}
