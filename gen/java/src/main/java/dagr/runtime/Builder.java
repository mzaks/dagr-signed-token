package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Where a writer stores a buffer (spec/45 §5.2) — the C target's {@code dagr_builder}. Bytes are
 * stored BACK TO FRONT: each store claims room immediately below what is stored so far, so a
 * child is written before the parent that points at it. {@link #growing} reallocates a heap
 * segment as it fills; {@link #fixed} writes into caller storage and allocates nothing.
 *
 * <p>Failure is STICKY and never thrown: a claim that cannot be served sets {@link #status}
 * ({@code BUFFER_FULL}, {@code OUT_OF_MEMORY}, or a store's {@code INVALID_VALUE}) and every later
 * claim fails too; the caller reads {@code status()} once, at the end.
 */
public final class Builder {
  private MemorySegment seg;
  private byte[] array;   // seg's backing array (a heap segment), or null — what a string store writes into directly
  private long arrayBase;
  private char[] chars = new char[64];   // a string's chars, measured for UTF-8 (Writer.utf8Measure)
  // Writer.utf8Measure's cache: the last short String seen in each slot (by identity) and its
  // measure. Strings are immutable, so an entry can never go stale; a miss overwrites the slot.
  // Made on the first short string, so a builder that stores none (or a fixed one made per
  // message that stores few) does not pay for it.
  String[] measured;
  long[] measures;
  static final int MEASURE_SLOTS = 256;
  private long cap;
  private long cursor;
  private Status status = Status.OK;
  private long alignmentOffset;
  private final boolean growable;

  private Builder(MemorySegment seg, boolean growable) {
    this.growable = growable;
    adopt(seg);
  }

  private void adopt(MemorySegment s) {
    seg = s;
    cap = s.byteSize();
    // a heap segment's address is its offset in the array; a read-only one exposes no array
    array = !s.isNative() && s.heapBase().orElse(null) instanceof byte[] a ? a : null;
    arrayBase = array != null ? s.address() : 0;
  }

  /** A builder that grows a heap segment as it fills. */
  public static Builder growing() {
    return growing(256);
  }

  public static Builder growing(int initialCapacity) {
    return new Builder(MemorySegment.ofArray(new byte[Math.max(initialCapacity, 16)]), true);
  }

  /** A builder over caller storage: no allocation; {@code BUFFER_FULL} when a buffer does not fit. The buffer is written at the END of {@code storage}. */
  public static Builder fixed(MemorySegment storage) {
    return new Builder(storage, false);
  }

  public Status status() {
    return status;
  }

  public boolean ok() {
    return status == Status.OK;
  }

  /** Records the first failure; every later claim fails. */
  public void fail(Status s) {
    if (status == Status.OK) status = s;
  }

  /** Bytes stored so far. */
  public long cursor() {
    return cursor;
  }

  /** Rewinds for another buffer over the same storage (the alignment offset is kept). */
  public void reset() {
    cursor = 0;
    status = Status.OK;
  }

  /** Back to an earlier cursor (dropping what was stored since) — a header stored once to measure it. */
  public void rewind(long to) {
    if (status == Status.OK && to >= 0 && to <= cursor) cursor = to;
  }

  /**
   * The LEB stored most recently, at the front of what is stored, if it began after cursor {@code since}:
   * {@code (value << 4) | length}, or -1 — what a spec-15 header frame reads its fields' length from.
   */
  long frontLeb(long since) {
    if (status != Status.OK || since > cursor) return -1;
    final long avail = cursor - since;
    final long p = cap - cursor;
    long v = 0;
    for (int i = 0; i < avail && i < 9; i++) {
      final int x = get(p + i);
      v |= (long) (x & 0x7f) << (7 * i);
      if ((x & 0x80) == 0) return (v << 4) | (i + 1);
    }
    return -1;
  }

  /** The number of bytes that will PRECEDE the finished buffer in its envelope (spec 12 §14); kept across {@link #reset}. */
  public void setAlignmentOffset(long offset) {
    alignmentOffset = offset;
  }

  public long alignmentOffset() {
    return alignmentOffset;
  }

  /** The buffer stored so far — a view into this builder, valid until it is next used; empty once anything failed. */
  public MemorySegment bytes() {
    return status == Status.OK ? seg.asSlice(cap - cursor, cursor) : MemorySegment.ofArray(new byte[0]);
  }

  /** Where the first byte sits that was stored when the cursor was {@code at}. */
  long position(long at) {
    return cap - at;
  }

  MemorySegment segment() {
    return seg;
  }

  /** Scratch room for {@code n} chars, reused across stores. */
  char[] chars(int n) {
    if (chars.length < n) chars = new char[Math.max(n, chars.length * 2)];
    return chars;
  }

  /** The backing array (null for a native segment), and where position 0 sits in it. */
  public byte[] array() {
    return array;
  }

  long arrayBase() {
    return arrayBase;
  }

  /**
   * Where {@code n} bytes may be written FORWARD in {@link #array}, below what is stored, without
   * claiming them — what a sink record of bounded scalars is written into (Sink.writeForward) — or
   * -1: no heap array, a failed builder, or no room (a fixed builder never fails for it; the caller
   * takes the backward path, which claims exactly).
   */
  public int room(int n) {
    if (array == null || status != Status.OK) return -1;
    if (n > cap - cursor && (!growable || !grow(n))) return -1;
    return (int) (arrayBase + cap - cursor - n);
  }

  /** The absolute position of {@code n} new bytes immediately below what is stored, or -1 (and the builder fails). */
  long claim(long n) {
    if (status != Status.OK) return -1;
    if (n > cap - cursor && !grow(n)) return -1;
    cursor += n;
    return cap - cursor;
  }

  private boolean grow(long n) {
    if (!growable) {
      fail(Status.BUFFER_FULL);
      return false;
    }
    final long need = cursor + n;
    long next = Math.max(cap * 2, need + 64);
    if (next > Integer.MAX_VALUE - 8) next = need;
    if (next > Integer.MAX_VALUE - 8) {
      fail(Status.OUT_OF_MEMORY);
      return false;
    }
    final MemorySegment bigger = MemorySegment.ofArray(new byte[(int) next]);
    MemorySegment.copy(seg, cap - cursor, bigger, next - cursor, cursor);
    adopt(bigger);
    return true;
  }

  /** Appends {@code tail} AFTER what is stored — a doubly-linked sink's trailing span (spec 11 §11.4). */
  void appendTail(byte[] tail) {
    final long n = tail.length;
    if (n == 0 || claim(n) < 0) return;
    final long front = cap - cursor;
    MemorySegment.copy(seg, front + n, seg, front, cursor - n);
    MemorySegment.copy(MemorySegment.ofArray(tail), 0, seg, cap - n, n);
  }

  /** Copies {@code n} stored bytes from {@code from} to {@code to} (overlap allowed). */
  void move(long from, long to, long n) {
    if (n > 0) MemorySegment.copy(seg, from, seg, to, n);
  }

  // A heap builder writes its array directly: a segment access per byte costs its session, read-only
  // and bounds checks each time (measured: most of an encode). Positions come from claim(), inside the
  // segment; the array's own bounds check remains.

  void put(long p, int v) {
    final byte[] a = array;
    if (a != null) {
      a[(int) (arrayBase + p)] = (byte) v;
    } else {
      seg.set(ValueLayout.JAVA_BYTE, p, (byte) v);
    }
  }

  int get(long p) {
    final byte[] a = array;
    return a != null ? Byte.toUnsignedInt(a[(int) (arrayBase + p)]) : Byte.toUnsignedInt(seg.get(ValueLayout.JAVA_BYTE, p));
  }

  /** {@code n} bytes of {@code src} from {@code off}, at {@code p}. */
  void putBytes(long p, byte[] src, int off, int n) {
    final byte[] a = array;
    if (a != null) {
      System.arraycopy(src, off, a, (int) (arrayBase + p), n);
    } else {
      MemorySegment.copy(src, off, seg, ValueLayout.JAVA_BYTE, p, n);
    }
  }

  /** {@code n} bytes of {@code src}, at {@code p}. */
  void putSegment(long p, MemorySegment src, long n) {
    final byte[] a = array;
    if (a != null) {
      MemorySegment.copy(src, ValueLayout.JAVA_BYTE, 0, a, (int) (arrayBase + p), (int) n);
    } else {
      MemorySegment.copy(src, 0, seg, p, n);
    }
  }
}
