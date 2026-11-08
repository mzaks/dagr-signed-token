package dagr.runtime;

import java.lang.foreign.MemorySegment;

/**
 * The DataSink runtime (spec/11, spec/34; spec/45 milestone 4) — a port of the C target's
 * dagr/sink.h: stream framing, the record scan, the reverse span of a doubly-linked sink, record
 * ranges, enum records, raw-embedded graphs in records, the destinations.
 *
 * <pre>[LEB framing] ([LEB length][packed header]) ( [LEB type id][LEB size][body] [RLEB span]? )*</pre>
 *
 * Every reader function is TOTAL: a truncated or garbled tail ends the stream; nothing throws.
 */
public final class Sink {
  private Sink() {}

  /** The reserved band of meta-record type ids (spec 34 §2.1). */
  public static final long META_TYPE_ID_BASE = 16384;
  public static final long META_TYPE_ID_END = 32767;
  /** The framing word of a sink stream: the kind bit (2) set, and bit 0 when a header follows. */
  public static final int FRAMING_PLAIN = 2;
  public static final int FRAMING_WITH_HEADER = 3;

  public static boolean isMetaTypeId(long typeId) {
    return typeId >= META_TYPE_ID_BASE && typeId <= META_TYPE_ID_END;
  }

  /** A record's bytes RELATIVE to the stream's records start (spec 34 §3.1): [start, end), a doubly-linked record's trailing span included — the ranges of a stream tile its records. */
  public record Range(long typeId, long start, long end) {}

  /** Where a sink stream's records go: {@code write} takes one whole record (or the framing) — all of it, or fails having taken none. */
  public interface Dest {
    Status write(MemorySegment bytes);

    /** {@code len} bytes of {@code a} from {@code off} — what a heap builder hands over without a segment view. */
    default Status write(byte[] a, int off, int len) {
      return write(MemorySegment.ofArray(a).asSlice(off, len));
    }

    /**
     * Writing IN PLACE: where up to {@code n} bytes may be written directly after what this destination
     * holds — an index into {@link #array} — or -1 (the default), and the writer hands each record over
     * through {@code write}. Bytes written there count only once {@link #commit}ted.
     */
    default int room(int n) {
      return -1;
    }

    /** The array {@link #room} indexes — read after {@code room}, which may replace it. */
    default byte[] array() {
      return null;
    }

    /** Takes the {@code len} bytes written in place at the index {@link #room} returned. */
    default Status commit(int len) {
      return Status.INVALID_VALUE;
    }
  }

  /** The write observer (spec 34 §3.2): called once per appended record, meta records included, with its range and its exact bytes (valid for the call only). */
  public interface Observer {
    void observe(Range range, MemorySegment bytes);
  }

  /** A destination over caller storage: every record lands in one write, all of it or — {@code BUFFER_FULL} — none. */
  public static final class FixedDest implements Dest {
    private final MemorySegment storage;
    private final byte[] array;   // storage's backing array (a heap segment), or null
    private final long arrayBase;
    private long size;

    public FixedDest(MemorySegment storage) {
      this.storage = storage;
      array = !storage.isNative() && !storage.isReadOnly() && storage.heapBase().orElse(null) instanceof byte[] a ? a : null;
      arrayBase = array != null ? storage.address() : 0;
    }

    @Override
    public Status write(MemorySegment bytes) {
      if (bytes.byteSize() > storage.byteSize() - size) return Status.BUFFER_FULL;
      MemorySegment.copy(bytes, 0, storage, size, bytes.byteSize());
      size += bytes.byteSize();
      return Status.OK;
    }

    @Override
    public int room(int n) {
      return array != null && n <= storage.byteSize() - size ? (int) (arrayBase + size) : -1;
    }

    @Override
    public byte[] array() {
      return array;
    }

    @Override
    public Status commit(int len) {
      if (array == null || len < 0 || len > storage.byteSize() - size) return Status.BUFFER_FULL;
      size += len;
      return Status.OK;
    }

    @Override
    public Status write(byte[] a, int off, int len) {
      if (len > storage.byteSize() - size) return Status.BUFFER_FULL;
      if (array != null) System.arraycopy(a, off, array, (int) (arrayBase + size), len);
      else MemorySegment.copy(a, off, storage, java.lang.foreign.ValueLayout.JAVA_BYTE, size, len);
      size += len;
      return Status.OK;
    }

    /** What has been written so far. */
    public MemorySegment bytes() {
      return storage.asSlice(0, size);
    }
  }

  /** A destination that grows a heap buffer. */
  public static final class GrowingDest implements Dest {
    private byte[] data = new byte[256];
    private int size;

    @Override
    public Status write(MemorySegment bytes) {
      final long n = bytes.byteSize();
      if (n > Integer.MAX_VALUE - 8 - size) return Status.OUT_OF_MEMORY;
      if (size + n > data.length) data = java.util.Arrays.copyOf(data, (int) Math.max(data.length * 2L, size + n));
      MemorySegment.copy(bytes, 0, MemorySegment.ofArray(data), size, n);
      size += (int) n;
      return Status.OK;
    }

    @Override
    public int room(int n) {
      if (n > Integer.MAX_VALUE - 8 - size) return -1;
      if (size + n > data.length) data = java.util.Arrays.copyOf(data, (int) Math.max(data.length * 2L, (long) size + n));
      return size;
    }

    @Override
    public byte[] array() {
      return data;
    }

    @Override
    public Status commit(int len) {
      if (len < 0 || len > data.length - size) return Status.OUT_OF_MEMORY;
      size += len;
      return Status.OK;
    }

    @Override
    public Status write(byte[] a, int off, int len) {
      if (len > Integer.MAX_VALUE - 8 - size) return Status.OUT_OF_MEMORY;
      if (size + len > data.length) data = java.util.Arrays.copyOf(data, (int) Math.max(data.length * 2L, (long) size + len));
      System.arraycopy(a, off, data, size, len);
      size += len;
      return Status.OK;
    }

    public MemorySegment bytes() {
      return MemorySegment.ofArray(data).asSlice(0, size);
    }
  }

  // ── Framing ─────────────────────────────────────────────────────────────────

  /** Where a stream's parts are: the header block (NPOS without one) and the first record. */
  public static final class Frame {
    public long headerAt = Reader.NPOS;
    public long recordsStart;
  }

  /**
   * Parses the framing word (and skips the header) of a sink stream. {@code header} says whether the
   * schema declares one: a stream that disagrees is refused — {@code BAD_FRAMING} for a graph buffer
   * or an unexpected header, {@code NO_HEADER} for a missing one. An EMPTY buffer is an empty stream.
   */
  public static Status frameOf(MemorySegment buf, boolean header, Frame out) {
    out.headerAt = Reader.NPOS;
    out.recordsStart = 0;
    if (buf.byteSize() == 0) return Status.OK;
    final long f = Reader.lebPacked(buf, 0);
    if (f < 0 || (Reader.lebValue(f) & 2) == 0) return Status.BAD_FRAMING;
    final boolean has = (Reader.lebValue(f) & 1) != 0;
    if (has != header) return has ? Status.BAD_FRAMING : Status.NO_HEADER;
    final int fl = Reader.lebLength(f);
    if (!header) {
      out.recordsStart = fl;
      return Status.OK;
    }
    final long l = Reader.lebPacked(buf, fl);
    if (l < 0 || Reader.lebValue(l) > Reader.remaining(buf, fl + Reader.lebLength(l))) return Status.BAD_FRAMING;
    out.headerAt = fl;
    out.recordsStart = fl + Reader.lebLength(l) + Reader.lebValue(l);
    return Status.OK;
  }

  /** The record region of a framed stream: everything after the framing word and the header. */
  public static MemorySegment recordsRegion(MemorySegment buf, Frame frame) {
    return slice(buf, frame.recordsStart, buf.byteSize());
  }

  // ── Records ─────────────────────────────────────────────────────────────────

  /** One record of a stream, as positions: {@code content} is the size prefix (where a record's packed accessor opens), {@code value} the byte after it, {@code end} the byte after the body, {@code next} the next record. */
  public static final class At {
    public long typeId;
    public long begin;
    public long content;
    public long value;
    public long end;
    public long next;
  }

  /** The record at {@code pos}, or false when none starts there (the end, a tail too short to hold one). A doubly-linked record's span is stepped over. */
  public static boolean recordRead(MemorySegment buf, long pos, boolean doublyLinked, At out) {
    if (pos < 0 || pos >= buf.byteSize()) return false;
    final long tid = Reader.lebPacked(buf, pos);
    if (tid < 0) return false;
    final long content = pos + Reader.lebLength(tid);
    final long size = Reader.lebPacked(buf, content);
    if (size < 0) return false;
    final long value = content + Reader.lebLength(size);
    if (Reader.lebValue(size) > Reader.remaining(buf, value)) return false;
    final long end = value + Reader.lebValue(size);
    long next = end;
    if (doublyLinked) {
      final int span = Writer.lebLength(end - pos);
      if (span > Reader.remaining(buf, end)) return false;
      next = end + span;
    }
    out.typeId = Reader.lebValue(tid);
    out.begin = pos;
    out.content = content;
    out.value = value;
    out.end = end;
    out.next = next;
    return true;
  }

  /** The record that ENDS at {@code end} in a doubly-linked stream, or false when the trailing span there does not lead to a whole record at or after {@code floor}. */
  public static boolean recordBefore(MemorySegment buf, long floor, long end, At out) {
    if (end > buf.byteSize() || end <= floor) return false;
    // the span's LEB bytes in reverse (spec 11 §11.4): read right to left up to the terminator
    long value = 0;
    int shift = 0;
    long pos = end;
    int len = 0;
    while (pos > floor && shift <= 63) {
      pos--;
      final int x = Reader.u8(buf, pos);
      value |= (long) (x & 0x7f) << shift;
      if ((x & 0x80) == 0) {
        len = (int) (end - pos);
        break;
      }
      shift += 7;
    }
    if (len == 0) return false;
    final long bodyEnd = end - len;
    if (value < 0 || value > bodyEnd - floor) return false;
    final long begin = bodyEnd - value;
    final At rec = new At();
    if (!recordRead(buf, begin, true, rec) || rec.end != bodyEnd || rec.next != end) return false;
    out.typeId = rec.typeId;
    out.begin = rec.begin;
    out.content = rec.content;
    out.value = rec.value;
    out.end = rec.end;
    out.next = rec.next;
    return true;
  }

  /** A record's content — its size prefix and body: what {@code appendRaw} takes back. */
  public static MemorySegment recordContent(MemorySegment buf, At at) {
    return slice(buf, at.content, at.end);
  }

  /** The bytes of {@code range} (relative to {@code recordsStart}): a record's exact wire bytes. */
  public static MemorySegment rangeBytes(MemorySegment buf, long recordsStart, Range range) {
    if (range.start() < 0 || range.end() < range.start()) return MemorySegment.ofArray(new byte[0]);
    return slice(buf, recordsStart + range.start(), recordsStart + range.end());
  }

  static MemorySegment slice(MemorySegment buf, long from, long to) {
    final long n = buf.byteSize();
    from = Math.max(0, Math.min(from, n));
    to = Math.max(from, Math.min(to, n));
    return buf.asSlice(from, to - from);
  }

  // ── Enum records (spec 11 §2) ───────────────────────────────────────────────

  /** The content of an ENUM record: one raw byte for a byte-wide enum; a wider one as a varint when shorter than its width — behind the size prefix. */
  public static void storeEnum(Builder b, long value, int width) {
    final long before = b.cursor();
    if (width == 1) Writer.storeU8(b, (int) value);
    else if (Writer.lebLength(value) < width) Writer.storeLeb(b, value);
    else Writer.storeFixed(b, value, width);
    Writer.storeLeb(b, b.cursor() - before);
  }

  /** The value of an enum record whose content holds {@code size} bytes at {@code at}. */
  public static long readEnum(MemorySegment buf, long at, long size, int width) {
    if (width == 1) return Reader.u8(buf, at);
    if (size == width) return Reader.uintLe(buf, at, width);
    return Reader.leb(buf, at);
  }

  // ── Raw-embedded graphs in records (spec 18 §11) ────────────────────────────

  /** The standalone graph a record's raw-embedded entry at {@code pos} holds: {@code [LEB payload length]}, then — with aligned arrays — a pad count {@code p} and {@code p} zero bytes, then the graph. The pad LEADS (spec 18 §11.4). Empty when unreadable. */
  public static MemorySegment rawBlob(MemorySegment buf, long pos, boolean hasPad) {
    final MemorySegment none = MemorySegment.ofArray(new byte[0]);
    if (pos < 0) return none;
    final long l = Reader.lebPacked(buf, pos);
    if (l < 0) return none;
    long start = pos + Reader.lebLength(l);
    long size = Reader.lebValue(l);
    if (size > Reader.remaining(buf, start)) return none;
    if (hasPad) {
      if (size == 0) return none;
      final int pad = Reader.u8(buf, start);
      if (pad + 1 > size) return none;
      start += pad + 1;
      size -= pad + 1;
    }
    return buf.asSlice(start, size);
  }

  /** The root of that graph as a position in {@code buf} (its pointers are relative, so its accessors read it in place); NPOS when unreadable. */
  public static long rawRoot(MemorySegment buf, long pos, boolean hasPad) {
    final MemorySegment blob = rawBlob(buf, pos, hasPad);
    if (blob.byteSize() == 0) return Reader.NPOS;
    final long root = Reader.rootOffset(blob);
    if (root == Reader.NPOS) return Reader.NPOS;
    return blob.address() - buf.address() + root;
  }

  /** Stores {@code blob}, a standalone graph, as a record field's raw-embedded payload with {@code pad} leading zero bytes; returns the cursor just after the blob. */
  public static long storeRaw(Builder b, MemorySegment blob, boolean hasPad, int pad) {
    final long before = b.cursor();
    if (blob != null && blob.byteSize() > 0) {
      final long p = b.claim(blob.byteSize());
      if (p >= 0) b.putSegment(p, blob, blob.byteSize());
    }
    final long at = b.cursor();
    if (hasPad) {
      Writer.storeZeros(b, pad);
      Writer.storeU8(b, pad);
    }
    Writer.storeLeb(b, b.cursor() - before);
    return at;
  }

  /**
   * The leading pad of a record's raw-embedded graph (spec 18 §11.4, spec 42 D6): {@code block} is
   * the record content {@code [LEB size][fields]} written with pad 0, its graph at {@code blobOffset};
   * {@code base} is the stream position of the block's first byte. The SMALLEST count in [0, 255]
   * that puts the graph on an {@code n} boundary, COUNTING that the pad lengthens the field's payload
   * length and the record's size. 0 when none does.
   */
  public static int rawPad(MemorySegment block, long blobOffset, long base, long n) {
    final long size = Reader.lebPacked(block, 0);
    if (n == 0 || size < 0 || blobOffset < 2 || blobOffset > block.byteSize()) return 0;
    long q = blobOffset - 2; // the payload length's last byte: the pad count follows
    while (q > 0 && (Reader.u8(block, q - 1) & 0x80) != 0) q--;
    final long payload = Reader.lebPacked(block, q);
    if (payload < 0) return 0;
    for (int pad = 0; pad < 256; pad++) {
      final long growP = Writer.lebLength(Reader.lebValue(payload) + pad) - Reader.lebLength(payload);
      final long growC = Writer.lebLength(Reader.lebValue(size) + pad + growP) - Reader.lebLength(size);
      if ((base + blobOffset + pad + growP + growC) % n == 0) return pad;
    }
    return 0;
  }

  /** Puts the raw-embedded graph of the record content just stored in {@code b} (with pad 0) on its {@code n} boundary in the stream, {@code base} being where the content will start. Only the head in front of the graph moves (spec 42 D6). */
  public static void placeRaw(Builder b, long blobAt, long base, long n) {
    if (!b.ok()) return;
    final MemorySegment block = b.bytes();
    if (blobAt > block.byteSize()) return;
    final long bo = block.byteSize() - blobAt;
    final int pad = rawPad(block, bo, base, n);
    if (pad == 0) return;
    final long size = Reader.lebPacked(block, 0);
    long q = bo - 2;
    while (q > 0 && (Reader.u8(block, q - 1) & 0x80) != 0) q--;
    final long payload = Reader.lebPacked(block, q);
    final long newPayload = Reader.lebValue(payload) + pad;
    final long newSize = Reader.lebValue(size) + pad + (Writer.lebLength(newPayload) - Reader.lebLength(payload));
    final long grow = pad + (Writer.lebLength(newPayload) - Reader.lebLength(payload))
        + (Writer.lebLength(newSize) - Reader.lebLength(size));
    final long middle = q - Reader.lebLength(size); // the fields before, and the field's tag
    final long stored = b.cursor();
    final long front = b.claim(grow);
    if (front < 0) return;
    // where the pad-0 content starts — computed AFTER the claim, which may have moved the storage
    final long old = b.position(stored);
    b.move(old + Reader.lebLength(size), front + Writer.lebLength(newSize), middle);
    long p = front + Writer.putLeb(b, front, newSize) + middle;
    p += Writer.putLeb(b, p, newPayload);
    b.put(p++, pad);
    for (int k = 0; k < pad; k++) b.put(p + k, 0); // p + pad == old + bo: the graph, unmoved
  }

  // ── Writing ─────────────────────────────────────────────────────────────────

  /** {@code len} bytes of {@code a} from {@code off}, as a segment — a record written in place, for an observer. */
  public static MemorySegment view(byte[] a, int off, int len) {
    return MemorySegment.ofArray(a).asSlice(off, len);
  }

  /** Hands what {@code b} holds to {@code dest} in one write — straight from a heap builder's array, no segment view. */
  public static Status write(Dest dest, Builder b) {
    final byte[] a = b.array();
    if (a != null) return dest.write(a, (int) (b.arrayBase() + b.position(b.cursor())), (int) b.cursor());
    return dest.write(b.bytes());
  }

  /** A doubly-linked record's span written forward at {@code o} of {@code a} — its LEB bytes last byte first, as {@link #frameRecord}; the position after it. */
  public static int fwdSpan(byte[] a, int o, long span) {
    final int n = Writer.lebLength(span);
    for (int i = n - 1; i >= 0; i--) {
      final int low = (int) (span & 0x7f);
      span >>>= 7;
      a[o + i] = (byte) (span != 0 ? low | 0x80 : low);
    }
    return o + n;
  }

  /** Frames the record just stored in {@code b} as a record of {@code typeId}: the type id in front and, doubly-linked, the span at the end (counting the type id and the body, never itself). */
  public static void frameRecord(Builder b, long typeId, boolean doublyLinked) {
    Writer.storeLeb(b, typeId);
    if (!doublyLinked) return;
    long span = b.cursor();
    final int n = Writer.lebLength(span);
    final byte[] tail = new byte[n];
    for (int i = 0; i < n; i++) { // the LEB bytes, last byte first
      final int low = (int) (span & 0x7f);
      span >>>= 7;
      tail[n - 1 - i] = (byte) (span != 0 ? low | 0x80 : low);
    }
    b.appendTail(tail);
  }
}
