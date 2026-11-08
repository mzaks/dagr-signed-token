package dagr.runtime;

import java.util.Arrays;
import java.util.HashMap;

/**
 * The write side of the generated ARENAS (spec/45 §5.5, milestone 8): what a whole graph needs beyond
 * the packed stores of {@link Writer} — regular (vtable) and frozen (positional) nodes, the regular
 * arrays and union slots they point at, the three dedup caches, late binding for cycles. A port of the
 * C target's {@code dagr/graph_writer.h}, itself a port of the Python reference writer
 * ({@code dagr/runtime/dagr_writer.py}), which is byte-identical to the Swift and Rust writers.
 *
 * <p>Offsets: a stored thing is named by the builder's cursor right after it was stored — the bytes
 * from its first byte to the end of the record. Offsets survive a growing builder's reallocation; a
 * pointer is the difference of two of them.
 *
 * <p>Node references are {@code long}s: an offset (&ge; 0), {@link #NIL} (no node), or — for a node
 * still being stored, an ancestor a cycle leads back to — PENDING ({@code -2 - entry}): a pointer to it
 * is written as a placeholder and patched by {@link #finish}.
 *
 * <p>Failure is sticky, as everywhere: a builder that failed stores nothing more; a vtable entry or a
 * reference the wire cannot hold fails it with {@code INVALID_VALUE}. Reusable: {@link #reset}.
 */
public final class GraphWriter {
  /** No node: a nil element of a node array with optionals. */
  public static final long NIL = -1;
  /** What {@link #begin} returns for a node to store now. */
  public static final long NEW = Long.MIN_VALUE;
  /** Union slot kinds: an inline value, a forward pointer to content, a bidirectional pointer to a node. */
  public static final int VALUE = 0, FORWARD = 1, NODE = 2;
  /** The default largest buffer every writer assumes: it fixes a cycle placeholder's width (4 bytes). */
  public static final long DEFAULT_MAX_SIZE = 2L * 1024 * 1024;

  private record NodeKey(int type, long handle) {}

  private record VtKey(boolean wide, long[] norm) {
    @Override
    public boolean equals(Object o) {
      return o instanceof VtKey k && k.wide == wide && Arrays.equals(k.norm, norm);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(norm) * 31 + (wide ? 1 : 0);
    }
  }

  private Builder b;
  private final int reserve;
  private final HashMap<NodeKey, Integer> nodeIndex = new HashMap<>();
  private long[] nodeOff = new long[16];
  private boolean[] nodeDone = new boolean[16];
  private int[] nodeBinds = new int[16];
  private int nNodes;
  private int lastEntry;
  private final HashMap<VtKey, Long> vtables = new HashMap<>();
  private final HashMap<String, Long> strings = new HashMap<>();
  // the late bindings: a linked list per pending node
  private int[] bindNext = new int[8];
  private long[] bindAt = new long[8];
  private long[] bindBase = new long[8];
  private long[] bindArrayEnd = new long[8];
  private int[] bindEs = new int[8];
  private int nBinds;

  /** A writer over {@code b} for buffers up to {@code maxSize} bytes (the cycle placeholder width). */
  public GraphWriter(Builder b, long maxSize) {
    this.b = b;
    this.reserve = reserveWidth(maxSize);
  }

  public GraphWriter(Builder b) {
    this(b, DEFAULT_MAX_SIZE);
  }

  /** bits = bitlen(max_size) + 3; the width is the power of two of bytes that holds them, at least 2 — the Swift / Rust rule. */
  public static int reserveWidth(long maxSize) {
    final int bitlen = 64 - Long.numberOfLeadingZeros(maxSize);
    final int bytes = (bitlen + 3 + 7) / 8;
    int w = 1;
    while (w < bytes) w <<= 1;
    return Math.max(w, 2);
  }

  public Builder builder() {
    return b;
  }

  /** Another builder for the next graph (a raw-embedded one is written into its own). */
  public void use(Builder builder) {
    this.b = builder;
  }

  /** Forgets every cached node, vtable and string — for the next graph. */
  public void reset() {
    nodeIndex.clear();
    vtables.clear();
    strings.clear();
    nNodes = 0;
    nBinds = 0;
  }

  public boolean ok() {
    return b.ok();
  }

  public void invalid() {
    b.fail(Status.INVALID_VALUE);
  }

  public long cursor() {
    return b.cursor();
  }

  // ── Node dedup and late binding ─────────────────────────────────────────────

  private int addNode(NodeKey key, long off, boolean done) {
    if (nNodes == nodeOff.length) {
      nodeOff = Arrays.copyOf(nodeOff, nNodes * 2);
      nodeDone = Arrays.copyOf(nodeDone, nNodes * 2);
      nodeBinds = Arrays.copyOf(nodeBinds, nNodes * 2);
    }
    final int e = nNodes++;
    nodeOff[e] = off;
    nodeDone[e] = done;
    nodeBinds[e] = -1;
    nodeIndex.put(key, e);
    return e;
  }

  /**
   * Starts storing the regular or frozen node {@code handle} of node type {@code type}: its reference
   * when it is stored (an offset) or in flight (PENDING: a cycle) — or {@link #NEW}, and then
   * {@link #lastEntry} names it for {@link #finish}.
   */
  public long begin(int type, long handle) {
    final Integer e = nodeIndex.get(new NodeKey(type, handle));
    if (e != null) return nodeDone[e] ? nodeOff[e] : -2 - e;
    lastEntry = addNode(new NodeKey(type, handle), 0, false);
    return NEW;
  }

  /** The entry the last {@link #begin} that returned {@link #NEW} registered. */
  public int lastEntry() {
    return lastEntry;
  }

  /** The node {@code entry} is stored at {@code off}: every placeholder written against it is patched. */
  public long finish(int entry, long off) {
    nodeOff[entry] = off;
    nodeDone[entry] = true;
    for (int i = nodeBinds[entry]; i != -1; i = bindNext[i]) {
      if (!b.ok()) break;   // the builder failed: nothing left to patch
      final long p = b.position(bindAt[i]);
      if (bindArrayEnd[i] >= 0) {
        // a node array's slot: the raw two's-complement distance, + 1
        Writer.putLe(b, p, bindArrayEnd[i] - off + 1, bindEs[i]);
      } else {
        // a field pointer: a ZigZag V62 at the reserved width
        final long d = bindBase[i] - off;
        final long wc = bindEs[i] == 2 ? 1 : bindEs[i] == 4 ? 2 : 3;
        Writer.putLe(b, p, (Reader.zigzagEncode(d) << 2) | wc, bindEs[i]);
      }
    }
    nodeBinds[entry] = -1;
    return off;
  }

  /** Where the packed node {@code handle} is stored, or -1 (a packed node is a tree: nothing in flight). */
  public long cached(int type, long handle) {
    final Integer e = nodeIndex.get(new NodeKey(type, handle));
    return e != null && nodeDone[e] ? nodeOff[e] : -1;
  }

  /**
   * Registers a packed node stored at {@code off} — only a node DECLARED packed: a regular or frozen node
   * a packed parent inlines is a private copy (spec 07 §5.1). A node inlined again replaces the earlier
   * copy: a later pointer reaches the most recent one, as in every other writer.
   */
  public void cache(int type, long handle, long off) {
    final NodeKey key = new NodeKey(type, handle);
    final Integer e = nodeIndex.get(key);
    if (e != null) {
      nodeOff[e] = off;
      return;
    }
    addNode(key, off, true);
  }

  private void bind(int entry, long at, long base, long arrayEnd, int es) {
    if (!b.ok()) return;
    if (nBinds == bindNext.length) {
      bindNext = Arrays.copyOf(bindNext, nBinds * 2);
      bindAt = Arrays.copyOf(bindAt, nBinds * 2);
      bindBase = Arrays.copyOf(bindBase, nBinds * 2);
      bindArrayEnd = Arrays.copyOf(bindArrayEnd, nBinds * 2);
      bindEs = Arrays.copyOf(bindEs, nBinds * 2);
    }
    bindNext[nBinds] = nodeBinds[entry];
    bindAt[nBinds] = at;
    bindBase[nBinds] = base;
    bindArrayEnd[nBinds] = arrayEnd;
    bindEs[nBinds] = es;
    nodeBinds[entry] = nBinds++;
  }

  // ── Pointers ────────────────────────────────────────────────────────────────

  /** A V62 of {@code value}, at least {@code minCode} wide (0 → 1 byte … 3 → 8 bytes). */
  public void storeV62(long value, int minCode) {
    if (Long.compareUnsigned(value, 1L << 6) < 0 && minCode == 0) {
      Writer.storeU8(b, (int) (value << 2));
    } else if (Long.compareUnsigned(value, 1L << 14) < 0 && minCode <= 1) {
      Writer.storeFixed(b, (value << 2) | Math.max(minCode, 1), 2);
    } else if (Long.compareUnsigned(value, 1L << 30) < 0 && minCode <= 2) {
      Writer.storeFixed(b, (value << 2) | Math.max(minCode, 2), 4);
    } else if (Long.compareUnsigned(value, 1L << 62) < 0) {
      Writer.storeFixed(b, (value << 2) | 3, 8);
    } else {
      b.fail(Status.INVALID_VALUE);
    }
  }

  /** A forward pointer to the content stored at {@code off}. */
  public void storeForwardPointer(long off) {
    storeV62(b.cursor() - off, 0);
  }

  /** A bidirectional pointer to a node: ZigZag V62 of the distance, or — to a node in flight — a placeholder of the reserved width. */
  public void storeBidirectionalPointer(long ref) {
    final long base = b.cursor();
    if (ref >= 0) {
      storeV62(Reader.zigzagEncode(base - ref), 0);
      return;
    }
    Writer.storeZeros(b, reserve);
    if (ref <= -2) bind((int) (-2 - ref), b.cursor(), base, -1, reserve);
  }

  // ── utf8 / data content ─────────────────────────────────────────────────────

  /** {@code [LEB count][bytes]}, the same string stored once (spec 07 §5): its offset. */
  public long utf8(String s) {
    final String key = s == null ? "" : s;
    final Long known = strings.get(key);
    if (known != null) return known;
    Writer.storeText(b, key);
    final long off = b.cursor();
    if (b.ok()) strings.put(key, off);
    return off;
  }

  /** {@code [LEB count][bytes]} — data is never deduplicated. */
  public long data(byte[] d) {
    Writer.storeBlob(b, ArenaArrays.bytes(d));
    return b.cursor();
  }

  // ── The vtable (regular nodes, spec 05) ─────────────────────────────────────

  /**
   * Stores the vtable of a node whose field slots were stored at {@code offsets} (forward index order;
   * 0 = absent), deduplicated, and returns the node's offset. A slot more than 65535 bytes before the
   * header cannot be written: {@code INVALID_VALUE}.
   */
  public long storeVtable(long[] offsets) {
    final int n = offsets.length;
    final long cur = b.cursor();
    final long[] norm = new long[n];
    boolean wide = false;
    for (int k = 0; k < n; k++) {
      final long v = offsets[k] == 0 ? 0 : cur - offsets[k] + 1;
      if (v > 0xffff) {
        b.fail(Status.INVALID_VALUE);
        return b.cursor();
      }
      wide = wide || v > 0xff;
      norm[k] = v;
    }
    final VtKey key = new VtKey(wide, norm);
    final Long known = vtables.get(key);
    if (known != null) {
      // a vtable already stored: an EVEN marker, the distance to it doubled
      Writer.storeLeb(b, (b.cursor() - known) << 1);
      return b.cursor();
    }
    final long cnt = wide ? ((long) n << 1) | 1 : (long) n << 1;
    final long size = (!wide && cnt == 0) ? 0 : Writer.lebLength(cnt) + (long) n * (wide ? 2 : 1);
    Writer.storeLeb(b, size == 0 ? 0 : ((size - 1) << 1) | 1);
    final long result = b.cursor();
    final int es = wide ? 2 : 1;
    if (n != 0) {
      final long p = b.claim((long) n * es);
      if (p >= 0) {
        for (int k = 0; k < n; k++) Writer.putLe(b, p + (long) k * es, norm[k], es);
      }
    }
    Writer.storeLeb(b, cnt);
    if (b.ok()) vtables.put(key, b.cursor());
    return result;
  }

  // ── Arrays of node references and pointer tables (spec 04 §4.7) ─────────────

  public static int unsignedWidthCode(long v) {
    return Long.compareUnsigned(v, 0xff) <= 0 ? 0 : Long.compareUnsigned(v, 0xffff) <= 0 ? 1
        : Long.compareUnsigned(v, 0xffffffffL) <= 0 ? 2 : 3;
  }

  public static int signedWidthCode(long d) {
    return (d >= -128 && d <= 127) ? 0 : (d >= -32768 && d <= 32767) ? 1
        : (d >= Integer.MIN_VALUE && d <= Integer.MAX_VALUE) ? 2 : 3;
  }

  /** {@code [LEB (count << 2) | wc][count × es signed slots]} over the element references (a pending one is patched by {@link #finish}; {@link #NIL} is slot 0). Its offset. */
  public long storeNodeRefArray(long[] refs) {
    final int n = refs.length;
    final long cur = b.cursor();
    int wc = 0;
    boolean pending = false;
    for (long r : refs) {
      if (r == NIL) continue;
      if (r >= 0) {
        wc = Math.max(wc, signedWidthCode(cur - r + 1));
      } else {
        pending = true;
      }
    }
    final int reserveWc = reserve == 2 ? 1 : reserve == 4 ? 2 : 3;
    if (pending && wc < reserveWc) wc = reserveWc;
    final int es = 1 << wc;
    if (n != 0) {
      final long p = b.claim((long) n * es);
      if (p >= 0) {
        final long first = b.cursor();
        for (int i = 0; i < n; i++) {
          final long r = refs[i];
          Writer.putLe(b, p + (long) i * es, r >= 0 ? cur - r + 1 : 0, es);
          if (r <= -2) bind((int) (-2 - r), first - (long) i * es, 0, cur, es);
        }
      }
    }
    Writer.storeLeb(b, ((long) n << 2) | wc);
    return b.cursor();
  }

  /** A pointer table {@code [LEB (count << 2) | wc][count × es unsigned slots]} over utf8 / data element offsets (0 = nil). Its offset. */
  public long storePtrTable(long[] offs) {
    final int n = offs.length;
    final long cur = b.cursor();
    int wc = 0;
    for (long off : offs) {
      if (off != 0) wc = Math.max(wc, unsignedWidthCode(cur - off + 1));
    }
    final int es = 1 << wc;
    if (n != 0) {
      final long p = b.claim((long) n * es);
      if (p >= 0) {
        for (int i = 0; i < n; i++) Writer.putLe(b, p + (long) i * es, offs[i] == 0 ? 0 : cur - offs[i] + 1, es);
      }
    }
    Writer.storeLeb(b, ((long) n << 2) | wc);
    return b.cursor();
  }

  // ── Unions in regular / frozen nodes (spec 04 §4.9) ─────────────────────────

  /** What a union FIELD's first pass stored, for its slot to point at or hold. */
  public static final class Applied {
    public long id;
    public int kind = VALUE;
    public int width = 1;
    public long bits;
    public long ref;
  }

  private void emit(Applied a) {
    switch (a.kind) {
      case VALUE -> {
        final long p = b.claim(a.width);
        if (p >= 0) Writer.putLe(b, p, a.bits, a.width);
      }
      case FORWARD -> storeForwardPointer(a.ref);
      default -> storeBidirectionalPointer(a.ref);
    }
  }

  /** The slot of a union FIELD: the value or pointer, then {@code LEB (id << 2) | wc}. Its offset. */
  public long storeUnionSlot(Applied a) {
    final long before = b.cursor();
    emit(a);
    final long n = b.cursor() - before;
    final long wc = n == 1 ? 0 : n == 2 ? 1 : n == 4 ? 2 : 3;
    Writer.storeLeb(b, (a.id << 2) | wc);
    return b.cursor();
  }

  /** A NESTED union value (a union variant of a union): {@code LEB id << 2}, no width code. */
  public long storeNestedUnionSlot(Applied a) {
    emit(a);
    Writer.storeLeb(b, a.id << 2);
    return b.cursor();
  }

  private static long slotOf(int kind, long val, long contentEnd) {
    return switch (kind) {
      case VALUE -> val;
      case FORWARD -> contentEnd - val;
      default -> (contentEnd - val) << 1;
    };
  }

  /**
   * A union ARRAY {@code [LEB (count << 2) | wc][type ids][nil bitset?][count slots]} over the elements
   * (their content already stored): ids, kinds, values (a bit pattern, or the offset of content / a node)
   * and presence. {@code bitsPer}: a type id's width (1, 2, 4, or 8: a byte each). Its offset.
   */
  public long storeUnionArray(long[] ids, int[] kinds, long[] vals, boolean[] present, int bitsPer, boolean opt) {
    final int n = ids.length;
    final long contentEnd = b.cursor();
    int wc = 0;
    for (int i = 0; i < n; i++) {
      if (present[i]) wc = Math.max(wc, unsignedWidthCode(slotOf(kinds[i], vals[i], contentEnd)));
    }
    final int es = 1 << wc;
    final int nb = opt ? (n + 7) / 8 : 0;
    final int tb = bitsPer < 8 ? (n * bitsPer + 7) / 8 : n;
    final long total = (long) n * es + nb + tb;
    if (total != 0) {
      final long p = b.claim(total);
      if (p >= 0) {
        for (long k = 0; k < total; k++) b.put(p + k, 0);
        final long types = p, nils = p + tb, slots = nils + nb;
        final int per = bitsPer < 8 ? 8 / bitsPer : 1;
        final long mask = bitsPer < 8 ? (1L << bitsPer) - 1 : 0xff;
        for (int i = 0; i < n; i++) {
          if (!present[i]) {
            if (opt) Writer.setBit(b, nils, i);
            continue;
          }
          Writer.putLe(b, slots + (long) i * es, slotOf(kinds[i], vals[i], contentEnd), es);
          if (bitsPer < 8) {
            final long at = types + i / per;
            b.put(at, b.get(at) | (int) ((ids[i] & mask) << ((i % per) * bitsPer)));
          } else {
            b.put(types + i, (int) ids[i]);
          }
        }
      }
    }
    Writer.storeLeb(b, ((long) n << 2) | wc);
    return b.cursor();
  }

  /** The headers of a packed union array, its payloads already stored: {@code [headers][nil bitset, LEB header size]?[LEB count]}, then the block length counted from {@code before}. */
  public void storePackedUnionHeaders(long[] headers, boolean[] present, boolean opt, long before) {
    final int n = headers.length;
    final long at = b.cursor();
    for (int i = n - 1; i >= 0; i--) {
      if (present[i]) Writer.storeLeb(b, headers[i]);
    }
    if (opt) {
      Writer.storeLeb(b, b.cursor() - at);
      final int nb = (n + 7) / 8;
      if (nb != 0) {
        final long p = b.claim(nb);
        if (p >= 0) {
          for (int k = 0; k < nb; k++) b.put(p + k, 0);
          for (int i = 0; i < n; i++) {
            if (!present[i]) Writer.setBit(b, p, i);
          }
        }
      }
    }
    Writer.storeLeb(b, n);
    Writer.storeLeb(b, b.cursor() - before);
  }

  // ── Regular / frozen arrays of values (spec 04) ─────────────────────────────
  // `[LEB count][elements]`, or with optionals `[LEB count][nil bitset][count slots]` (an absent element
  // is `width` zero bytes: not compacted). `bits(i)` is what the wire holds for element i.

  private interface Bits {
    long at(int i);
  }

  private long fixed(int n, Bits bits, boolean[] present, boolean opt, int width) {
    final int nb = opt ? (n + 7) / 8 : 0;
    if (n != 0) {
      final long p = b.claim(nb + (long) n * width);
      if (p >= 0) {
        for (int k = 0; k < nb; k++) b.put(p + k, 0);
        for (int i = 0; i < n; i++) {
          if (opt && present != null && !present[i]) {
            Writer.setBit(b, p, i);
            Writer.putLe(b, p + nb + (long) i * width, 0, width);
            continue;
          }
          Writer.putLe(b, p + nb + (long) i * width, bits.at(i), width);
        }
      }
    }
    Writer.storeLeb(b, n);
    return b.cursor();
  }

  public long storeFixedArray(int[] v, boolean[] present, boolean opt, int width) {
    final int[] a = v == null ? new int[0] : v;
    return fixed(a.length, i -> a[i], present, opt, width);
  }

  public long storeFixedArray(long[] v, boolean[] present, boolean opt, int width) {
    final long[] a = v == null ? new long[0] : v;
    return fixed(a.length, i -> a[i], present, opt, width);
  }

  public long storeFixedArray(short[] v, boolean[] present, boolean opt) {
    final short[] a = v == null ? new short[0] : v;
    return fixed(a.length, i -> a[i], present, opt, 2);
  }

  public long storeFixedArray(byte[] v, boolean[] present, boolean opt) {
    final byte[] a = v == null ? new byte[0] : v;
    return fixed(a.length, i -> a[i], present, opt, 1);
  }

  /** {@code half}: 0 f32, 1 f16, 2 bf16. */
  public long storeFixedArray(float[] v, boolean[] present, boolean opt, int half) {
    final float[] a = v == null ? new float[0] : v;
    if (half == 0) return fixed(a.length, i -> Float.floatToRawIntBits(a[i]) & 0xffffffffL, present, opt, 4);
    return fixed(a.length, i -> Writer.halfBits(a[i], half == 2), present, opt, 2);
  }

  public long storeFixedArray(double[] v, boolean[] present, boolean opt) {
    final double[] a = v == null ? new double[0] : v;
    return fixed(a.length, i -> Double.doubleToRawLongBits(a[i]), present, opt, 8);
  }

  /** {@code [LEB count][bitset]}, or with optionals {@code [LEB count][nil bitset][value bitset]}. */
  public long storeBoolArray(boolean[] v, boolean[] present, boolean opt) {
    final int n = v == null ? 0 : v.length;
    final int nb = (n + 7) / 8;
    final int total = opt ? 2 * nb : nb;
    if (total != 0) {
      final long p = b.claim(total);
      if (p >= 0) {
        for (int k = 0; k < total; k++) b.put(p + k, 0);
        for (int i = 0; i < n; i++) {
          if (opt && present != null && !present[i]) {
            Writer.setBit(b, p, i);
          } else if (v[i]) {
            Writer.setBit(b, opt ? p + nb : p, i);
          }
        }
      }
    }
    Writer.storeLeb(b, n);
    return b.cursor();
  }

  private long bitEnum(int n, Bits codes, boolean[] present, boolean opt, int bits) {
    final int nb = opt ? (n + 7) / 8 : 0;
    final int vb = (n * bits + 7) / 8;
    if (nb + vb != 0) {
      final long p = b.claim(nb + vb);
      if (p >= 0) {
        for (int k = 0; k < nb + vb; k++) b.put(p + k, 0);
        for (int i = 0; i < n; i++) {
          if (opt && present != null && !present[i]) {
            Writer.setBit(b, p, i);
            continue;
          }
          final long bit = (long) i * bits;
          final long v = codes.at(i) & ((1L << bits) - 1);
          final long at = p + nb + (bit >>> 3);
          b.put(at, b.get(at) | (int) (v << (bit & 7)));
        }
      }
    }
    Writer.storeLeb(b, n);
    return b.cursor();
  }

  /** A sub-byte enum array {@code [LEB count][nil bitset?][packed bits]}. */
  public long storeBitEnumArray(int[] v, boolean[] present, boolean opt, int bits) {
    final int[] a = v == null ? new int[0] : v;
    return bitEnum(a.length, i -> a[i], present, opt, bits);
  }

  public long storeBitEnumArray(long[] v, boolean[] present, boolean opt, int bits) {
    final long[] a = v == null ? new long[0] : v;
    return bitEnum(a.length, i -> a[i], present, opt, bits);
  }

  // ── aligned(N) arrays and blobs (spec 12 §11) ───────────────────────────────

  /** Zero bytes before (in store order: after) a payload of {@code payload} bytes, so that its first byte lands on a multiple of {@code n} counted from the record's end. */
  public void storeAlignedPad(long payload, long n) {
    Writer.storeZeros(b, (-(b.cursor() + payload)) & (n - 1));
  }

  /** An aligned utf8 / data payload — never deduplicated, its position matters. */
  public long storeAlignedText(String s, long align) {
    return storeAlignedBytes(s == null ? new byte[0] : s.getBytes(java.nio.charset.StandardCharsets.UTF_8), align);
  }

  public long storeAlignedBytes(byte[] src, long align) {
    final byte[] a = src == null ? new byte[0] : src;
    storeAlignedPad(a.length, align);
    Writer.storeBytes(b, a);
    Writer.storeLeb(b, a.length);
    return b.cursor();
  }
}
