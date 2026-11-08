package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * The Java target's write runtime (spec/45 §5.2) — a port of the C target's dagr/writer.h: what a
 * generated store calls. Every store claims its room from the {@link Builder} (back to front) and
 * is a no-op once the builder has failed. Generated code never touches the builder's memory.
 *
 * <p>Packed scalars (spec 07 §3, §12): a packed node's field is {@code [LEB (index << 1) | raw][payload]};
 * {@code raw} says the payload is in its fixed-width form, otherwise the compact one (a varint, or
 * the self-describing float codec). The writer picks per value — the compact form only when strictly
 * smaller — unless the schema marks the field {@code raw} (spec 39).
 */
public final class Writer {
  private Writer() {}

  // ── Encoding arithmetic ─────────────────────────────────────────────────────

  /** LEB128 byte length of unsigned {@code v} (0 → 1). */
  public static int lebLength(long v) {
    return (63 - Long.numberOfLeadingZeros(v | 1)) / 7 + 1;   // 7 bits a byte; unsigned, so 2^63.. is 10
  }

  private static final VarHandle LE16 = MethodHandles.byteArrayViewVarHandle(short[].class, ByteOrder.LITTLE_ENDIAN);
  private static final VarHandle LE32 = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);
  private static final VarHandle LE64 = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

  static int putLeb(Builder b, long p, long v) {
    final byte[] a = b.array();
    if (a != null) {   // a heap builder: straight into its array
      int o = (int) (b.arrayBase() + p);
      final int start = o;
      while ((v & ~0x7fL) != 0) {
        a[o++] = (byte) (v | 0x80);
        v >>>= 7;
      }
      a[o++] = (byte) v;
      return o - start;
    }
    int n = 0;
    while (Long.compareUnsigned(v, 0x80) >= 0) {
      b.put(p + n++, (int) ((v & 0x7f) | 0x80));
      v >>>= 7;
    }
    b.put(p + n++, (int) v);
    return n;
  }

  static void putLe(Builder b, long p, long v, int width) {
    final byte[] a = b.array();
    if (a != null) {
      final int o = (int) (b.arrayBase() + p);
      switch (width) {
        case 8 -> LE64.set(a, o, v);
        case 4 -> LE32.set(a, o, (int) v);
        case 2 -> LE16.set(a, o, (short) v);
        case 1 -> a[o] = (byte) v;
        default -> {
          for (int k = 0; k < width; k++) a[o + k] = (byte) (v >>> (8 * k));
        }
      }
      return;
    }
    for (int k = 0; k < width; k++) b.put(p + k, (int) (v >>> (8 * k)));
  }

  static void setBit(Builder b, long base, long i) {
    final long at = base + (i >>> 3);
    b.put(at, b.get(at) | (1 << (i & 7)));
  }

  /** Sets bit {@code i} of a bitset the caller assembles (a frozen node's presence / encoding bits). */
  public static void setBit(byte[] bits, int i) {
    bits[i >> 3] = (byte) (bits[i >> 3] | (1 << (i & 7)));
  }

  /** What the varint form of a packed integer encodes: the value, or its ZigZag when signed. */
  public static long lebForm(long bits, int width, boolean signed) {
    return signed ? Reader.zigzagEncode(Reader.signExtend(bits, width)) : bits;
  }

  public static boolean isPresent(boolean[] present, int i) {
    return present == null || present[i];
  }

  // ── Fixed-width scalars, bytes, varints ─────────────────────────────────────

  public static void storeU8(Builder b, int v) {
    final long p = b.claim(1);
    if (p >= 0) b.put(p, v);
  }

  /** The low {@code width} bytes of {@code v}, little-endian. */
  public static void storeFixed(Builder b, long v, int width) {
    final long p = b.claim(width);
    if (p >= 0) putLe(b, p, v, width);
  }

  public static void storeBytes(Builder b, byte[] src) {
    if (src.length == 0) return;
    final long p = b.claim(src.length);
    if (p >= 0) b.putBytes(p, src, 0, src.length);
  }

  /** Raw bytes, in order — a record's encoded content ({@code appendRaw}). */
  public static void storeBytes(Builder b, MemorySegment src) {
    final long n = src == null ? 0 : src.byteSize();
    if (n == 0) return;
    final long p = b.claim(n);
    if (p >= 0) b.putSegment(p, src, n);
  }

  public static void storeZeros(Builder b, long n) {
    if (n == 0) return;
    final long p = b.claim(n);
    if (p >= 0) b.segment().asSlice(p, n).fill((byte) 0);
  }

  /** Unsigned LEB128. */
  public static void storeLeb(Builder b, long v) {
    final long p = b.claim(lebLength(v));
    if (p >= 0) putLeb(b, p, v);
  }

  /** {@code [LEB length][bytes]} in one claim — data payloads. */
  public static void storeBlob(Builder b, MemorySegment src) {
    final long n = src == null ? 0 : src.byteSize();
    final int ln = lebLength(n);
    final long p = b.claim(ln + n);
    if (p < 0) return;
    putLeb(b, p, n);
    if (n != 0) b.putSegment(p + ln, src, n);
  }

  /** {@code [LEB length][UTF-8 bytes]} — utf8 payloads ({@code null} is the empty string). Encoded in place: nothing allocated. */
  public static void storeText(Builder b, String s) {
    final long m = s == null ? 0 : utf8Measure(b, s);
    final long n = m & ~NON_ASCII;
    final int ln = lebLength(n);
    final long p = b.claim(ln + n);
    if (p < 0) return;
    putLeb(b, p, n);
    if (n != 0) putUtf8(b, p + ln, s, m);
  }

  /** The flag {@link #utf8Measure} sets beside the length when a char is not ASCII. */
  static final long NON_ASCII = 1L << 62;

  /**
   * The UTF-8 length of {@code s} without encoding it — protobuf-java's measure (a char loop) — or-ed
   * with {@link #NON_ASCII} when any char is not ASCII. An unpaired surrogate counts one byte:
   * {@code String.getBytes(UTF_8)} encodes it as {@code '?'}, and the bytes must stay that encoding's —
   * which is why the flag, not the length, decides the ASCII copy.
   */
  static long utf8Measure(Builder b, String s) {
    final int n = s.length();
    if (n >= 32) {
      // a long string: copy its chars (an intrinsic) and OR them — one vectorizable pass decides ASCII;
      // a short one is cheaper through charAt (measured: the copy's fixed cost dominates below ~32 chars)
      final char[] cs = b.chars(n);
      s.getChars(0, n, cs, 0);
      int any = 0;
      for (int i = 0; i < n; i++) any |= cs[i];
      if (any < 0x80) return n;
      return measureChars(s, n);
    }
    // A short string goes through a per-builder cache keyed by IDENTITY (spec/45 §5.2.1): the same
    // String instance stored again — an attribute key, a constant value — skips the char loop. One
    // slot per identity hash, the newest entry wins, nothing allocated; a string is immutable, so a
    // hit is always its own measure.
    String[] seen = b.measured;
    if (seen == null) {
      seen = b.measured = new String[Builder.MEASURE_SLOTS];
      b.measures = new long[Builder.MEASURE_SLOTS];
    }
    final int slot = System.identityHashCode(s) & (Builder.MEASURE_SLOTS - 1);
    if (seen[slot] == s) return b.measures[slot];
    final long m = measureChars(s, n);
    seen[slot] = s;
    b.measures[slot] = m;
    return m;
  }

  /** utf8Measure's char loop: the UTF-8 length of {@code s}, or-ed with {@link #NON_ASCII}. */
  static long measureChars(String s, int n) {
    long len = n;
    long flag = 0;
    for (int i = 0; i < n; i++) {
      final char c = s.charAt(i);
      if (c < 0x80) continue;
      flag = NON_ASCII;
      if (c < 0x800) {
        len += 1;
      } else if (!Character.isSurrogate(c)) {
        len += 2;
      } else if (Character.isHighSurrogate(c) && i + 1 < n && Character.isLowSurrogate(s.charAt(i + 1))) {
        len += 2;   // two chars, four bytes
        i++;
      }
    }
    return len | flag;
  }

  /** {@code s} as UTF-8 at {@code p} ({@code measure}: {@link #utf8Measure}'s): straight into a heap builder's array. */
  @SuppressWarnings("deprecation")   // String.getBytes(int, int, byte[], int): the low byte of each char — exact for ASCII
  static void putUtf8(Builder b, long p, String s, long measure) {
    final int chars = s.length();
    final byte[] a = b.array();
    if (a == null) {
      final byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
      b.putBytes(p, bytes, 0, bytes.length);
      return;
    }
    int o = (int) (b.arrayBase() + p);
    if (measure == chars) {
      s.getBytes(0, chars, a, o);   // ASCII: one intrinsic copy
      return;
    }
    for (int i = 0; i < chars; i++) {
      final char c = s.charAt(i);
      if (c < 0x80) {
        a[o++] = (byte) c;
      } else if (c < 0x800) {
        a[o++] = (byte) (0xc0 | (c >>> 6));
        a[o++] = (byte) (0x80 | (c & 0x3f));
      } else if (!Character.isSurrogate(c)) {
        a[o++] = (byte) (0xe0 | (c >>> 12));
        a[o++] = (byte) (0x80 | ((c >>> 6) & 0x3f));
        a[o++] = (byte) (0x80 | (c & 0x3f));
      } else if (Character.isHighSurrogate(c) && i + 1 < chars && Character.isLowSurrogate(s.charAt(i + 1))) {
        final int cp = Character.toCodePoint(c, s.charAt(++i));
        a[o++] = (byte) (0xf0 | (cp >>> 18));
        a[o++] = (byte) (0x80 | ((cp >>> 12) & 0x3f));
        a[o++] = (byte) (0x80 | ((cp >>> 6) & 0x3f));
        a[o++] = (byte) (0x80 | (cp & 0x3f));
      } else {
        a[o++] = (byte) '?';   // an unpaired surrogate, as String.getBytes(UTF_8)
      }
    }
  }


  // ── Packed scalars (spec 07 §3, §12) ────────────────────────────────────────

  /** The payload of a u16..i64 field ({@code bits}: its two's complement in {@code width} bytes): a varint when shorter than the width, else the width. Whether it went raw. */
  public static boolean storePackedInt(Builder b, long bits, int width, boolean signed, boolean forceRaw) {
    final long lv = lebForm(bits, width, signed);
    if (!forceRaw && lebLength(lv) < width) {
      storeLeb(b, lv);
      return false;
    }
    storeFixed(b, bits, width);
    return true;
  }

  /** {@code [tag][payload]} of a u16..i64 field in ONE claim. */
  public static void storePackedIntField(Builder b, long bits, int width, boolean signed, long index, boolean forceRaw) {
    final long lv = lebForm(bits, width, signed);
    final int ll = lebLength(lv);
    if (!forceRaw && ll < width) {
      final long tag = index << 1;
      final int tl = lebLength(tag);
      final long p = b.claim(tl + ll);
      if (p >= 0) {
        putLeb(b, p, tag);
        putLeb(b, p + tl, lv);
      }
      return;
    }
    final long tag = (index << 1) | 1;
    final int tl = lebLength(tag);
    final long p = b.claim(tl + width);
    if (p >= 0) {
      putLeb(b, p, tag);
      putLe(b, p + tl, bits, width);
    }
  }

  /** {@code [tag | 1][byte]} — u8, i8, bool and byte-wide enums have one encoding. */
  public static void storePackedByteField(Builder b, int v, long index) {
    final long tag = (index << 1) | 1;
    final int tl = lebLength(tag);
    final long p = b.claim(tl + 1);
    if (p >= 0) {
      putLeb(b, p, tag);
      b.put(p + tl, v);
    }
  }

  /** {@code [tag | 1][LEB length][bytes]} in one claim — data fields. */
  public static void storePackedBlobField(Builder b, MemorySegment src, long index) {
    final long tag = (index << 1) | 1;
    final int tl = lebLength(tag);
    final long n = src == null ? 0 : src.byteSize();
    final int ln = lebLength(n);
    final long p = b.claim(tl + ln + n);
    if (p < 0) return;
    putLeb(b, p, tag);
    putLeb(b, p + tl, n);
    if (n != 0) b.putSegment(p + tl + ln, src, n);
  }

  /** {@code [tag | 1][LEB length][UTF-8]} — utf8 fields, encoded in place. */
  public static void storePackedTextField(Builder b, String s, long index) {
    final long tag = (index << 1) | 1;
    final int tl = lebLength(tag);
    final long m = s == null ? 0 : utf8Measure(b, s);
    final long n = m & ~NON_ASCII;
    final int ln = lebLength(n);
    final long p = b.claim(tl + ln + n);
    if (p < 0) return;
    putLeb(b, p, tag);
    putLeb(b, p + tl, n);
    if (n != 0) putUtf8(b, p + tl + ln, s, m);
  }

  /** The tag of a field whose payload was just stored. */
  public static void storePackedTag(Builder b, long index, boolean raw) {
    storeLeb(b, (index << 1) | (raw ? 1 : 0));
  }

  // ── The self-describing float codec ─────────────────────────────────────────

  /** The half bits of {@code v} when it is a NORMAL half (or ±0) exactly — what tag 06 stores — else -1. */
  static int exactHalf(float v) {
    final int bits = Float.floatToRawIntBits(v);
    final int sign = bits >>> 31;
    final int exp32 = (bits >>> 23) & 0xff;
    final int mant32 = bits & 0x7fffff;
    if (exp32 == 0xff) return -1;
    if (exp32 == 0) return mant32 != 0 ? -1 : sign << 15;
    final int exp16 = exp32 - 112;
    if (exp16 < 1 || exp16 > 30) return -1;
    if ((mant32 & 0x1fff) != 0) return -1;
    return (sign << 15) | (exp16 << 10) | (mant32 >>> 13);
  }

  /** The one-byte encoding of ±0, ±infinity or NaN of an f32's bits, or -1. */
  static int special32(int bits) {
    if (bits == 0) return 0x00;
    if (bits == 0x80000000) return 0x01;
    if ((bits & 0x7fffffff) > 0x7f800000) return 0x04;
    if (bits == 0x7f800000) return 0x02;
    if (bits == 0xff800000) return 0x03;
    return -1;
  }

  static int special64(long bits) {
    if (bits == 0) return 0x00;
    if (bits == 0x8000000000000000L) return 0x01;
    if ((bits & 0x7fffffffffffffffL) > 0x7ff0000000000000L) return 0x04;
    if (bits == 0x7ff0000000000000L) return 0x02;
    if (bits == 0xfff0000000000000L) return 0x03;
    return -1;
  }

  /** Whether f32 {@code v} takes the raw (fixed-width) form of the codec. */
  public static boolean f32IsRaw(float v) {
    if (special32(Float.floatToRawIntBits(v)) >= 0) return false;
    if (v > -2097152.0f && v < 2097152.0f) { // |v| < 2^21
      final long iv = (long) v;
      if ((float) iv == v && lebLength(Reader.zigzagEncode(iv)) <= 3) return false;
    }
    return exactHalf(v) < 0;
  }

  /**
   * spec 07 §12, f32: special → {@code [tag]}; a small integer → {@code [05][zigzag LEB ≤ 3]}; an
   * exact half → {@code [06][2]}; else the 4 raw bytes — behind tag 07 when {@code elem} (array
   * elements are always self-describing; a field says "raw" in its tag instead). Whether raw.
   */
  public static boolean storePackedF32(Builder b, float v, boolean elem) {
    final int bits = Float.floatToRawIntBits(v);
    final int special = special32(bits);
    if (special >= 0) {
      storeU8(b, special);
      return false;
    }
    if (v > -2097152.0f && v < 2097152.0f) {
      final long iv = (long) v;
      if ((float) iv == v && lebLength(Reader.zigzagEncode(iv)) <= 3) {
        storeFloatInt(b, iv);
        return false;
      }
    }
    final int h = exactHalf(v);
    if (h >= 0) {
      storeTagged(b, 0x06, h, 2);
      return false;
    }
    if (elem) storeTagged(b, 0x07, bits & 0xffffffffL, 4);
    else storeFixed(b, bits & 0xffffffffL, 4);
    return true;
  }

  /** Whether f64 {@code v} takes the raw (fixed-width) form of the codec. */
  public static boolean f64IsRaw(double v) {
    if (special64(Double.doubleToRawLongBits(v)) >= 0) return false;
    if (v > -281474976710656.0 && v < 281474976710656.0) { // |v| < 2^48
      final long iv = (long) v;
      if ((double) iv == v && lebLength(Reader.zigzagEncode(iv)) <= 7) return false;
    }
    return !(v >= -3.4028234663852886e38 && v <= 3.4028234663852886e38 && (double) (float) v == v);
  }

  /** spec 07 §12, f64: as f32 with a 7-byte integer, then an exact half (06), an exact float (07), else the 8 raw bytes (behind tag 08 when {@code elem}). Whether raw. */
  public static boolean storePackedF64(Builder b, double v, boolean elem) {
    final long bits = Double.doubleToRawLongBits(v);
    final int special = special64(bits);
    if (special >= 0) {
      storeU8(b, special);
      return false;
    }
    if (v > -281474976710656.0 && v < 281474976710656.0) {
      final long iv = (long) v;
      if ((double) iv == v && lebLength(Reader.zigzagEncode(iv)) <= 7) {
        storeFloatInt(b, iv);
        return false;
      }
    }
    if (v >= -3.4028234663852886e38 && v <= 3.4028234663852886e38) {
      final float f = (float) v;
      if ((double) f == v) {
        final int h = exactHalf(f);
        if (h >= 0) storeTagged(b, 0x06, h, 2);
        else storeTagged(b, 0x07, Float.floatToRawIntBits(f) & 0xffffffffL, 4);
        return false;
      }
    }
    if (elem) storeTagged(b, 0x08, bits, 8);
    else storeFixed(b, bits, 8);
    return true;
  }

  private static void storeFloatInt(Builder b, long iv) {
    final long z = Reader.zigzagEncode(iv);
    final int ll = lebLength(z);
    final long p = b.claim(1 + ll);
    if (p >= 0) {
      b.put(p, 0x05);
      putLeb(b, p + 1, z);
    }
  }

  private static void storeTagged(Builder b, int tag, long v, int width) {
    final long p = b.claim(1 + width);
    if (p >= 0) {
      b.put(p, tag);
      putLe(b, p + 1, v, width);
    }
  }

  /** The tag byte a packed f16 / bf16 stores INSTEAD of its two bytes, or -1. */
  public static int halfSpecial(float v) {
    return special32(Float.floatToRawIntBits(v));
  }

  /** {@code v} as f16 or bf16 bits (round to nearest even; a NaN f16 is 0x7e00, as every writer). */
  public static int halfBits(float v, boolean bf16) {
    if (!bf16) return Reader.floatToF16(v);
    final int bits = Float.floatToRawIntBits(v);
    return ((bits + 0x7fff + ((bits >>> 16) & 1)) >>> 16) & 0xffff;
  }

  /** A packed f16 / bf16 SCALAR: a special value as its one tag byte (false), else the two raw bytes (true). */
  public static boolean storePackedHalf(Builder b, float v, boolean bf16) {
    final int special = halfSpecial(v);
    if (special >= 0) {
      storeU8(b, special);
      return false;
    }
    storeFixed(b, halfBits(v, bf16), 2);
    return true;
  }

  // ── Forward field writes (a sink record of bounded scalars, spec/45 §5.2) ──────
  // A record whose fields are all bounded scalars is written FRONT TO BACK into room the caller
  // bounded once (Builder.room): no claim per field. Each returns the position after what it wrote.
  // The bytes are those of the backward stores above — the sink goldens gate both.

  public static int fwdLeb(byte[] a, int o, long v) {
    while ((v & ~0x7fL) != 0) {
      a[o++] = (byte) (v | 0x80);
      v >>>= 7;
    }
    a[o++] = (byte) v;
    return o;
  }

  private static int fwdLe(byte[] a, int o, long v, int width) {
    switch (width) {
      case 8 -> LE64.set(a, o, v);
      case 4 -> LE32.set(a, o, (int) v);
      case 2 -> LE16.set(a, o, (short) v);
      default -> {
        for (int k = 0; k < width; k++) a[o + k] = (byte) (v >>> (8 * k));
      }
    }
    return o + width;
  }

  /** {@code [tag][payload]} of a u16..i64 field — as {@link #storePackedIntField}. */
  public static int fwdPackedIntField(byte[] a, int o, long bits, int width, boolean signed, long index, boolean forceRaw) {
    final long lv = lebForm(bits, width, signed);
    if (!forceRaw && lebLength(lv) < width) return fwdLeb(a, fwdLeb(a, o, index << 1), lv);
    return fwdLe(a, fwdLeb(a, o, (index << 1) | 1), bits, width);
  }

  /** {@code [tag | 1][byte]} — as {@link #storePackedByteField}. */
  public static int fwdPackedByteField(byte[] a, int o, int v, long index) {
    o = fwdLeb(a, o, (index << 1) | 1);
    a[o] = (byte) v;
    return o + 1;
  }

  /** {@code [tag | 1][width bytes]} — a {@code raw} float field (spec 39). */
  public static int fwdFixedField(byte[] a, int o, long bits, int width, long index) {
    return fwdLe(a, fwdLeb(a, o, (index << 1) | 1), bits, width);
  }

  /** An f16 / bf16 field — as {@link #storePackedHalf} behind its tag. */
  public static int fwdPackedHalfField(byte[] a, int o, float v, boolean bf16, long index) {
    final int special = halfSpecial(v);
    if (special >= 0) {
      o = fwdLeb(a, o, index << 1);
      a[o] = (byte) special;
      return o + 1;
    }
    return fwdLe(a, fwdLeb(a, o, (index << 1) | 1), halfBits(v, bf16), 2);
  }

  /** An f32 field — as {@link #storePackedF32} behind its tag. */
  public static int fwdPackedF32Field(byte[] a, int o, float v, long index) {
    final int bits = Float.floatToRawIntBits(v);
    final int special = special32(bits);
    if (special >= 0) {
      o = fwdLeb(a, o, index << 1);
      a[o] = (byte) special;
      return o + 1;
    }
    if (v > -2097152.0f && v < 2097152.0f) {
      final long iv = (long) v;
      final long z = Reader.zigzagEncode(iv);
      if ((float) iv == v && lebLength(z) <= 3) {
        o = fwdLeb(a, o, index << 1);
        a[o] = 0x05;
        return fwdLeb(a, o + 1, z);
      }
    }
    final int h = exactHalf(v);
    if (h >= 0) {
      o = fwdLeb(a, o, index << 1);
      a[o] = 0x06;
      return fwdLe(a, o + 1, h, 2);
    }
    return fwdLe(a, fwdLeb(a, o, (index << 1) | 1), bits, 4);
  }

  /** An f64 field — as {@link #storePackedF64} behind its tag. */
  public static int fwdPackedF64Field(byte[] a, int o, double v, long index) {
    final long bits = Double.doubleToRawLongBits(v);
    final int special = special64(bits);
    if (special >= 0) {
      o = fwdLeb(a, o, index << 1);
      a[o] = (byte) special;
      return o + 1;
    }
    if (v > -281474976710656.0 && v < 281474976710656.0) {
      final long iv = (long) v;
      final long z = Reader.zigzagEncode(iv);
      if ((double) iv == v && lebLength(z) <= 7) {
        o = fwdLeb(a, o, index << 1);
        a[o] = 0x05;
        return fwdLeb(a, o + 1, z);
      }
    }
    if (v >= -3.4028234663852886e38 && v <= 3.4028234663852886e38) {
      final float f = (float) v;
      if ((double) f == v) {
        o = fwdLeb(a, o, index << 1);
        final int h = exactHalf(f);
        if (h >= 0) {
          a[o] = 0x06;
          return fwdLe(a, o + 1, h, 2);
        }
        a[o] = 0x07;
        return fwdLe(a, o + 1, Float.floatToRawIntBits(f) & 0xffffffffL, 4);
      }
    }
    return fwdLe(a, fwdLeb(a, o, (index << 1) | 1), bits, 8);
  }

  // ── Packed unions (spec 07 §8): [LEB (type id << 3) | code][payload] ────────
  // the code says how to SKIP the payload: 0 a varint, 1 / 2 / 3 / 4 a fixed 1 / 2 / 4 / 8 bytes,
  // 5 the float codec, 6 a length-prefixed blob.

  public static long widthCode(int width) {
    return width == 1 ? 1 : width == 2 ? 2 : width == 4 ? 3 : 4;
  }

  /** The code of a u16..i64 variant: 0 when its varint is shorter than its width. */
  public static long packedUnionIntCode(long bits, int width, boolean signed) {
    return lebLength(lebForm(bits, width, signed)) < width ? 0 : widthCode(width);
  }

  public static long storePackedUnionInt(Builder b, long bits, int width, boolean signed) {
    return storePackedInt(b, bits, width, signed, false) ? widthCode(width) : 0;
  }

  public static long packedUnionF32Code(float v) {
    return f32IsRaw(v) ? 3 : 5;
  }

  public static long storePackedUnionF32(Builder b, float v) {
    return storePackedF32(b, v, false) ? 3 : 5;
  }

  public static long packedUnionF64Code(double v) {
    return f64IsRaw(v) ? 4 : 5;
  }

  public static long storePackedUnionF64(Builder b, double v) {
    return storePackedF64(b, v, false) ? 4 : 5;
  }

  // ── Packed arrays (spec 04 §5, spec 07) ─────────────────────────────────────
  // [LEB block length][count word][bitsets][elements], the block length counting everything after
  // itself; an array with optionals stores a nil bitset (bit i set = element i absent) and only the
  // PRESENT elements. Where a bitset depends on the elements, they are measured first and the body
  // written forward into ONE exact claim — an over-claim would make a buffer that fits an
  // exact-size fixed builder fail.

  public static void pkFinishBlock(Builder b, long before, long countWord) {
    storeLeb(b, countWord);
    storeLeb(b, b.cursor() - before);
  }

  /** The nil bitset of an array with optionals. */
  public static void storeNilBits(Builder b, boolean[] present, int n) {
    final int nb = (n + 7) >> 3;
    if (nb == 0) return;
    final long p = b.claim(nb);
    if (p < 0) return;
    for (int k = 0; k < nb; k++) b.put(p + k, 0);
    for (int i = 0; i < n; i++) {
      if (!present[i]) setBit(b, p, i);
    }
  }

  /** The presence of a REFERENCE array with optionals (utf8, data, nodes, unions): a null element is nil. */
  public static boolean[] presenceOf(Object[] elems) {
    final boolean[] out = new boolean[elems == null ? 0 : elems.length];
    for (int i = 0; i < out.length; i++) out[i] = elems[i] != null;
    return out;
  }

  /**
   * {@code [u16..i64]} / {@code [u16?..i64?]} from a {@code short[]}: {@code [(count << 2) | tag][nil
   * bitset][encoding bitset if tag 2][elements]} — tag 0 every element a varint, 1 every element
   * fixed-width, 2 mixed (bit i set = element i fixed). {@code raw} (spec 39) skips the probe: tag 1.
   */
  public static void storePkIntArray(Builder b, short[] elems, boolean[] present, int width, boolean signed, boolean raw) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    long total = 0;
    int rawCount = 0, count = 0;
    for (int i = 0; i < n; i++) {
      if (!isPresent(present, i)) continue;
      count++;
      final int ll = lebLength(lebForm((long) elems[i], width, signed));
      if (!raw && ll < width) {
        total += ll;
      } else {
        total += width;
        rawCount++;
      }
    }
    final long tag = pkIntTag(raw, rawCount, count);
    final long nb = present != null ? (n + 7) >> 3 : 0;
    final long eb = tag == 2 ? (n + 7) >> 3 : 0;
    if (nb + eb + total != 0) {
      final long p = b.claim(nb + eb + total);
      if (p >= 0) {
        for (long k = 0; k < nb + eb; k++) b.put(p + k, 0);
        final long enc = p + nb;
        long out = enc + eb;
        for (int i = 0; i < n; i++) {
          if (!isPresent(present, i)) {
            setBit(b, p, i);
            continue;
          }
          final long bits = (long) elems[i];
          final long lv = lebForm(bits, width, signed);
          if (tag != 1 && lebLength(lv) < width) {
            out += putLeb(b, out, lv);
          } else {
            putLe(b, out, bits, width);
            out += width;
            if (eb != 0) setBit(b, enc, i);
          }
        }
      }
    }
    pkFinishBlock(b, before, ((long) n << 2) | tag);
  }

  /**
   * {@code [u16..i64]} / {@code [u16?..i64?]} from a {@code int[]}: {@code [(count << 2) | tag][nil
   * bitset][encoding bitset if tag 2][elements]} — tag 0 every element a varint, 1 every element
   * fixed-width, 2 mixed (bit i set = element i fixed). {@code raw} (spec 39) skips the probe: tag 1.
   */
  public static void storePkIntArray(Builder b, int[] elems, boolean[] present, int width, boolean signed, boolean raw) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    long total = 0;
    int rawCount = 0, count = 0;
    for (int i = 0; i < n; i++) {
      if (!isPresent(present, i)) continue;
      count++;
      final int ll = lebLength(lebForm((long) elems[i], width, signed));
      if (!raw && ll < width) {
        total += ll;
      } else {
        total += width;
        rawCount++;
      }
    }
    final long tag = pkIntTag(raw, rawCount, count);
    final long nb = present != null ? (n + 7) >> 3 : 0;
    final long eb = tag == 2 ? (n + 7) >> 3 : 0;
    if (nb + eb + total != 0) {
      final long p = b.claim(nb + eb + total);
      if (p >= 0) {
        for (long k = 0; k < nb + eb; k++) b.put(p + k, 0);
        final long enc = p + nb;
        long out = enc + eb;
        for (int i = 0; i < n; i++) {
          if (!isPresent(present, i)) {
            setBit(b, p, i);
            continue;
          }
          final long bits = (long) elems[i];
          final long lv = lebForm(bits, width, signed);
          if (tag != 1 && lebLength(lv) < width) {
            out += putLeb(b, out, lv);
          } else {
            putLe(b, out, bits, width);
            out += width;
            if (eb != 0) setBit(b, enc, i);
          }
        }
      }
    }
    pkFinishBlock(b, before, ((long) n << 2) | tag);
  }

  /**
   * {@code [u16..i64]} / {@code [u16?..i64?]} from a {@code long[]}: {@code [(count << 2) | tag][nil
   * bitset][encoding bitset if tag 2][elements]} — tag 0 every element a varint, 1 every element
   * fixed-width, 2 mixed (bit i set = element i fixed). {@code raw} (spec 39) skips the probe: tag 1.
   */
  public static void storePkIntArray(Builder b, long[] elems, boolean[] present, int width, boolean signed, boolean raw) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    long total = 0;
    int rawCount = 0, count = 0;
    for (int i = 0; i < n; i++) {
      if (!isPresent(present, i)) continue;
      count++;
      final int ll = lebLength(lebForm(elems[i], width, signed));
      if (!raw && ll < width) {
        total += ll;
      } else {
        total += width;
        rawCount++;
      }
    }
    final long tag = pkIntTag(raw, rawCount, count);
    final long nb = present != null ? (n + 7) >> 3 : 0;
    final long eb = tag == 2 ? (n + 7) >> 3 : 0;
    if (nb + eb + total != 0) {
      final long p = b.claim(nb + eb + total);
      if (p >= 0) {
        for (long k = 0; k < nb + eb; k++) b.put(p + k, 0);
        final long enc = p + nb;
        long out = enc + eb;
        for (int i = 0; i < n; i++) {
          if (!isPresent(present, i)) {
            setBit(b, p, i);
            continue;
          }
          final long bits = elems[i];
          final long lv = lebForm(bits, width, signed);
          if (tag != 1 && lebLength(lv) < width) {
            out += putLeb(b, out, lv);
          } else {
            putLe(b, out, bits, width);
            out += width;
            if (eb != 0) setBit(b, enc, i);
          }
        }
      }
    }
    pkFinishBlock(b, before, ((long) n << 2) | tag);
  }

  /** An integer array's tag: 1 every element raw (or {@code raw}), 2 mixed, 0 every element a varint. */
  static long pkIntTag(boolean raw, int rawCount, int count) {
    return raw ? 1 : (rawCount == count && count > 0) ? 1 : rawCount > 0 ? 2 : 0;
  }

  /** {@code [u8]} / {@code [i8]}: {@code [count][bytes]}; with optionals {@code [count][nil bitset][present bytes]}. */
  public static void storePkByteArray(Builder b, byte[] elems, boolean[] present) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    int count = 0;
    for (int i = 0; i < n; i++) count += isPresent(present, i) ? 1 : 0;
    if (count != 0) {
      final long p = b.claim(count);
      if (p >= 0) {
        long out = p;
        for (int i = 0; i < n; i++) {
          if (isPresent(present, i)) b.put(out++, elems[i]);
        }
      }
    }
    if (present != null) storeNilBits(b, present, n);
    pkFinishBlock(b, before, n);
  }

  /** {@code [u8]} from widened values. */
  public static void storePkByteArray(Builder b, int[] elems, boolean[] present) {
    final byte[] bytes = new byte[elems == null ? 0 : elems.length];
    for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) elems[i];
    storePkByteArray(b, bytes, present);
  }

  /** {@code [bool]}: {@code [count][bitset]}; {@code [bool?]}: {@code [count][nil bitset][the present values' bits]}. */
  public static void storePkBoolArray(Builder b, boolean[] elems, boolean[] present) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    int count = 0;
    for (int i = 0; i < n; i++) count += isPresent(present, i) ? 1 : 0;
    final int vb = (count + 7) >> 3;
    if (vb != 0) {
      final long p = b.claim(vb);
      if (p >= 0) {
        for (int k = 0; k < vb; k++) b.put(p + k, 0);
        int at = 0;
        for (int i = 0; i < n; i++) {
          if (!isPresent(present, i)) continue;
          if (elems[i]) setBit(b, p, at);
          at++;
        }
      }
    }
    if (present != null) storeNilBits(b, present, n);
    pkFinishBlock(b, before, n);
  }

  /** {@code [f16]} / {@code [bf16]}: {@code [count][encoding bitset][elements]}; with optionals {@code [count][nil bitset][two raw bytes per present element]}. */
  public static void storePkHalfArray(Builder b, float[] elems, boolean[] present, boolean bf16) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    if (present != null) {
      for (int i = n - 1; i >= 0; i--) {
        if (present[i]) storeFixed(b, halfBits(elems[i], bf16), 2);
      }
      storeNilBits(b, present, n);
      pkFinishBlock(b, before, n);
      return;
    }
    final int eb = (n + 7) >> 3;
    long total = 0;
    for (int i = 0; i < n; i++) total += halfSpecial(elems[i]) >= 0 ? 1 : 2;
    if (eb + total != 0) {
      final long p = b.claim(eb + total);
      if (p >= 0) {
        for (int k = 0; k < eb; k++) b.put(p + k, 0);
        long out = p + eb;
        for (int i = 0; i < n; i++) {
          final int special = halfSpecial(elems[i]);
          if (special >= 0) {
            b.put(out++, special);
          } else {
            putLe(b, out, halfBits(elems[i], bf16), 2);
            out += 2;
            setBit(b, p, i);
          }
        }
      }
    }
    pkFinishBlock(b, before, n);
  }

  /** {@code [f32]}: {@code [(count << 2) | mode][nil bitset?][elements]} — mode 0 each element self-describing, mode 1 ({@code raw}) native. */
  public static void storePkFloatArray(Builder b, float[] elems, boolean[] present, boolean raw) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    for (int i = n - 1; i >= 0; i--) {
      if (!isPresent(present, i)) continue;
      if (raw) storeFixed(b, Float.floatToRawIntBits(elems[i]) & 0xffffffffL, 4);
      else storePackedF32(b, elems[i], true);
    }
    if (present != null) storeNilBits(b, present, n);
    pkFinishBlock(b, before, ((long) n << 2) | (raw ? 1 : 0));
  }

  /** {@code [f64]}: as {@code [f32]}. */
  public static void storePkFloatArray(Builder b, double[] elems, boolean[] present, boolean raw) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    for (int i = n - 1; i >= 0; i--) {
      if (!isPresent(present, i)) continue;
      if (raw) storeFixed(b, Double.doubleToRawLongBits(elems[i]), 8);
      else storePackedF64(b, elems[i], true);
    }
    if (present != null) storeNilBits(b, present, n);
    pkFinishBlock(b, before, ((long) n << 2) | (raw ? 1 : 0));
  }

  /** A sub-byte enum array ({@code bits} 1, 2 or 4): {@code [count][nil bitset?][the present values' bits, low first]}. */
  public static void storePkBitEnumArray(Builder b, int[] elems, boolean[] present, int bits) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    int count = 0;
    for (int i = 0; i < n; i++) count += isPresent(present, i) ? 1 : 0;
    final long nb = ((long) count * bits + 7) / 8;
    if (nb != 0) {
      final long p = b.claim(nb);
      if (p >= 0) {
        for (long k = 0; k < nb; k++) b.put(p + k, 0);
        final int perByte = 8 / bits;
        final int mask = (1 << bits) - 1;
        int at = 0;
        for (int i = 0; i < n; i++) {
          if (!isPresent(present, i)) continue;
          final long q = p + at / perByte;
          b.put(q, b.get(q) | ((elems[i] & mask) << ((at % perByte) * bits)));
          at++;
        }
      }
    }
    if (present != null) storeNilBits(b, present, n);
    pkFinishBlock(b, before, n);
  }

  /** An enum array of a byte or more per element: {@code [count][nil bitset?][LEB per present element]}. */
  public static void storePkLebEnumArray(Builder b, int[] elems, boolean[] present) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    for (int i = n - 1; i >= 0; i--) {
      if (isPresent(present, i)) storeLeb(b, elems[i] & 0xffffffffL);
    }
    if (present != null) storeNilBits(b, present, n);
    pkFinishBlock(b, before, n);
  }

  /** A u32 / u64 bitset enum array: as {@link #storePkLebEnumArray}. */
  public static void storePkLebEnumArray(Builder b, long[] elems, boolean[] present) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    for (int i = n - 1; i >= 0; i--) {
      if (isPresent(present, i)) storeLeb(b, elems[i]);
    }
    if (present != null) storeNilBits(b, present, n);
    pkFinishBlock(b, before, n);
  }

  /** {@code [utf8]} / {@code [utf8?]}: {@code [count][nil bitset?][blob per present element]}; with optionals a null element is nil. */
  public static void storePkTextArray(Builder b, String[] elems, boolean optionals) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    for (int i = n - 1; i >= 0; i--) {
      if (!optionals || elems[i] != null) storeText(b, elems[i]);
    }
    if (optionals) storeNilBits(b, presenceOf(elems), n);
    pkFinishBlock(b, before, n);
  }

  /** {@code [data]} / {@code [data?]}. */
  public static void storePkDataArray(Builder b, MemorySegment[] elems, boolean optionals) {
    final int n = elems == null ? 0 : elems.length;
    final long before = b.cursor();
    for (int i = n - 1; i >= 0; i--) {
      if (!optionals || elems[i] != null) storeBlob(b, elems[i]);
    }
    if (optionals) storeNilBits(b, presenceOf(elems), n);
    pkFinishBlock(b, before, n);
  }

  // ── Graph framing (spec 06, spec 12 §4 / §14, spec 42) ──────────────────────

  /**
   * The zero bytes that make {@code alignment offset + finished length} a multiple of {@code maxN},
   * given the framing word that follows them. The search runs over [0, 2 · maxN) — over [0, maxN) it
   * can straddle a step of the framing length and hold no solution (spec 42 §1).
   */
  public static void storeFinishAlignmentPadding(Builder b, long root, long maxN) {
    for (long pad = 0; pad < 2 * maxN; pad++) {
      final long after = b.cursor() + pad;
      final int framing = lebLength((after - root) << 2);
      if ((b.alignmentOffset() + after + framing) % maxN == 0) {
        storeZeros(b, pad);
        return;
      }
    }
  }

  /** Ends a graph buffer whose root was just stored: alignment padding when the graph declares aligned arrays, then the framing word. */
  public static void storeGraphFraming(Builder b, long maxAlign) {
    storeGraphFramingAt(b, b.cursor(), maxAlign);
  }

  /** Ends a graph buffer whose root is stored at offset {@code root} (an arena's root may have been stored before the end). */
  public static void storeGraphFramingAt(Builder b, long root, long maxAlign) {
    if (maxAlign > 1) storeFinishAlignmentPadding(b, root, maxAlign);
    storeLeb(b, (b.cursor() - root) << 2);
  }

  // ── The spec-15 header, written by an arena (spec/45 milestone 8) ──────────────

  /** The header's fields length: the block length of the packed header node stored right after cursor {@code body}; 0 when none. */
  public static long headerFieldsLen(Builder b, long body) {
    final long f = b.frontLeb(body);
    return f < 0 ? 0 : f >>> 4;
  }

  /** The zero bytes that inflate a header so the body after it stays aligned to {@code maxN} (spec 15 §6). */
  public static long headerPadding(long fieldsLen, long rootOffset, long body, long maxN) {
    long q = 0;
    if (maxN > 1) {
      for (;; q++) {
        final long c = fieldsLen + q;
        final long span = lebLength(c) + c;
        final long stored = ((rootOffset + span) << 2) | 1;
        if ((lebLength(stored) + span + body) % maxN == 0 || q > 4 * maxN) break;
      }
    }
    return q;
  }

  /**
   * Turns the packed header node stored after cursor {@code body} (behind {@code q} zero bytes) into the
   * frame: its block length becomes the header's length {@code c}, and the framing word
   * {@code ((rootOffset + LEB(c) + c) << 2) | 1} goes in front.
   */
  public static void storeHeaderFrame(Builder b, long body, long q, long rootOffset) {
    if (!b.ok()) return;
    final long f = b.frontLeb(body);
    final long n = f & 15;
    final long fields = f >>> 4;
    if (f < 0 || fields + n + q != b.cursor() - body) {
      b.fail(Status.INVALID_VALUE);
      return;
    }
    b.rewind(b.cursor() - n);
    final long c = fields + q;
    storeLeb(b, c);
    storeLeb(b, ((rootOffset + lebLength(c) + c) << 2) | 1);
  }

  /** Whether two byte views hold the same bytes (a write-side elision test). */
  public static boolean sameBytes(MemorySegment a, MemorySegment b) {
    final long n = a == null ? 0 : a.byteSize();
    if (n != (b == null ? 0 : b.byteSize())) return false;
    return n == 0 || MemorySegment.mismatch(a, 0, n, b, 0, n) == -1;
  }
}
