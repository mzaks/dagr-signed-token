package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;

/**
 * What an arena's array getters return (spec/45 §5.5): read-only views of a record's array — the
 * lazy reader's indexed arrays' surface ({@code size()}, {@code has(i)}, {@code get(i)},
 * {@code toArray()}), so one assertion body reads both. A view is valid until the field is set again;
 * {@code present} null means every element is present. An index outside the array, or a nil element,
 * reads zero / empty.
 */
public final class ArenaArrays {
  private ArenaArrays() {}

  static boolean has(int i, int n, boolean[] present) {
    return i >= 0 && i < n && (present == null || present[i]);
  }

  /** The UTF-8 bytes of {@code s} as a segment (empty for null). */
  public static MemorySegment utf8(String s) {
    return s == null || s.isEmpty() ? MemorySegment.NULL : MemorySegment.ofArray(s.getBytes(StandardCharsets.UTF_8));
  }

  /** A read-only view of {@code b} (empty for null). */
  public static MemorySegment bytes(byte[] b) {
    return b == null || b.length == 0 ? MemorySegment.NULL : MemorySegment.ofArray(b).asReadOnly();
  }

  /** A copy of {@code s}'s bytes (what an arena restore keeps of a buffer's data). */
  public static byte[] copy(MemorySegment s) {
    return s == null ? new byte[0] : s.toArray(java.lang.foreign.ValueLayout.JAVA_BYTE);
  }

  /** {@code bs} as segments — what the packed array store takes (null stays null: nil). */
  public static MemorySegment[] segments(byte[][] bs) {
    if (bs == null) return null;
    final MemorySegment[] out = new MemorySegment[bs.length];
    for (int i = 0; i < bs.length; i++) out[i] = bs[i] == null ? null : MemorySegment.ofArray(bs[i]);
    return out;
  }

  /** Whether {@code a} holds exactly {@code b}'s bytes (null: empty) — a write-side elision test. */
  public static boolean sameBytes(byte[] a, byte[] b) {
    return java.util.Arrays.equals(a == null ? new byte[0] : a, b == null ? new byte[0] : b);
  }

  /** {@code a} grown or cut to {@code n} elements — the arena's store growth and array cleaning. */
  public static <T> T[] copyOf(T[] a, int n) {
    return java.util.Arrays.copyOf(a, n);
  }

  public static long[] copyOf(long[] a, int n) {
    return java.util.Arrays.copyOf(a, n);
  }

  public static int[] copyOf(int[] a, int n) {
    return java.util.Arrays.copyOf(a, n);
  }

  /** The common surface: the length and the presence. */
  public abstract static class View {
    protected final boolean[] present;
    protected final int n;

    View(int n, boolean[] present) {
      this.n = n;
      this.present = present;
    }

    public final int size() {
      return n;
    }

    public final boolean isEmpty() {
      return n == 0;
    }

    public boolean has(int i) {
      return ArenaArrays.has(i, n, present);
    }
  }

  public static final class Ints extends View {
    private final int[] v;

    public Ints(int[] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    public int get(int i) {
      return has(i) ? v[i] : 0;
    }

    public int[] toArray() {
      final int[] out = new int[n];
      for (int i = 0; i < n; i++) out[i] = get(i);
      return out;
    }
  }

  public static final class Longs extends View {
    private final long[] v;

    public Longs(long[] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    public long get(int i) {
      return has(i) ? v[i] : 0;
    }

    public long[] toArray() {
      final long[] out = new long[n];
      for (int i = 0; i < n; i++) out[i] = get(i);
      return out;
    }
  }

  public static final class Shorts extends View {
    private final short[] v;

    public Shorts(short[] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    public short get(int i) {
      return has(i) ? v[i] : 0;
    }

    public short[] toArray() {
      final short[] out = new short[n];
      for (int i = 0; i < n; i++) out[i] = get(i);
      return out;
    }
  }

  public static final class Bytes extends View {
    private final byte[] v;

    public Bytes(byte[] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    public byte get(int i) {
      return has(i) ? v[i] : 0;
    }

    public byte[] toArray() {
      final byte[] out = new byte[n];
      for (int i = 0; i < n; i++) out[i] = get(i);
      return out;
    }
  }

  public static final class Floats extends View {
    private final float[] v;

    public Floats(float[] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    public float get(int i) {
      return has(i) ? v[i] : 0;
    }

    public float[] toArray() {
      final float[] out = new float[n];
      for (int i = 0; i < n; i++) out[i] = get(i);
      return out;
    }
  }

  public static final class Doubles extends View {
    private final double[] v;

    public Doubles(double[] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    public double get(int i) {
      return has(i) ? v[i] : 0;
    }

    public double[] toArray() {
      final double[] out = new double[n];
      for (int i = 0; i < n; i++) out[i] = get(i);
      return out;
    }
  }

  public static final class Booleans extends View {
    private final boolean[] v;

    public Booleans(boolean[] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    public boolean get(int i) {
      return has(i) && v[i];
    }

    public boolean[] toArray() {
      final boolean[] out = new boolean[n];
      for (int i = 0; i < n; i++) out[i] = get(i);
      return out;
    }
  }

  /** A {@code [utf8]} / {@code [utf8?]}: a null element is nil. */
  public static final class Strings extends View {
    private final String[] v;

    public Strings(String[] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    @Override
    public boolean has(int i) {
      return super.has(i) && v[i] != null;   // a null element is nil
    }

    public String get(int i) {
      return has(i) ? v[i] : "";
    }
  }

  /** A {@code [data]} / {@code [data?]}: a null element is nil. */
  public static final class Blobs extends View {
    private final byte[][] v;

    public Blobs(byte[][] v, boolean[] present) {
      super(v == null ? 0 : v.length, present);
      this.v = v;
    }

    @Override
    public boolean has(int i) {
      return super.has(i) && v[i] != null;   // a null element is nil
    }

    public MemorySegment get(int i) {
      return has(i) ? ArenaArrays.bytes(v[i]) : MemorySegment.NULL;
    }
  }
}
