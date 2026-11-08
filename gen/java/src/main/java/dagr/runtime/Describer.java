package dagr.runtime;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

/**
 * The canonical walk of an arena's structural methods (spec/45 §5.5) — a port of the C target's
 * {@code dagr_describer}: a node is written in full the first time it is met, as {@code Name#n{…}},
 * and as {@code Name#n} after that — so a shared node and a cycle show as such, and two arenas holding
 * isomorphic graphs describe them alike whatever their ids. Floats are written as their bits.
 * {@code equals} compares two descriptions, {@code hashCode} hashes one (FNV-1a), {@code toString}
 * is one.
 */
public final class Describer {
  /** How deep a walk goes before it writes {@code …}. */
  public static final int MAX_DEPTH = 128;

  private final StringBuilder out = new StringBuilder();
  private final HashMap<Key, Integer> seen = new HashMap<>();
  private int depth;

  private record Key(long type, long handle) {}

  public void raw(String text) {
    out.append(text);
  }

  public void u64(long v) {
    out.append(Long.toUnsignedString(v));
  }

  public void i64(long v) {
    out.append(v);
  }

  public void bool(boolean v) {
    out.append(v);
  }

  public void f32(float v) {
    out.append('f').append(Integer.toHexString(Float.floatToRawIntBits(v)));
  }

  public void f64(double v) {
    out.append('d').append(Long.toHexString(Double.doubleToRawLongBits(v)));
  }

  public void none() {
    out.append("nil");
  }

  /** Text, quoted, with {@code "} and {@code \} escaped. */
  public void str(String s) {
    out.append('"');
    for (int i = 0; i < s.length(); i++) {
      final char c = s.charAt(i);
      if (c == '"' || c == '\\') out.append('\\');
      out.append(c);
    }
    out.append('"');
  }

  /** Bytes as {@code 0x} and lower-case hex. */
  public void bytes(byte[] b) {
    out.append("0x");
    if (b == null) return;
    for (byte x : b) {
      out.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
    }
  }

  public void bytes(MemorySegment b) {
    bytes(b == null ? null : b.toArray(ValueLayout.JAVA_BYTE));
  }

  public void field(String name, boolean first) {
    if (!first) out.append(", ");
    out.append(name).append(": ");
  }

  public void sep(int i) {
    if (i > 0) out.append(", ");
  }

  /**
   * Starts node {@code handle} of node type {@code type}: false — having written {@code Name#n} (met
   * before) or {@code …} (the depth limit) — when its fields are not to be written; true after
   * {@code Name#n{}, paired with {@link #leave}.
   */
  public boolean enter(long type, String name, long handle) {
    final Key key = new Key(type, handle);
    final Integer ordinal = seen.get(key);
    if (ordinal != null) {
      out.append(name).append('#').append(ordinal.intValue());
      return false;
    }
    if (depth >= MAX_DEPTH) {
      out.append('…');
      return false;
    }
    final int n = seen.size();
    seen.put(key, n);
    out.append(name).append('#').append(n).append('{');
    depth++;
    return true;
  }

  public void leave() {
    depth--;
    out.append('}');
  }

  public String text() {
    return out.toString();
  }

  /** FNV-1a of the description's UTF-8 bytes — what {@code hashCode} folds. */
  public long hash() {
    long h = 0xcbf29ce484222325L;
    for (byte b : text().getBytes(StandardCharsets.UTF_8)) {
      h ^= b & 0xff;
      h *= 0x100000001b3L;
    }
    return h;
  }
}
