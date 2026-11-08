package dagr.runtime;

/**
 * The state of a recursive restore over the data (spec/45 §4: anything recursive over the bytes
 * takes a depth limit — a 1 MB buffer can nest packed nodes half a million deep): how deep it may
 * still go, and the first failure. The C target's {@code dagr_restore}, without scratch memory —
 * a Java restore allocates its values.
 */
public final class RestoreCtx {
  /** The depth limit every target defaults to. */
  public static final int DEFAULT_MAX_DEPTH = 128;

  private int depthLeft;
  private Status status = Status.OK;

  public RestoreCtx() {
    this(DEFAULT_MAX_DEPTH);
  }

  public RestoreCtx(int maxDepth) {
    this.depthLeft = maxDepth;
  }

  /** One level deeper: false (and {@code DEPTH_EXCEEDED}) past the limit or after a failure. */
  public boolean enter() {
    if (status != Status.OK) return false;
    if (depthLeft == 0) {
      status = Status.DEPTH_EXCEEDED;
      return false;
    }
    depthLeft--;
    return true;
  }

  public void leave() {
    depthLeft++;
  }

  public Status status() {
    return status;
  }

  /** A utf8 value, checked (spec/49 U1): {@link Reader#INVALID_TEXT} records {@code INVALID_UTF8}. */
  public String text(String s) {
    if (s == Reader.INVALID_TEXT && status == Status.OK) status = Status.INVALID_UTF8;
    return s;
  }
}
