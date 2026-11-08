package dagr.runtime;

import java.util.ArrayDeque;
import java.util.HashMap;

/**
 * What an arena restore threads (spec/45 §5.5, milestone 8) — a port of the C target's
 * {@code dagr_restore_seen}: each node read so far, by node type and buffer position, so that a node
 * met again — shared, or a cycle back to an ancestor — is the same node; how deep the walk may still
 * descend (it recurses over the DATA, so a hostile buffer must not overflow the stack); and the first
 * failure ({@code DEPTH_EXCEEDED}).
 */
public final class RestoreSeen {
  /** The depth limit every target defaults to. */
  public static final int DEFAULT_MAX_DEPTH = 128;

  private record Key(int type, long pos) {}

  private final HashMap<Key, Long> seen = new HashMap<>();
  private final ArrayDeque<Runnable> pending = new ArrayDeque<>();
  private final int maxDepth;
  private int depthLeft;
  private Status status = Status.OK;

  public RestoreSeen(int maxDepth) {
    this.depthLeft = maxDepth;
    this.maxDepth = maxDepth;
  }

  /** A utf8 value, checked (spec/49 U1): {@link Reader#INVALID_TEXT} records {@code INVALID_UTF8}. */
  public String text(String s) {
    if (s == Reader.INVALID_TEXT) fail(Status.INVALID_UTF8);
    return s;
  }

  /** Queues the fill of a regular or frozen node reached by reference (spec/49 R1): run by {@link #drain}, not by a nested call. */
  public void later(Runnable fill) {
    pending.push(fill);
  }

  /** Runs the queued fills, and those they queue, each from level 1 (spec/49 R2), while nothing has failed. */
  public void drain() {
    while (!pending.isEmpty() && status == Status.OK) {
      final Runnable fill = pending.pop();
      final int saved = depthLeft;
      depthLeft = maxDepth;
      fill.run();
      depthLeft = saved;
    }
  }

  /** A packed subtree reached by reference starts again at level 1 (spec/49 R2): the whole limit until {@link #resume}. */
  public int restart() {
    final int saved = depthLeft;
    depthLeft = maxDepth;
    return saved;
  }

  public void resume(int saved) {
    depthLeft = saved;
  }

  public Status status() {
    return status;
  }

  public boolean ok() {
    return status == Status.OK;
  }

  public void fail(Status s) {
    if (status == Status.OK) status = s;
  }

  /** The id the node of {@code type} at {@code pos} was restored as, or -1. */
  public long find(int type, long pos) {
    final Long id = seen.get(new Key(type, pos));
    return id == null ? -1 : id;
  }

  public void add(int type, long pos, long id) {
    seen.put(new Key(type, pos), id);
  }

  /** One level of the walk: false — and {@code DEPTH_EXCEEDED} recorded — at the depth limit; pair a true one with {@link #leave}. */
  public boolean enter() {
    if (depthLeft == 0) {
      fail(Status.DEPTH_EXCEEDED);
      return false;
    }
    depthLeft--;
    return true;
  }

  public void leave() {
    depthLeft++;
  }
}
