package dagr.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Owner identity and liveness for the multi-producer SharedBuffer strategies (spec/40 §3.2, §4.3;
 * spec/45 §6): a lock word or a ring slot records WHICH process holds it, and a waiter takes it over
 * only once that process is gone — never on a timeout, which would let a merely paused holder resume
 * and write beside the new one.
 *
 * <p>The owner word is BIT-IDENTICAL across languages (processes of different languages share one
 * lock): pid in the low 32 bits, the process's start token in the high 32 — a port of the C target's
 * {@code dagr/owner.h}. The start token is read from {@code /proc/<pid>/stat} where it exists (Linux)
 * and is 0 elsewhere, as in every target — NOT {@code ProcessHandle.Info.startInstant()}, whose
 * precision is unspecified (spec/45 O-J6).
 *
 * <p>OS tier: it talks to the operating system ({@code ProcessHandle}, {@code /proc}).
 */
public final class Owner {
  private Owner() {}

  private static final long PID = ProcessHandle.current().pid();
  private static volatile long cached;

  /**
   * The low 32 bits of a process's start time (Linux: {@code /proc/<pid>/stat} field 22, clock ticks
   * since boot), or-ed with 1 so that it is never 0; 0 where it is not available — liveness then goes
   * by pid alone, and a reused pid can delay a recovery but never cause a wrong one.
   */
  public static int startToken(long pid) {
    final byte[] stat;
    try {
      stat = Files.readAllBytes(Path.of("/proc/" + pid + "/stat"));
    } catch (IOException | RuntimeException e) {
      return 0;
    }
    return parseStartToken(stat);
  }

  /** The start token of a {@code /proc/<pid>/stat} line; 0 when it has none. */
  public static int parseStartToken(byte[] stat) {
    int close = -1;   // the command name may contain spaces and parentheses: the LAST ')'
    for (int i = 0; i < stat.length; i++) {
      if (stat[i] == ')') close = i;
    }
    if (close < 0) return 0;
    int q = close + 1;
    // fields 3.. follow ") "; field 22 (starttime) is the 20th of them
    for (int field = 0; field < 19; field++) {
      while (q < stat.length && stat[q] == ' ') q++;
      while (q < stat.length && stat[q] != ' ') q++;
      if (q >= stat.length) return 0;
    }
    while (q < stat.length && stat[q] == ' ') q++;
    long v = 0;
    boolean any = false;
    for (; q < stat.length && stat[q] >= '0' && stat[q] <= '9'; q++) {
      v = v * 10 + (stat[q] - '0');
      any = true;
    }
    if (!any) return 0;
    return (int) v | 1;
  }

  /**
   * This process's identity: pid in the low 32 bits, its start token in the high 32. Never zero
   * (zero is "unowned"). Computed once and cached; two threads computing it at once is a benign repeat.
   */
  public static long self() {
    long me = cached;
    if (me == 0 || (int) me != (int) PID) {
      me = (PID & 0xffffffffL) | ((long) startToken(PID) << 32);
      cached = me;
    }
    return me;
  }

  /** This process's pid. */
  public static long pid() {
    return PID;
  }

  /**
   * Whether the process an owner word names still exists. A process always counts itself alive (its
   * threads cannot die without it), and any doubt answers "alive": a false "dead" would let two
   * writers run at once, a false "alive" only delays recovery.
   */
  public static boolean alive(long owner) {
    final long pid = owner & 0xffffffffL;
    if (owner == 0 || pid == (PID & 0xffffffffL)) return true;
    final boolean exists;
    try {
      exists = ProcessHandle.of(pid).isPresent();
    } catch (RuntimeException e) {
      return true;
    }
    if (!exists) return false;
    // the pid exists — the same process, or a later one that reused the pid?
    final int token = (int) (owner >>> 32);
    if (token != 0) {
      final int current = startToken(pid);
      if (current != 0 && current != token) return false;
    }
    return true;
  }

  /** Gives the processor to another thread — what a spinning waiter does now and then. */
  public static void pause() {
    Thread.yield();
  }
}
