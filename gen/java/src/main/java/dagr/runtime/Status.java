package dagr.runtime;

/** Why something did not happen — the C / C++ targets' status, same values, same order. */
public enum Status {
  OK,
  /** The framing word is malformed or points outside the buffer. */
  BAD_FRAMING,
  /** A header was asked for and the framing word carries none (spec 15). */
  NO_HEADER,
  /** Inconsistent bytes. */
  MALFORMED,
  /** A fixed-capacity writer, scratch or destination ran out of room. */
  BUFFER_FULL,
  /** A recursive walk over the data hit its depth limit. */
  DEPTH_EXCEEDED,
  /** A value holds what the wire cannot express (a union with no variant). */
  INVALID_VALUE,
  /** A growing writer could not allocate. */
  OUT_OF_MEMORY,
  /** An open-time gate refused the stream (spec 34 §4.3). */
  REJECTED,
  /** A DataSink record was asked for as a type it is not. */
  WRONG_TYPE,
  /** A utf8 value is not well-formed UTF-8 (spec/49 U1). */
  INVALID_UTF8
}
