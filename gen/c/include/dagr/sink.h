/* dagr/sink.h — the DataSink runtime (spec/11, spec/34; spec/44 §12.1): stream framing, the
 * record scan, the reverse span of a doubly-linked sink, record ranges, enum records,
 * raw-embedded graphs in records, and the fixed destination. A transliteration of the C++
 * target's dagr/sink.hpp.
 *
 *   [LEB framing] ([LEB length][packed header]) ( [LEB type id][LEB size][body] [RLEB span]? )*
 *
 * Every reader function is TOTAL: a truncated or garbled tail ends the stream, it never
 * reads outside the buffer.
 *
 * Core tier: no allocation. */
#ifndef DAGR_SINK_H
#define DAGR_SINK_H

#include "writer.h"

/* ── Type ids ──────────────────────────────────────────────────────────────────
 * The reserved band of meta-record type ids (spec 34 §2.1): meta_types[i] is 16384 + i. */
enum { dagr_meta_type_id_base = 16384, dagr_meta_type_id_end = 32767 };

static inline bool dagr_is_meta_type_id(uint64_t type_id) {
  return type_id >= dagr_meta_type_id_base && type_id <= dagr_meta_type_id_end;
}

/* ── Record ranges ─────────────────────────────────────────────────────────────── */

/** A record's bytes RELATIVE to the stream's records start (spec 34 §3.1): [start, end), a
 * doubly-linked record's trailing span included — the ranges of a stream tile its records. */
typedef struct dagr_record_range {
  uint64_t type_id;
  size_t start;
  size_t end;
} dagr_record_range;

static inline bool dagr_record_range_eq(dagr_record_range a, dagr_record_range b) {
  return a.type_id == b.type_id && a.start == b.start && a.end == b.end;
}

/** The write observer (spec 34 §3.2): called once per appended record, meta records included,
 * in stream order, with the record's range and its exact bytes (valid for the call only). */
typedef void (*dagr_sink_observer)(void *context, dagr_record_range range, dagr_bytes bytes);

/** Where a sink stream's records go: `write` takes one whole record (or the framing) — all of
 * it, or fails having taken none of it. `room` and `commit` are optional (NULL — build a dest
 * with `dagr_sink_dest_of`, or zero it): a destination that offers them has records of bounded
 * scalars written IN PLACE (spec 11 §6.1) — `room(n)` is `n` writable bytes right after what is
 * written (or NULL), `commit(len)` takes the `len` bytes written there. */
typedef struct dagr_sink_dest {
  dagr_status (*write)(void *context, const uint8_t *bytes, size_t n);
  void *context;
  uint8_t *(*room)(void *context, size_t n);
  dagr_status (*commit)(void *context, size_t len);
} dagr_sink_dest;

/** A destination that only writes. */
static inline dagr_sink_dest dagr_sink_dest_of(dagr_status (*write)(void *, const uint8_t *, size_t), void *context) {
  dagr_sink_dest dest;
  dest.write = write;
  dest.context = context;
  dest.room = NULL;
  dest.commit = NULL;
  return dest;
}

/* ── Framing ───────────────────────────────────────────────────────────────────── */

/** The framing word of a sink stream: the kind bit (2) set, and bit 0 when a header follows. */
enum { dagr_sink_framing_plain = 2, dagr_sink_framing_with_header = 3 };

/** Where a sink stream's parts are: the header block (SIZE_MAX without one) and the first record. */
typedef struct dagr_sink_frame {
  size_t header_at;
  size_t records_start;
} dagr_sink_frame;

/** Parses the framing word (and skips the header) of a sink stream. `header` says whether the
 * schema declares one: a stream that disagrees is refused — `dagr_bad_framing` for a graph
 * buffer or an unexpected header, `dagr_no_header` for a missing one. An EMPTY buffer is an
 * empty stream (a writer that never appended). */
static inline dagr_status dagr_sink_frame_of(dagr_bytes buf, bool header, dagr_sink_frame *out) {
  out->header_at = SIZE_MAX;
  out->records_start = 0;
  if (buf.len == 0) return dagr_ok;
  const dagr_varint framing = dagr_read_leb(buf, 0);
  if (framing.len == 0 || (framing.value & 2u) == 0) return dagr_bad_framing;
  const bool has = (framing.value & 1u) != 0;
  if (has != header) return has ? dagr_bad_framing : dagr_no_header;
  if (!header) {
    out->records_start = framing.len;
    return dagr_ok;
  }
  const dagr_varint length = dagr_read_leb(buf, framing.len);
  if (length.len == 0 || length.value > dagr_remaining(buf, framing.len + length.len)) return dagr_bad_framing;
  out->header_at = framing.len;
  out->records_start = framing.len + length.len + (size_t)length.value;
  return dagr_ok;
}

/* ── Records ───────────────────────────────────────────────────────────────────── */

/** One record of a stream, as positions: `[type id][size][body …][span?]` from `begin`;
 * `content` is the size prefix (where a record's packed accessor opens), `value` the byte
 * after it, `end` the byte after the body and `next` the next record. */
typedef struct dagr_sink_record_at {
  uint64_t type_id;
  size_t begin;
  size_t content;
  size_t value;
  size_t end;
  size_t next;
} dagr_sink_record_at;

/** The record at `pos`, or false when none starts there: at the end of the buffer, and for a
 * tail too short to hold one. A doubly-linked record's trailing span is stepped over. */
static inline bool dagr_sink_record_read(dagr_bytes buf, size_t pos, bool doubly_linked, dagr_sink_record_at *out) {
  if (pos >= buf.len) return false;
  const dagr_varint tid = dagr_read_leb(buf, pos);
  if (tid.len == 0) return false;
  const size_t content = pos + tid.len;
  const dagr_varint size = dagr_read_leb(buf, content);
  if (size.len == 0) return false;
  const size_t value = content + size.len;
  if (size.value > dagr_remaining(buf, value)) return false;
  const size_t end = value + (size_t)size.value;
  size_t next = end;
  if (doubly_linked) {
    const size_t span = dagr_leb_length(end - pos);
    if (span > dagr_remaining(buf, end)) return false;
    next = end + span;
  }
  out->type_id = tid.value;
  out->begin = pos;
  out->content = content;
  out->value = value;
  out->end = end;
  out->next = next;
  return true;
}

/** The trailing span whose last byte is at `end - 1` (spec 11 §11.4: the LEB bytes in reverse,
 * so a right-to-left read stops at the leading terminator), never reading below `floor`.
 * `len == 0` when there is none. */
static inline dagr_varint dagr_read_rleb_backward(dagr_bytes buf, size_t floor, size_t end) {
  if (end > buf.len || end <= floor) return dagr_varint_of(0, 0);
  uint64_t value = 0;
  unsigned shift = 0;
  size_t pos = end;
  while (pos > floor && shift <= 63) {
    pos--;
    const uint8_t byte = buf.ptr[pos];
    value |= (uint64_t)(byte & 0x7fu) << shift;
    if ((byte & 0x80u) == 0) return dagr_varint_of(value, end - pos);
    shift += 7;
  }
  return dagr_varint_of(0, 0);
}

/** The record that ENDS at `end` in a doubly-linked stream, or false when the span there does
 * not lead to a whole record at or after `floor` (the records start). */
static inline bool dagr_sink_record_before(dagr_bytes buf, size_t floor, size_t end, dagr_sink_record_at *out) {
  const dagr_varint span = dagr_read_rleb_backward(buf, floor, end);
  if (span.len == 0) return false;
  const size_t body_end = end - span.len;
  if (span.value > body_end - floor) return false;
  const size_t begin = body_end - (size_t)span.value;
  dagr_sink_record_at rec;
  if (!dagr_sink_record_read(buf, begin, true, &rec) || rec.end != body_end || rec.next != end) return false;
  *out = rec;
  return true;
}

/** A record's content — its size prefix and body: what `append_raw` takes back. */
static inline dagr_bytes dagr_sink_record_content(dagr_bytes buf, const dagr_sink_record_at *at) {
  return dagr_slice(buf, at->content, at->end);
}

/** The bytes of `range` (relative to `records_start`): a record's exact wire bytes. */
static inline dagr_bytes dagr_sink_range_bytes(dagr_bytes buf, size_t records_start, dagr_record_range range) {
  if (range.start > SIZE_MAX - records_start || range.end > SIZE_MAX - records_start) return dagr_bytes_of(NULL, 0);
  return dagr_slice(buf, records_start + range.start, records_start + range.end);
}

/* ── Enum records (spec 11 §2) ─────────────────────────────────────────────────── */

/** The content of an ENUM record: one raw byte for a byte-wide enum; a wider one as a varint
 * when that is shorter than its width — behind the size prefix every content starts with. */
static inline void dagr_store_sink_enum(dagr_builder *b, uint64_t value, size_t width) {
  const size_t before = b->cursor;
  if (width == 1) {
    dagr_store_u8(b, (uint8_t)value);
  } else if (dagr_leb_length(value) < width) {
    dagr_store_leb(b, value);
  } else {
    dagr_store_fixed(b, value, width);
  }
  dagr_store_leb(b, b->cursor - before);
}

/** The value of an enum record whose content holds `size` bytes at `at`. */
static inline uint64_t dagr_read_sink_enum(dagr_bytes buf, size_t at, size_t size, size_t width) {
  if (width == 1) return dagr_read_u8(buf, at);
  if (size == width) return dagr_read_uint_le(buf, at, width);
  return dagr_read_leb(buf, at).value;
}

/* ── Raw-embedded graphs in records (spec 18 §11) ──────────────────────────────── */

/** The standalone graph a record's raw-embedded entry at `pos` holds: `[LEB payload length]`,
 * then — when the graph has aligned arrays — a pad count `p` and `p` zero bytes, then the
 * graph. The pad LEADS (spec 18 §11.4). Empty when unreadable. */
static inline dagr_bytes dagr_sink_raw_blob(dagr_bytes buf, size_t pos, bool has_pad) {
  if (pos == SIZE_MAX) return dagr_bytes_of(NULL, 0);
  const dagr_varint length = dagr_read_leb(buf, pos);
  size_t start = pos + length.len;
  if (length.len == 0 || length.value > dagr_remaining(buf, start)) return dagr_bytes_of(NULL, 0);
  size_t size = (size_t)length.value;
  if (has_pad) {
    if (size == 0) return dagr_bytes_of(NULL, 0);
    const size_t pad = dagr_read_u8(buf, start);
    if (pad + 1 > size) return dagr_bytes_of(NULL, 0);
    start += pad + 1;
    size -= pad + 1;
  }
  return dagr_bytes_of(buf.ptr + start, size);
}

/** The root of the standalone graph a record's raw-embedded entry at `pos` holds, as a position
 * in `buf` (the graph's pointers are relative, so its accessors read it in place); SIZE_MAX when
 * the entry or the graph's framing is unreadable. */
static inline size_t dagr_sink_raw_root(dagr_bytes buf, size_t pos, bool has_pad) {
  const dagr_bytes blob = dagr_sink_raw_blob(buf, pos, has_pad);
  if (blob.len == 0) return SIZE_MAX;
  const size_t root = dagr_root_offset(blob);
  if (root == SIZE_MAX) return SIZE_MAX;
  return (size_t)(blob.ptr - buf.ptr) + root;
}

/** Stores `blob`, a standalone graph, as a record field's raw-embedded payload with `pad`
 * leading zero bytes; returns the cursor just after the blob — its distance from the end of
 * the record, which a writer needs to put the blob on its boundary. */
static inline size_t dagr_store_sink_raw(dagr_builder *b, dagr_bytes blob, bool has_pad, size_t pad) {
  const size_t before = b->cursor;
  dagr_store_bytes(b, blob.ptr, blob.len);
  const size_t at = b->cursor;
  if (has_pad) {
    dagr_store_zeros(b, pad);
    dagr_store_u8(b, (uint8_t)pad);
  }
  dagr_store_leb(b, b->cursor - before);
  return at;
}

/** The leading pad of a record's raw-embedded graph (spec 18 §11.4, spec 42 D6): `block` is the
 * record content `[LEB size][fields]` written with pad 0, its graph at `blob_offset`; `base` is
 * the absolute stream position of the block's first byte. The SMALLEST count in [0, 255] that
 * puts the graph on an `n` boundary in the stream, COUNTING that the pad lengthens the field's
 * payload length and the record's size. 0 when none does. */
static inline size_t dagr_sink_raw_pad(dagr_bytes block, size_t blob_offset, size_t base, size_t n) {
  const dagr_varint size = dagr_read_leb(block, 0);
  if (n == 0 || size.len == 0 || blob_offset < 2 || blob_offset > block.len) return 0;
  size_t q = blob_offset - 2; /* the payload length's last byte: the pad count follows */
  while (q > 0 && (dagr_read_u8(block, q - 1) & 0x80u) != 0) q--;
  const dagr_varint payload = dagr_read_leb(block, q);
  if (payload.len == 0) return 0;
  for (size_t pad = 0; pad < 256; pad++) {
    const size_t grow_p = dagr_leb_length(payload.value + pad) - payload.len;
    const size_t grow_c = dagr_leb_length(size.value + pad + grow_p) - size.len;
    if ((base + blob_offset + pad + grow_p + grow_c) % n == 0) return pad;
  }
  return 0;
}

/** Puts the raw-embedded graph of the record content just stored in `b` (with pad 0) on its
 * `n` boundary in the stream, `base` being where the content will start there. `blob_at` is
 * what dagr_store_sink_raw returned. Only the head in front of the graph moves (spec 42 D6). */
static inline void dagr_place_sink_raw(dagr_builder *b, size_t blob_at, size_t base, size_t n) {
  if (!dagr_builder_ok(b)) return;
  const dagr_bytes block = dagr_builder_bytes(b);
  if (blob_at > block.len) return;
  const size_t bo = block.len - blob_at;
  const size_t pad = dagr_sink_raw_pad(block, bo, base, n);
  if (pad == 0) return;
  const dagr_varint size = dagr_read_leb(block, 0);
  size_t q = bo - 2;
  while (q > 0 && (dagr_read_u8(block, q - 1) & 0x80u) != 0) q--;
  const dagr_varint payload = dagr_read_leb(block, q);
  const uint64_t new_payload = payload.value + pad;
  const uint64_t new_size = size.value + pad + (dagr_leb_length(new_payload) - payload.len);
  const size_t grow = pad + (dagr_leb_length(new_payload) - payload.len) + (dagr_leb_length(new_size) - size.len);
  const size_t middle = q - size.len; /* the fields before, and the field's tag */
  uint8_t *front = dagr_claim(b, grow);
  if (front == NULL) return;
  uint8_t *old = front + grow; /* where the pad-0 content now starts */
  memmove(front + dagr_leb_length(new_size), old + size.len, middle);
  uint8_t *p = front + dagr_put_leb(front, new_size) + middle;
  p += dagr_put_leb(p, new_payload);
  *p++ = (uint8_t)pad;
  memset(p, 0, pad); /* p + pad == old + bo: the graph, unmoved */
}

/* ── Writing ───────────────────────────────────────────────────────────────────── */

/** Frames the record just stored in `b` — its packed body, size prefix included — as a record
 * of `type_id`: the type id in front and, for a doubly-linked sink, the span at the end (the
 * span counts the type id and the body, never itself). */
static inline void dagr_frame_sink_record(dagr_builder *b, uint64_t type_id, bool doubly_linked) {
  dagr_store_leb(b, type_id);
  if (!doubly_linked) return;
  uint64_t span = b->cursor;
  uint8_t tail[10];
  const size_t n = dagr_leb_length(span);
  for (size_t i = 0; i < n; i++) { /* the LEB bytes, last byte first */
    const uint8_t low = (uint8_t)(span & 0x7fu);
    span >>= 7;
    tail[n - 1 - i] = (uint8_t)(span != 0 ? low | 0x80u : low);
  }
  dagr_builder_append_tail(b, tail, n);
}

/* ── The forward path (spec 11 §6.1, spec/44 §12.1) ─────────────────────────────
 * A record whose fields are all bounded scalars has a size bound, so its append asks for that
 * much room ONCE and writes `[type id][size][fields]` front to back — no claim per field — into
 * the destination itself when it offers room, else into the builder, and hands it over in one
 * write. Every `dagr_sink_fwd_*` writes the bytes of its backward twin in writer.h: change one,
 * change both (gate: `tests/schemas/sink_forward.py`). A transliteration of C++'s
 * `dagr::SinkForward`. */

/** Room for a record of at most `n` bytes, written forward: in `dest` (`*in_place` set) when it
 * offers room, else in `b`, reset for it; NULL when neither has it — store backward. */
static inline uint8_t *dagr_sink_room(dagr_sink_dest dest, dagr_builder *b, size_t n, bool *in_place) {
  if (dest.room != NULL && dest.commit != NULL) {
    uint8_t *p = dest.room(dest.context, n);
    if (p != NULL) {
      *in_place = true;
      return p;
    }
  }
  *in_place = false;
  dagr_builder_reset(b);
  return dagr_builder_room(b, n);
}

/** Hands a record written forward to `dest`: committed when it was written there, else in one
 * write. */
static inline dagr_status dagr_sink_hand_over(dagr_sink_dest dest, dagr_bytes record, bool in_place) {
  if (in_place) return dest.commit(dest.context, record.len);
  return dest.write(dest.context, record.ptr, record.len);
}

/** A record of bounded scalars written front to back over room from `dagr_sink_room`: the
 * fields from `lead` bytes in — room for the type id and the size at their bound — then
 * `dagr_sink_forward_finish`. */
typedef struct dagr_sink_forward {
  uint8_t *start;
  uint8_t *fields;
  uint8_t *p;
} dagr_sink_forward;

static inline dagr_sink_forward dagr_sink_forward_at(uint8_t *room, size_t lead) {
  dagr_sink_forward f;
  f.start = room;
  f.fields = room + lead;
  f.p = room + lead;
  return f;
}

/** `[tag][payload]` of a u16..i64 field — as `dagr_store_packed_int_field`. */
static inline void dagr_sink_fwd_int(dagr_sink_forward *f, uint64_t bits, size_t width, bool is_signed, uint64_t index,
                                     bool force_raw) {
  const uint64_t lv = dagr_leb_form(bits, width, is_signed);
  if (!force_raw && dagr_leb_length(lv) < width) {
    f->p += dagr_put_leb(f->p, index << 1);
    f->p += dagr_put_leb(f->p, lv);
    return;
  }
  f->p += dagr_put_leb(f->p, (index << 1) | 1u);
  dagr_put_le(f->p, bits, width);
  f->p += width;
}

/** `[tag | 1][byte]` — as `dagr_store_packed_byte_field`. */
static inline void dagr_sink_fwd_byte(dagr_sink_forward *f, uint8_t v, uint64_t index) {
  f->p += dagr_put_leb(f->p, (index << 1) | 1u);
  *f->p++ = v;
}

static inline void dagr_sink_fwd_encoded_(dagr_sink_forward *f, const dagr_packed_float *e, uint64_t index) {
  f->p += dagr_put_leb(f->p, (index << 1) | (e->raw ? 1u : 0u));
  memcpy(f->p, e->bytes, e->len);
  f->p += e->len;
}

/** An f32 / f64 field through the float codec — as `dagr_store_packed_f32` / `_f64` behind its tag. */
static inline void dagr_sink_fwd_f32(dagr_sink_forward *f, float v, uint64_t index) {
  const dagr_packed_float e = dagr_encode_packed_f32(v, false);
  dagr_sink_fwd_encoded_(f, &e, index);
}
static inline void dagr_sink_fwd_f64(dagr_sink_forward *f, double v, uint64_t index) {
  const dagr_packed_float e = dagr_encode_packed_f64(v, false);
  dagr_sink_fwd_encoded_(f, &e, index);
}

/** A `raw` field's fixed bytes (spec 39): `[tag | 1][width bytes]` — raw f32 / f64 as their bits. */
static inline void dagr_sink_fwd_fixed(dagr_sink_forward *f, uint64_t bits, size_t width, uint64_t index) {
  f->p += dagr_put_leb(f->p, (index << 1) | 1u);
  dagr_put_le(f->p, bits, width);
  f->p += width;
}

/** An f16 / bf16 field — as `dagr_store_packed_half` behind its tag. */
static inline void dagr_sink_fwd_half(dagr_sink_forward *f, float v, bool bf16, uint64_t index) {
  const uint8_t special = dagr_half_special(v);
  if (special != 0xff) {
    f->p += dagr_put_leb(f->p, index << 1);
    *f->p++ = special;
    return;
  }
  dagr_sink_fwd_fixed(f, dagr_half_bits(v, bf16), 2, index);
}

/** Puts `[type id][size]` in front of the fields — which move up when the size is shorter than
 * its bound — and, doubly linked, the span after them (as `dagr_frame_sink_record`); the
 * record's bytes, from the room's start. */
static inline dagr_bytes dagr_sink_forward_finish(dagr_sink_forward *f, uint64_t type_id, bool doubly_linked) {
  const size_t body = (size_t)(f->p - f->fields);
  uint8_t *q = f->start + dagr_put_leb(f->start, type_id);
  q += dagr_put_leb(q, body);
  if (q != f->fields) memmove(q, f->fields, body);
  uint8_t *end = q + body;
  if (doubly_linked) {
    uint64_t span = (uint64_t)(end - f->start);
    const size_t n = dagr_leb_length(span);
    for (size_t i = 0; i < n; i++) { /* the LEB bytes, last byte first */
      const uint8_t low = (uint8_t)(span & 0x7fu);
      span >>= 7;
      end[n - 1 - i] = (uint8_t)(span != 0 ? low | 0x80u : low);
    }
    end += n;
  }
  return dagr_bytes_of(f->start, (size_t)(end - f->start));
}

/** A destination over caller storage: every record lands in one write, all of it or —
 * `dagr_buffer_full` — none of it. Wire it in with `dagr_fixed_dest_as_dest`. */
typedef struct dagr_fixed_dest {
  uint8_t *data;
  size_t cap;
  size_t size;
} dagr_fixed_dest;

static inline dagr_fixed_dest dagr_fixed_dest_over(uint8_t *storage, size_t capacity) {
  dagr_fixed_dest d;
  d.data = storage;
  d.cap = capacity;
  d.size = 0;
  return d;
}

static inline dagr_status dagr_fixed_dest_write(void *context, const uint8_t *bytes, size_t n) {
  dagr_fixed_dest *d = (dagr_fixed_dest *)context;
  if (n > d->cap - d->size) return dagr_buffer_full;
  if (n != 0) memcpy(d->data + d->size, bytes, n);
  d->size += n;
  return dagr_ok;
}

/** Writing IN PLACE (`dagr_sink_room`): `n` bytes right after what is written, or NULL. */
static inline uint8_t *dagr_fixed_dest_room(void *context, size_t n) {
  dagr_fixed_dest *d = (dagr_fixed_dest *)context;
  return n <= d->cap - d->size ? d->data + d->size : NULL;
}

/** Takes the `len` bytes written in place at what `room` returned. */
static inline dagr_status dagr_fixed_dest_commit(void *context, size_t len) {
  dagr_fixed_dest *d = (dagr_fixed_dest *)context;
  if (len > d->cap - d->size) return dagr_buffer_full;
  d->size += len;
  return dagr_ok;
}

static inline dagr_sink_dest dagr_fixed_dest_as_dest(dagr_fixed_dest *d) {
  dagr_sink_dest dest = dagr_sink_dest_of(dagr_fixed_dest_write, d);
  dest.room = dagr_fixed_dest_room;
  dest.commit = dagr_fixed_dest_commit;
  return dest;
}

/** What has been written so far. */
static inline dagr_bytes dagr_fixed_dest_bytes(const dagr_fixed_dest *d) { return dagr_bytes_of(d->data, d->size); }

#endif /* DAGR_SINK_H */
