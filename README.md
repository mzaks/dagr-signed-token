# dagr-signed-token

A **JWT-shaped signed token**, defined once as a [Dagr](https://dagr.one) schema
and generated into **Swift, Rust, TypeScript, Mojo, and Odin** — with a
cross-language test that proves every language mints the **byte-for-byte identical**
token and can verify the others'.

> **Self-contained reference.** The `dagr` CLI and its schema DSL are **not yet public**.
> This repo commits the generated code in `gen/`, so all five examples build, run, and
> cross-verify **without** the CLI. `schema.py` is included to show the single source of
> truth; regenerating from it is what needs the (closed-source) CLI.

A JWT is `header.payload.signature`: the signature is a MAC over the payload, so
a verifier can trust the claims *before* acting on them. This reproduces that with
Dagr's customizable header ("14 Customizable Header.md"), **Shape A**:

| JWT | dagr-signed-token |
|---|---|
| payload / claims | the graph **body** (`Claims`, `frozen+packed`) |
| registered claims (`sub`/`iss`/`aud`/`iat`/`exp`) | typed `Claims` fields (all optional per RFC 7519 except a defensive `issuedAt`/`expiresAt`) |
| custom / private claims | a freeform recursive-JSON value (`custom`) |
| JOSE header + signature | a packed **header** node `Jws { algorithm, keyId, signature }` |
| sign `b64(header).b64(payload)` | sign `(rootOffset, body)` in the write closure |
| verify before use | the **read gate** — runs before the body is parsed |

Everything is **dependency-free**: the codec is generated Dagr code, and the
crypto is each platform's standard tool — Rust hand-rolls SHA-256/HMAC (validated
against NIST + RFC 4231 vectors), Swift uses CommonCrypto, TypeScript uses Node's
built-in `node:crypto`. Because HMAC-SHA256 is a standard and the Dagr body is
byte-identical across languages, the signatures — and the whole 207-byte token —
match to the byte.

## Layout

```
schema.py            the single source of truth — the Token graph + a Library(targets=[...])
                     (shown for reference; regenerating from it needs the closed-source dagr CLI)
CONTRACT.md          the shared constants every example mints (so buffers match)
gen/                 COMMITTED generated code: gen/{swift,rust,typescript,mojo,odin}/
examples/
  rust/              Cargo bin — path-deps the generated crate; sha256.rs is hand-rolled
  swift/             main.swift + Crypto.swift, compiled against gen/swift sources
  swift-jwt-bench/   standalone SwiftPM package — JWTKit HS256 JWT baseline for the benchmark
  typescript/        demo.ts — imports gen/typescript, HMAC via node:crypto
  mojo/              main.mojo — imports gen/mojo, hand-rolled HMAC + native file I/O
  odin/              main.odin — imports gen/odin + its runtime, HMAC via core:crypto/hmac
  python-ffi/        Python over a Rust cdylib (ctypes) — fast, self-contained; see its README
run_cross_lang.sh    (build →) mint in each language → N×N verify → assert byte-identity
run_bench.sh         (build optimized →) 50k-rep mint/verify per language → ns/op table
```

## Prerequisites

The examples build from the **committed** `gen/` — you do **not** need the `dagr` CLI.
You need: `cargo` / `rustc`, `swiftc` (macOS), `node` (v22+; the TS demo runs via `npx tsx`),
`pixi` (for Mojo — the example builds against a Mojo pixi environment), and `odin`.

## Regenerate the code (optional)

`gen/` is already committed, so this is only needed if you change `schema.py` — and it
requires the closed-source **`dagr`** CLI (not yet public). The `run_*.sh` scripts
auto-detect it: if `dagr` is on your PATH they regenerate `gen/` first, otherwise they use
what's committed.

```bash
dagr build        # reads schema.py, re-emits gen/{swift,rust,typescript,mojo,odin}/
```

## Run one language

```bash
# Rust
cargo run --manifest-path examples/rust/Cargo.toml

# Swift
swiftc -O gen/swift/Sources/dagr_signed_token/*.swift examples/swift/Crypto.swift examples/swift/main.swift -o examples/swift/dst-swift
./examples/swift/dst-swift

# TypeScript
npx tsx examples/typescript/demo.ts

# Mojo (self-contained pixi project in examples/mojo; hand-rolled HMAC + native file I/O)
pixi run --manifest-path examples/mojo/pixi.toml \
  mojo run -I gen/mojo examples/mojo/main.mojo

# Odin (HMAC via core:crypto/hmac)
odin run examples/odin -out:examples/odin/dst-odin
```

Each prints the mint size and five verification outcomes:

```
Minted token: 207 bytes
Verification:
  valid token          ACCEPT  sub="user-42" custom={"tenant":"acme","roles":["admin","billing"],"mfa":true,"fp":0xdeadbeef}
  tampered body        REJECT  [GATE (verify-before-parse)] BadSignature
  wrong key            REJECT  [GATE (verify-before-parse)] BadSignature
  alg:none token       REJECT  [GATE (verify-before-parse)] BadAlg
  expired token        REJECT  [post-decode claim check] Expired
```

## Cross-language validation

```bash
./run_cross_lang.sh
```

```
== [byte-identity] all minted tokens must be identical ==
  IDENTICAL (207 bytes) — rust == swift == ts == mojo == odin
== [cross-verify] every verifier reads every language's token ==
  rust   verifies rust   : OK
  swift  verifies rust   : OK
  ts     verifies rust   : OK
  … (25 combinations: every one of 5 languages verifies every language's token) …
== ALL GREEN ==
```

## Benchmarks

```bash
./run_bench.sh      # builds each language optimized → 50k-rep mint/verify → table
```

Each language mints + verifies in-process (warm-up + 50k reps, correctness-gated).
The Dagr numbers exercise the **fast path**: arena-free **direct build** (spec 31 —
a value tree straight to bytes, gated byte-identical to the arena) + **zero-alloc
lazy verify** (verify-before-parse, then read fields off the buffer, no restore).
**Rust, Swift, TypeScript, and Python** also bench an **equivalent classic HS256 JWT**
with the same claims via that language's *real* JWT library — **Rust `jsonwebtoken`**,
**Swift `JWTKit`** (Vapor), **TS `jsonwebtoken`**, **Python `PyJWT`** — so the delta isolates
the *format*. **Python** here is a `ctypes` binding over the Rust codec
(`examples/python-ffi`), not an independent implementation. The Rust Dagr side uses **`ring`**
for HMAC-SHA256 (the same asm crypto `jsonwebtoken` uses, so *that* comparison is
crypto-matched); Swift Dagr uses **CommonCrypto**. **Mojo** shows two arena-free build
strategies: **`reflect`** —
serialize straight from a live value struct via comptime reflection, no intermediate tree —
and **`tree`** — a `DirectJson` value tree. Representative run (Apple Silicon; ns/op —
ratios, not absolutes):

| lang | impl | mint (ns) | verify (ns) | size (B) |
|---|---|--:|--:|--:|
| rust | dagr | 451 | **205** | **207** |
| rust | jwt (`jsonwebtoken`) | 937 | 1519 | 395 |
| swift | dagr | 3533 | **819** | 207 |
| swift | jwt (`JWTKit`) | 25111 | 30565 | 368 |
| ts | dagr | 4840 | 2079 | 207 |
| ts | jwt (`jsonwebtoken`) | 1636 | 2085 | 395 |
| python | dagr (`ctypes`→Rust) | 5047 | 2882 | 207 |
| python | jwt (`PyJWT`) | 6025 | 7643 | 365 |
| mojo | dagr (reflect) | 1015 | 360 | 207 |
| mojo | dagr (tree) | 1355 | 360 | 207 |
| odin | dagr | 785 | 283 | 207 |

**What it shows** — the token is **207 B vs a classic JWT's 395 B (~48 % smaller)** in
every language (schema-driven: field names never hit the wire, no base64 33 % inflation;
even against JWTKit's leaner 368 B, Dagr is 44 % smaller). On *speed*, the compiled targets' standout
is **verify** — verify-before-parse + zero-alloc lazy read vs base64-decode + full
deserialize. **Rust verifies ~7× faster** than `jsonwebtoken` (205 vs 1519 ns, crypto
matched); **Swift ~37×** faster than JWTKit (819 vs 30 565 ns — JWTKit is async on
SwiftCrypto/BoringSSL); **Python (ctypes→Rust) ~2.7×** faster than PyJWT (2882 vs 7643 ns);
**Mojo and Odin** verify in ~300–360 ns. That's the hot path for a token you mint once and
check on every request. **Mint** is more mixed: Rust Dagr now mints *faster* than a real JWT
lib (451 vs 937 ns), and Python-over-Rust edges PyJWT (5047 vs 6025 ns); Mojo's reflection
path mints in ~1 µs; Swift
Dagr mint (~3.5 µs) still trails Rust — its **flat claims serialize in ~450 ns, but the
recursive-JSON `custom` claim is ~1.9 µs** (Swift value-semantics + ARC over the generic
`Array`/`indirect enum` store — the next optimization target, see below). In Node the
heavily-optimized *native* `JSON`+crypto still beats the interpreted TS Dagr codec on raw
speed. Dagr's durable wins are **size**, **cross-language byte-identity**, **type-safe lazy
reads**, and **fast verify** in compiled targets.

**Profiling** (`dst profile`, Rust, `--features bench`) drove two changes: (1) RustCrypto
`sha2` ran its *software* backend here — **~4.6× slower than `ring`** (745 vs 160 ns per
HMAC) — so both sides now use `ring`; (2) the direct serializer built the token in **three**
`DagrBuilder`s (body/header/framing) with three `finalize()` copies. Since the builder
grows back-to-front and the direct store is dedup-free, it now uses **one** builder —
write the body, sign it *in place*, then prepend the header + framing, and finalize once.
That cut serialize ~830 → ~570 ns and mint ~1400 → ~970 ns, closing the gap to JWT. (The
generated serializer keeps the 3-builder path only for aligned graphs, whose header
inflation needs the finalized body length.) (3) The remaining ~210 ns "build the value
tree" was mostly inherent (jsonwebtoken's owned Claims struct costs ~130 ns too), but the
recursive-JSON `Array` variant needlessly boxed each element (`Vec<Option<Box<Json>>>`) —
a `Vec` already heap-indirects, so it's now `Vec<Option<Json>>`: one fewer alloc per
element (build ~210 → ~180 ns) and no `Box::new` at call sites.

The same one-builder serialize was applied to the **Swift, TS, and Mojo** direct builders
(Mojo had serialized the whole tree *twice* — headerless to sign, then again with the header —
which a single-pass `gate` closure fixed, ~12360 → ~8420 ns). Two later passes closed more:

- **Mojo** later dropped `ArcPointer` entirely. The recursive union needs heap indirection to
  break the `Movable`/`Deinitable` conformance cycle; a generated **non-atomic `_Box`** (an
  erased untracked pointer + *unconditional* conformance) does it without atomics — where stdlib
  `OwnedPointer` can't (its deinit is conditional, so the cycle returns). Better still, the
  **`reflect`** path skips the intermediate tree altogether: `std.reflection` walks a live value
  struct and emits the union bytes directly (byte-identical, sound by borrow) — mint ~1 µs.
- **Swift** verify was dominated by **CryptoKit HMAC** (~1.5 µs/op of per-call `SymmetricKey`/
  `Data` bridging); switching to **CommonCrypto `CCHmac`** (same standard HMAC → byte-identical)
  cut verify 1859 → ~800 ns. On mint, the packed presence/encoding byte was built with
  `[Bool].bitSet` — a heap `[Bool]` + `[UInt8]` **per node**; emitting a direct `UInt8` bit-OR
  removed those allocations (universal across all graphs). What remains is the recursive `custom`
  JSON: the generic `Array` store's dynamic type-dispatch + `indirect enum` ARC, which would want
  a codegen-specialized store to close.

**Caveats.** This is deliberately *not* a fair fight (Dagr is a typed binary graph, JWT
is base64url JSON). Crypto differs *across languages* (Rust = `ring` both sides; Mojo
implements SHA-256 natively on the **ARMv8 crypto intrinsics** — `sha256h`/`h2`/`su0`/`su1`
via `llvm_intrinsic`, the same hardware `ring` uses, no FFI; Swift = CommonCrypto, TS =
`node:crypto`, Odin = `core:crypto`), so cross-language `verify` times
reflect the platform's crypto, not only the format read. The `jwt` rows likewise aren't
comparable *to each other* — each is a different library architecture (JWTKit is async on
SwiftCrypto/BoringSSL, `jsonwebtoken` is sync native) — only each to
its own language's `dagr` row. (Mojo went further: a streaming
HMAC keeps the SHA state + ipad/opad on the stack (`InlineArray`) and hashes the message
Span in place — no per-message padding copy, no inner/outer/preimage Lists — the
generated reader hands the gate a zero-copy `Span` subview of the buffer (not a `List`),
the 64 round constants are `comptime` immediates rather than a per-call heap `List`, the
message words load vectorized (SIMD + `rev32`), the two independent HMAC key-blocks are
interleaved, and `update`/`finalize` do their byte handling with `memcpy`/`memset`/SIMD
stores rather than scalar loops — plus a **lazy header gate** that stopped eagerly restoring
the header. Together these took Mojo verify **7920 → ~360 ns** (see below).)

**Why Mojo verify trails Rust's, and why that's expected.** Rust's `~206 ns` is `ring` —
world-class hand-tuned **assembly**; Odin's `~282 ns` is `core:crypto` — a tuned **stdlib**
library. Mojo has no mature crypto library, so its SHA-256/HMAC is **hand-rolled from
scratch**. The honest apples-to-apples: **Rust's own hand-rolled SHA-256 HMAC (the demo's
zero-dep default, `src/sha256.rs`) benchmarks at `1177 ns`** — so the gap is
*library-vs-hand-rolled crypto*, **not** a language gap.

The hand-roll was then tuned toward `ring`'s per-block structure (`645 ns`, ~2.8× `ring`).
The key diagnosis: Mojo was **overhead-bound, not `sha256h`-latency-bound** — a fully serial
block is ~128 cycles ≈ `ring`'s per-block, yet we measured ~680 cycles/block. So the wins
came from removing per-byte overhead, not from hiding latency: (1) a **vectorized
big-endian load** (one 16-byte SIMD load + `rev32` per quad, replacing 16 bounds-checked
scalar byte-assemblies) — `1170 → 1000 ns`; (2) **interleaving the two independent HMAC
first-blocks** (`ipad`/`opad` have no data dependency, so both `_block`s are issued
adjacently and the wide OoO core overlaps their `sha256h` latency) — `1000 → 925 ns`;
(3) dropping a per-call secret `String` copy — `925 → 890 ns`; (4) **vectorizing the
`update`/`finalize` byte handling** — partial-block buffering via `memcpy`, padding via
`memset`, the 64-bit length via one byte-swapped `u64` store, and the 32-byte digest via two
`rev32` + `u32x4` stores instead of ~145 scalar shift/mask/copy writes per verify — `890 →
645 ns`, the single biggest step. The interleave (2) is the *smallest* win, which is the
tell: with only 2 of ~6 blocks independent in a single-message HMAC, latency-hiding has
little to hide — the real cost was always per-byte scalar work.

**Then profiling the whole `verify` (not just the crypto) showed it wasn't crypto-bound at
all** — it split ~50/50 between the HMAC (~312 ns) and the **eager header restore** (~328 ns),
which built an owned `Jws{algorithm, keyId, signature}` — three heap allocations per verify,
`keyId` never even read by the gate. The fix is a **lazy header gate**: the verify-before-parse
gate now receives the zero-alloc header *accessor* (buffer + field positions) and reads
`algorithm`/`signature` as a `StringSlice`/`Span` straight from the buffer (`_view` getters),
so nothing is materialized and `keyId` is skipped. That erased the header half — **verify
`645 → 360 ns`** — and verify is now genuinely HMAC-bound (~91 %). Closing the last bit
would mean `ring`'s multi-buffer hand-scheduled asm — i.e. rebuilding a crypto library —
so we stop there.

The lazy header gate is a **cross-language** change (the gate now receives a zero-alloc
header accessor everywhere), and the win tracks how much each language paid for the header:
**Rust `239 → 196 ns`** (−18 %; its view getters return `&str`/`&[u8]` — fully zero-copy),
**TS `3318 → 3135 ns`** (−6 %; a bespoke positions-scanning view skips the unread `keyId`),
**Odin `297 → 281 ns`** (−5 %; its getters already borrowed, so mostly a cleanup), and
**Swift ~unchanged by the header gate itself** (it was crypto-bound at the time — the
CryptoKit → CommonCrypto swap described above is what later cut its verify to ~800 ns).
Where the header was a real fraction (Mojo, Rust) the gate win is large; where crypto
dominated (Swift, TS) it is small — exactly as the profile predicted.

**TS mint** was separately profiled (serialize was ~88 % of it, ~9.2 µs) and the hand-written
`Builder` rebuilt: it had stored every field as a tiny `number[]` chunk in a `number[][]`
list (hundreds of micro-allocations per token) and concatenated them at the end, with `LEB`
encoding routed through `BigInt`. Rewritten as a **single backward-growing `Uint8Array`**
(direct byte writes, a `number` LEB fast path, cycle late-binding recorded by cursor offset),
it is byte-identical (6007-test suite green) and roughly halves mint: **~10.7 µs → ~5.0 µs**.
**Odin mint** had the same chunk-list writer (`[dynamic][dynamic]u8` — a heap `make` per store
op plus a final concat); rewriting it to a **single backward-growing buffer** (direct writes,
late-bindings patched by cursor offset) took serialize ~1.8 µs → ~0.5 µs and mint **~2.3 µs →
~0.75 µs** (byte-identical; roundtrip/cyclic/aligned Odin suites green).
**Rust mint** was profiled too (`dst profile`): ~870 ns = build-tree ~200 + serialize ~525 +
`ring` HMAC ~158, and ~70 ns of the serialize was the builder's 64 KB `alloc_uninit` —
oversized for a 207 B token. The Direct Graph Builder only ever builds *trees* (spec 31), so
the V62 pointer width is irrelevant; a small initial buffer that grows on demand
(`DagrBuilder::with_capacity`) trimmed serialize to ~460 ns and mint to ~830 ns. Then the
value tree itself was the next ~200 ns: the direct value structs *owned* their data
(`String`/`Vec`), so building the tree did ~13 heap allocations (each literal allocated,
then copied into the buffer). Switching to a **borrowed value API** (`&'a str`/`&'a [u8]`/
`&'a [T]`) makes a literal tree entirely `'static` — **zero allocations to build it**, and
the serializer copies straight from the (contiguous, cache-friendly `.rodata`) slices. That
took build-tree ~200 → ~0 ns and serialize ~460 → ~215 ns: **mint ~830 → ~365 ns**, now
**~2.3× faster than `jsonwebtoken`'s mint** (858 ns) as well as ~6× faster to verify.

TS *verify* was then profiled too: the frozen-packed accessor decoded **every** field in its
constructor — including `scopes` and the whole recursive `custom` JSON tree — even though
verify reads only `expiresAt` + `audience`. Deferring composite fields (arrays / unions /
node-refs) to on-access getters (scalars stay eager) cut verify **~3.1 µs → ~2.2 µs**, now
*below* TS's own `jsonwebtoken` verify.

## Key properties

- **Verify-before-parse.** The signature is checked in the read gate *before* any
  claim is decoded — a forged or tampered token dies before your code touches it.
- **`algorithm` is pinned, not trusted.** The verifier accepts exactly `HS256`; an
  `alg:"none"` token is refused at the gate, sidestepping the classic JWT bypass
  and RS256↔HS256 confusion attacks.
- **Two layers.** Crypto (signature, algorithm) in the gate; semantics (`exp`,
  `aud`) after decode, over the now-trusted body.
- **One wire, every language.** Same schema → identical bytes in Swift, Rust, and
  TypeScript. A Rust service can mint a token a TypeScript client verifies, with no
  interop layer and nothing to canonicalize.

## Language coverage

The token needs the **customizable header** (spec 14, to carry the signature) *and*
**recursive unions under a frozen+packed node** (the freeform `custom` claim). Not
every Dagr target supports that combination yet:

| Language | Header | Recursive packed union | In this repo |
|---|---|---|---|
| Swift | ✅ | ✅ | ✅ |
| Rust | ✅ | ✅ | ✅ |
| TypeScript | ✅ | ✅ | ✅ |
| Mojo | ✅ | ✅ | ✅ |
| Odin | ✅ | ✅ | ✅ |
| Python | ✅ | ✅ | ✅ (via `python-ffi`) |
| Kotlin / Zig | ❌ — no header | — | — |

For Python, **`examples/python-ffi/`** calls the generated Rust codec through a small C ABI
(`ctypes`): byte-identical to the other targets, and faster + 43% smaller than an equivalent
PyJWT token (details in `examples/python-ffi/README.md`).

Two of the shipped targets needed generator work to join:

- **Mojo**: taught the packed codegen to handle a **recursive union array** (`Json`'s
  `array` variant is `[Json?]`) — the reader (lazy view), writer (serde), and eager
  restore now route it through the existing two-section union-array machinery, so it
  compiles and round-trips byte-identically. (Crypto is hand-rolled on the ARMv8 SHA
  intrinsics; file I/O is native — no dependencies.)
- **Odin**: taught the packed codegen the same **recursive union array** variant (read
  + write, coinductively breaking the self-reference through the self-delimiting array/
  union boundaries), added the **spec-14 customizable header** to its value/serde API
  (a flat packed self-sized envelope + `_to_bytes_with_header`/`_from_bytes_with_header`
  with a verify-before-parse gate), and wired **DataGraph emission into `dagr build`**
  (previously only SharedBuffer overlays were emitted). Crypto is Odin's own
  `core:crypto/hmac`.

Those were generator gaps, not format limits — as the remaining ones (Kotlin/Zig
headers) close, adding a target stays a one-line change in `schema.py`'s
`Library(targets=[...])` plus a `dagr build`.

---

*The customizable header, the schema DSL, and the CLI are documented in the Dagr
spec. This repo is a worked example of using them together.*
