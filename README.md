# dagr-signed-token

A **JWT-shaped signed token**, defined once as a [Dagr](https://codeberg.org/mzaks/dagr) schema
and generated into **ten languages: Rust, Swift, TypeScript, Mojo, Odin, Go, C++, C, Java and
Python** — with a cross-language test that proves every language mints the **byte-for-byte
identical** token and can verify the others'.

> **The generated code is committed.** All ten examples build, run, and cross-verify from
> `gen/`, without installing Dagr. `schema.py` is the single source of truth; to change it,
> install the Dagr CLI (`pip install dagr-cli`, source at
> [codeberg.org/mzaks/dagr](https://codeberg.org/mzaks/dagr)) and run `dagr build`.

A JWT is `header.payload.signature`: the signature is a MAC over the payload, so
a verifier can trust the claims *before* acting on them. This reproduces that with
Dagr's customizable header ([spec 15](https://codeberg.org/mzaks/dagr/src/branch/main/spec/15-customizable-header.md)), **Shape A**:

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
                     (`dagr build` regenerates gen/ from it)
CONTRACT.md          the shared constants every example mints (so buffers match)
gen/                 COMMITTED generated code: gen/{rust,swift,typescript,mojo,odin,go,cpp,c,java,python}/
examples/
  rust/              Cargo bin — path-deps the generated crate; sha256.rs is hand-rolled
  swift/             main.swift + Crypto.swift, compiled against gen/swift sources
                     (HMAC: CommonCrypto on macOS, hand-rolled elsewhere)
  swift-jwt-bench/   standalone SwiftPM package — JWTKit HS256 JWT baseline for the benchmark
  typescript/        demo.ts — imports gen/typescript, HMAC via node:crypto
  mojo/              main.mojo — imports gen/mojo + crypto.mojo, native file I/O
                     crypto.mojo — hand-rolled HMAC-SHA256; the SHA-256 core is picked at
                     comptime: ARMv8 crypto, x86-64 SHA-NI, or a portable scalar fallback
  odin/              main.odin — imports gen/odin + its runtime, HMAC via core:crypto/hmac
  go/                main.go — the generated module (direct builder + header gate), HMAC from
                     Go's standard library
  cpp/               main.cpp — the generated header-only library (arena + lazy reader),
                     HMAC from ../c/hmac_sha256.h
  c/                 main.c — the generated header-only C11 library (arena + lazy reader);
                     hmac_sha256.h — hand-rolled SHA-256/HMAC, self-tested (NIST, RFC 4231)
  java/              Main.java — the generated sources (arena + lazy reader), HMAC via javax.crypto
  python/            demo.py — the generated pure-Python target (it ships its own Dagr runtime),
                     HMAC via hashlib
  python-ffi/        Python over a Rust cdylib (ctypes) — fast, self-contained; see its README
run_cross_lang.sh    (build →) mint in each language → N×N verify → assert byte-identity
run_bench.sh         (build optimized →) 50k-rep mint/verify per language → ns/op table
```

## Prerequisites

The examples build from the **committed** `gen/` — you do **not** need the `dagr` CLI.
You need: `cargo` / `rustc`, `swiftc`, `node` (v22+; the TS demo runs via `npx tsx`),
`pixi` (for Mojo — the example builds against a Mojo pixi environment, locked for
`osx-arm64` and `linux-64`), `odin`, `go` (1.23+), a C11 / C++17 compiler, a JDK 22+ (found
through `JAVA_HOME`, the `PATH`, or Homebrew's `openjdk`), and `python3`.

Rust, Swift, TypeScript, Mojo and Odin build, cross-verify and benchmark on **both macOS-arm64
and Linux-x86_64**. Go, C++, C, Java and pure Python were added later and are cross-verified on
macOS-arm64 so far; they use only their standard libraries and the generated code. The two platform-specific
pieces are handled in-tree and stay dependency-free: Swift's HMAC is CommonCrypto on macOS and
hand-rolled where CommonCrypto does not exist, and Mojo's SHA-256 core is chosen at comptime
(ARMv8 crypto / x86-64 SHA-NI / portable scalar).

## Regenerate the code (optional)

`gen/` is already committed, so this is only needed if you change `schema.py`. Install the
Dagr CLI from PyPI; the `run_*.sh` scripts auto-detect it: if `dagr` is on your PATH they
regenerate `gen/` first, otherwise they use what's committed.

```bash
pip install 'dagr-cli>=2026.11.8'   # or: uv tool install dagr-cli
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

# Mojo (self-contained pixi project in examples/mojo; hand-rolled HMAC + native file I/O;
#       macOS-arm64 and Linux-x86_64)
pixi run --manifest-path examples/mojo/pixi.toml \
  mojo run -I gen/mojo examples/mojo/main.mojo

# Odin (HMAC via core:crypto/hmac). -o:speed: an unoptimized build hits an Odin compiler
# bug (dev-2026-07) that writes the custom claim's later members empty
odin run examples/odin -out:examples/odin/dst-odin -o:speed

# Go
(cd examples/go && go run .)

# C++ and C (header-only; SHA-256/HMAC from examples/c/hmac_sha256.h)
c++ -std=c++17 -O2 -I gen/cpp/include examples/cpp/main.cpp -o examples/cpp/dst-cpp && ./examples/cpp/dst-cpp
cc -std=c11 -O2 -I gen/c/include examples/c/main.c -lm -o examples/c/dst-c && ./examples/c/dst-c

# Java (22+)
javac --release 22 -d examples/java/build $(find gen/java/src/main/java -name '*.java') examples/java/Main.java
java -cp examples/java/build Main

# Python (the pure-Python target; see examples/python-ffi for the Rust codec over ctypes)
python3 examples/python/demo.py
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
  IDENTICAL (207 bytes) — rust == swift == ts == mojo == odin == go == cpp == c == java == python
== [cross-verify] every verifier reads every language's token ==
  rust   verifies rust   : OK
  swift  verifies rust   : OK
  ts     verifies rust   : OK
  … (100 combinations: every one of 10 languages verifies every language's token) …
== ALL GREEN ==
```

## Benchmarks

```bash
./run_bench.sh      # builds each language optimized → 50k-rep mint/verify → table
```

Each language mints + verifies in-process (warm-up + 50k reps, correctness-gated).
The Dagr numbers exercise the **fast path**: arena-free **direct build** ([spec 33](https://codeberg.org/mzaks/dagr/src/branch/main/spec/33-direct-graph-builder.md) —
a value tree straight to bytes, gated byte-identical to the arena) + **zero-alloc
lazy verify** (verify-before-parse, then read fields off the buffer, no restore).
**Rust, Swift, TypeScript, and Python** also bench an **equivalent classic HS256 JWT**
with the same claims via that language's *real* JWT library — **Rust `jsonwebtoken`**,
**Swift `JWTKit`** (Vapor), **TS `jsonwebtoken`**, **Python `PyJWT`** — so the delta isolates
the *format*. **Python** here is a `ctypes` binding over the Rust codec
(`examples/python-ffi`), not an independent implementation. **Rust and Python also bench a
standards-based CWT/COSE** token — the *binary* peer of JWT (RFC 8392 CWT in a RFC 9052
`COSE_Mac0`, HMAC-SHA256) — because that, not base64url JSON, is the honest comparison. Rust
uses a **tuned native** stack (`coset` + `ciborium` + **`ring`**, the same HMAC as its Dagr
row → a fair *efficiency* test); Python uses the **`pycose`** reference library (size-only —
see the CWT note under the table). The Rust Dagr side uses **`ring`**
for HMAC-SHA256 (the same asm crypto `jsonwebtoken` uses, so *that* comparison is
crypto-matched); Swift Dagr uses **CommonCrypto** on macOS and a hand-rolled
SHA-256/HMAC where CommonCrypto is absent (Linux), which costs it ~1.2 µs/op. **Mojo** shows two arena-free build
strategies: **`reflect`** —
serialize straight from a live value struct via comptime reflection, no intermediate tree —
and **`tree`** — a `DirectJson` value tree. Representative run (Apple Silicon, generated with
dagr-cli 2026.11.8; ns/op — ratios, not absolutes):

| lang | impl | mint (ns) | verify (ns) | size (B) |
|---|---|--:|--:|--:|
| rust | dagr | 402 | **206** | **207** |
| rust | jwt (`jsonwebtoken`) | 924 | 1532 | 395 |
| rust | cwt (`coset`) | 1423 | 2066 | **200** |
| swift | dagr | 3159 | **717** | 207 |
| swift | jwt (`JWTKit`) | 24486 | 30391 | 368 |
| ts | dagr | 3233 | 1815 | 207 |
| ts | jwt (`jsonwebtoken`) | 1800 | 2316 | 395 |
| python | dagr (`ctypes`→Rust) | 5164 | 2868 | 207 |
| python | jwt (`PyJWT`) | 6035 | 7963 | 365 |
| python | cwt (`pycose`) | 24244 | 11547 | **200** |
| mojo | dagr (reflect) | 970 | 378 | 207 |
| mojo | dagr (tree) | 1388 | 378 | 207 |
| odin | dagr | 751 | 295 | 207 |
| go | dagr | 858 | 684 | 207 |
| cpp | dagr (arena) | 1028 | 308 | 207 |
| c | dagr (arena) | 1059 | 338 | 207 |
| java | dagr (arena) | 1304 | 488 | 207 |
| python | dagr (pure Python) | 48762 | 38037 | 207 |

**The last five rows** were added with dagr-cli 2026.11.8 and bench Dagr only; no JWT baseline
yet. What they measure, and what their verify time is made of:
- **Go** mints with the direct builder. Its verify is ~245 ns of HMAC (Go's standard library)
  plus ~320 ns for the **validating open**, which walks the whole token once (bounds, depth,
  UTF-8) before the getters read it. Go's lazy getters may panic on malformed bytes by design,
  so a Go reader validates first; Rust's lazy reader is safe on any bytes without a walk.
- **C++ and C** mint through the **arena** (`serialize_with_header`): Dagr's C and C++ direct
  builders don't write a header yet, and the arena path allocates per node. Their HMAC is the
  shared `examples/c/hmac_sha256.h`. It uses the ARMv8 SHA-256 instructions when the compiler
  targets them, which takes the HMAC from ~1,030 to ~290 ns (CommonCrypto: ~380 ns), so the
  read itself is ~20–50 ns of their verify.
- **Java** mints through the arena too, and verifies with `javax.crypto` and the lazy reader
  (JIT warmed with a full round before timing).
- **Pure Python** is the eager, reflective target: verify decodes the whole token. It runs 5k
  reps rather than 50k; the `python` row above it is the Rust codec behind `ctypes`.

The **`cwt`** rows are the load-bearing comparison — CWT/COSE (RFC 8392 / RFC 9052 `COSE_Mac0`,
HMAC-SHA256) is the *binary* peer of JWT, so this, not base64url JSON, is the honest test.
Two takeaways:

- **Size is ~parity.** A standards-exact CWT of the same claims is **200 B** — a hair *under*
  Dagr's 207 B. Against CBOR, Dagr's ~48 % size win over JSON JWT collapses to roughly nothing
  (CBOR already gives integer claim keys and no base64 inflation). Size is where JWT loses to
  both; it is *not* where Dagr beats CWT.
- **Speed is where Dagr wins.** The `rust cwt` row is a **tuned native** stack — `coset`
  (RustCrypto COSE) + `ciborium` + **`ring`**, the *same* HMAC crate as the Dagr row — so it is
  a fair format-vs-format efficiency test at matched crypto. Dagr mints **~3.5× faster** (402 vs
  1423 ns) and verifies **~10× faster** (206 vs 2066 ns). The verify gap is the real story:
  Dagr's **verify-before-parse + zero-alloc lazy read** touches only `algorithm`/`signature`/
  `exp`/`aud`, while the COSE path parses the whole envelope and CBOR-decodes the entire claims
  map into an owned tree before it can check anything. A hand-rolled partial CBOR scan would
  narrow that gap — but *that is the point*: Dagr's lazy typed read falls out of the schema for
  free, whereas with CWT you would hand-write it. (The `python cwt` row uses **`pycose`**, a
  *reference* implementation — a Python object per COSE element — so read its ns/op as a library
  artifact, not a format signal; its **size**, 200 B, is the platform-independent fact.)

Dagr's other durable edges over CWT/COSE: **generator-guaranteed cross-language byte-identity**
(no COSE canonicalization footgun) and **typed field access**. What CWT/COSE has and this token
does not: an IETF standard, asymmetric algorithms, and — since alg lives in the COSE *protected*
header — an algorithm identifier bound *into* the MAC (this token pins HS256 by policy instead).

The same harness on **Linux x86-64** (Ryzen AI 9 HX 370, Node 25, Swift 6.3) — a different
machine *and* different per-language crypto, so read it against itself, not against the table
above. It was measured with the earlier generated code, before Go, C++, C, Java and pure Python
joined, and has not been re-run since:

| lang | impl | mint (ns) | verify (ns) | size (B) |
|---|---|--:|--:|--:|
| rust | dagr | 514 | **283** | **207** |
| rust | jwt (`jsonwebtoken`) | 743 | 1619 | 395 |
| rust | cwt (`coset`) | 1041 | 2327 | **200** |
| swift | dagr | 4090 | 1858 | 207 |
| swift | jwt (`JWTKit`) | 20602 | 24016 | 368 |
| ts | dagr | 12657 | 3039 | 207 |
| ts | jwt (`jsonwebtoken`) | 2699 | 3281 | 395 |
| python | dagr (`ctypes`→Rust) | 5420 | 3656 | 207 |
| python | jwt (`PyJWT`) | 6465 | 8184 | 365 |
| python | cwt (`pycose`) | 24686 | 10549 | **200** |
| mojo | dagr (reflect) | 612 | 447 | 207 |
| mojo | dagr (tree) | 828 | 447 | 207 |
| odin | dagr | 928 | 310 | 207 |

Unlike the table above, these are **medians of repeated runs** — 5 for the compiled targets,
3 for the slower Swift/TS/Python ones. That is worth doing because on this box `mint` is the
noisy half: Odin ranged 820–1120 ns and Rust Dagr 493–536 ns across runs, while every `verify`
held to ~2 % (Rust Dagr 281–289 ns). A single mint sample is the least trustworthy number in
either table; the first run after a build tends to be the worst (a cold `mojo reflect` measured
854 ns against its 612 ns median, briefly inverting its usual lead over the `tree` path).

Sizes are identical, as they must be — the `cwt` rows included, at **200 B** on both machines
(CBOR encoding is deterministic). Those rows now carry Linux **speeds** as well, where they
previously read `—`: the CWT result **survives the platform change but narrows**. Against the
tuned native `coset` + `ciborium` + `ring` stack at matched crypto, Dagr mints **~2× faster**
(514 vs 1041 ns; it is ~3.5× on Apple Silicon) and verifies **~8× faster** (283 vs 2327 ns;
was ~10×). The narrowing is on COSE's side of the ledger — `coset` mints *faster* here than on
the M-series box (1041 vs 1423 ns) while Dagr's mint is a touch slower — so the ratio moved
without the shape changing: near-parity on size, a large multiple on verify, because
verify-before-parse still beats CBOR-decoding the whole claims map before anything can be
checked. One ordering holds on both machines and is easy to miss: `coset`'s CWT verify is
*slower* than `jsonwebtoken`'s JSON verify (2327 vs 1619 ns here). Against JWT, CBOR buys
**size**, not speed. The `python cwt` row tracks its macOS figures closely (24.7 vs 23.2 µs
mint, 10.5 vs 11.1 µs verify), which is the expected result for a reference library whose cost
is a Python object per COSE element — platform barely enters into it.

Two rows move for platform reasons rather than format reasons: **Swift** verify is the
hand-rolled HMAC standing in for CommonCrypto (its SHA-256 compression is ~240 ns/block against
CommonCrypto's asm), and **Mojo** verify (378 → 447 ns) is SHA-NI in place of the ARMv8 crypto
extensions. **TS** mint is ~2.6× slower on this box — a Node/JIT difference, not a codec change.

**What it shows** — the token is **207 B vs a classic JWT's 395 B (~48 % smaller)** in
every language (schema-driven: field names never hit the wire, no base64 33 % inflation;
even against JWTKit's leaner 368 B, Dagr is 44 % smaller). That win is against *JSON*; against
the *binary* peer **CWT/COSE the size is ~parity** (200 vs 207 B), and Dagr's edge moves to
*speed* — vs a tuned native COSE stack (`coset`+`ring`) it mints ~2–3× and verifies ~8–10×
faster at matched crypto (both machines; see the CWT note under the first table), plus
byte-identity and typed reads. On *speed*, the compiled targets' standout
is **verify** — verify-before-parse + zero-alloc lazy read vs base64-decode + full
deserialize. **Rust verifies ~7× faster** than `jsonwebtoken` (206 vs 1532 ns, crypto
matched); **Swift ~42×** faster than JWTKit (717 vs 30 391 ns — see the decomposition below for
where JWTKit's 30 µs goes); **Python (ctypes→Rust) ~2.8×** faster than PyJWT (2868 vs 7963 ns);
**Mojo, Odin, C++ and C** verify in ~300–380 ns. That's the hot path for a token you mint once
and check on every request. **Mint** is more mixed: Rust Dagr mints *faster* than a real JWT
lib (402 vs 924 ns), and Python-over-Rust edges PyJWT (5164 vs 6035 ns); Mojo's reflection
path mints in ~1 µs; Swift
Dagr mint (~3.2 µs) still trails Rust — its **flat claims serialize in ~450 ns, but the
recursive-JSON `custom` claim is ~1.9 µs** (Swift value-semantics + ARC over the generic
`Array`/`indirect enum` store — the next optimization target, see below). In Node, TS Dagr
now verifies faster than `jsonwebtoken` (1815 vs 2316 ns), while Node's native `JSON` still
mints faster than the TS Dagr codec (1800 vs 3233 ns). Dagr's durable wins are **size**, **cross-language byte-identity**, **type-safe lazy
reads**, and **fast verify** in compiled targets.

**Where JWTKit's ~30 µs goes** (the surprise: a *compiled* Swift JWT lib trailing even
interpreted PyJWT). Decomposing `keys.sign`/`keys.verify` on the **Apple Silicon** box of the
first table — the shares below are of *its* ~30 µs verify, not the Linux box's 24 µs (isolate
each cost, 50k reps):

| component | cost | share of verify |
|---|--:|--:|
| HMAC-SHA256 (crypto) | ~1.5 µs | ~5 % |
| Foundation `Codable` JSON, per encode/decode | ~3.5 µs | ~12 % (verify does header **and** payload) |
| async / actor `await` (measured *inline*) | **~8 ns** | ~0 % |
| **remainder** — base64url of 3 segments, `Data` allocs/concats, token split, `JWTKeyCollection` handling | **~20 µs** | **~70 %** |

So it is **not** crypto (~5 %), **not** async (the actor hop is ~8 ns inline — a red herring;
JWTKit's API being `async` costs nothing here), and only partly JSON (~15–25 %). The bulk is
**JWTKit's own per-call Foundation object model** — allocation-heavy `Data`/base64 work, top
to bottom. That is why `jsonwebtoken` (Rust) and PyJWT (thin Python glue over C `json` +
`hashlib`) win: they do the same job with far fewer allocations, PyJWT's heavy lifting being
C. The clincher that it is **not** a Swift-language limit: Dagr's *own* Swift row verifies in
**673 ns** on the same box — the cost is this specific library's model, not the language.

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
  cut verify 1859 → ~800 ns. A later fix to `hmacValid`'s **constant-time compare** — which had
  been indexing `Data` byte-by-byte (`Data`'s subscript re-resolves its backing on each access,
  ~450 ns/verify); reading both sides through `withUnsafeBytes` removed it — took macOS verify a
  further **~800 → ~673 ns** (2389 → 1902 ns on Linux). On mint, the packed presence/encoding byte was built with
  `[Bool].bitSet` — a heap `[Bool]` + `[UInt8]` **per node**; emitting a direct `UInt8` bit-OR
  removed those allocations (universal across all graphs). What remains is the recursive `custom`
  JSON: the generic `Array` store's dynamic type-dispatch + `indirect enum` ARC, which would want
  a codegen-specialized store to close.

**Caveats.** This is deliberately *not* a fair fight (Dagr is a typed binary graph, JWT
is base64url JSON). Crypto differs *across languages* (Rust = `ring` both sides; Mojo
implements SHA-256 natively on **whatever SHA acceleration the target has**, selected at
comptime — the **ARMv8 crypto intrinsics** (`sha256h`/`h2`/`su0`/`su1`) or **x86-64 SHA-NI**
(`sha256rnds2`/`msg1`/`msg2`) via `llvm_intrinsic`, the same hardware `ring` uses, no FFI,
with a portable scalar core where neither exists; Swift = CommonCrypto on macOS and a
hand-rolled SHA-256/HMAC elsewhere, TS = `node:crypto`, Odin = `core:crypto`), so cross-language `verify` times
reflect the platform's crypto, not only the format read. The `jwt` rows likewise aren't
comparable *to each other* — each is a different library architecture — only each to
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
oversized for a 207 B token. The Direct Graph Builder only ever builds *trees* (spec 33), so
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
- **One wire, every language.** Same schema → identical bytes in all ten languages. A Rust
  service can mint a token a Java, Go or TypeScript client verifies, with no interop layer and
  nothing to canonicalize.

## Language coverage

The token needs the **customizable header** (spec 15, to carry the signature) *and*
**recursive unions under a frozen+packed node** (the freeform `custom` claim):

| Language | Header | Recursive packed union | In this repo |
|---|---|---|---|
| Swift | ✅ | ✅ | ✅ |
| Rust | ✅ | ✅ | ✅ |
| TypeScript | ✅ | ✅ | ✅ |
| Mojo | ✅ | ✅ | ✅ |
| Odin | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | ✅ (direct builder + header gate) |
| C++ | ✅ | ✅ | ✅ (arena + lazy reader) |
| C | ✅ | ✅ | ✅ (arena + lazy reader) |
| Java | ✅ | ✅ | ✅ (arena + lazy reader) |
| Python | ✅ | ✅ | ✅ (the pure-Python target, and `python-ffi`) |

C and C++ mint through the arena's `serialize_with_header`: their direct builders don't write a
header yet (the generator says so when it runs). The benchmark tables below cover the first
five languages and the Python FFI; the other five are cross-verified but not benchmarked yet.

For Python, **`examples/python-ffi/`** calls the generated Rust codec through a small C ABI
(`ctypes`): byte-identical to the other targets, and faster + 43% smaller than an equivalent
PyJWT token (details in `examples/python-ffi/README.md`).

Two of the shipped targets needed generator work to join:

- **Mojo**: taught the packed codegen to handle a **recursive union array** (`Json`'s
  `array` variant is `[Json?]`) — the reader (lazy view), writer (serde), and eager
  restore now route it through the existing two-section union-array machinery, so it
  compiles and round-trips byte-identically. (Crypto is hand-rolled on the ARMv8 SHA or
  x86-64 SHA-NI intrinsics, whichever the target has; file I/O is native — no dependencies.)
- **Odin**: taught the packed codegen the same **recursive union array** variant (read
  + write, coinductively breaking the self-reference through the self-delimiting array/
  union boundaries), added the **customizable header** (spec 15) to its value/serde API
  (a flat packed self-sized envelope + `_to_bytes_with_header`/`_from_bytes_with_header`
  with a verify-before-parse gate), and wired **DataGraph emission into `dagr build`**
  (previously only SharedBuffer overlays were emitted). Crypto is Odin's own
  `core:crypto/hmac`.

Those were generator gaps, not format limits. Adding a target is a one-line change in
`schema.py`'s `Library(targets=[...])` plus a `dagr build`, and an example program for it.

---

*The customizable header, the schema DSL, and the CLI are documented in the
[Dagr specs](https://codeberg.org/mzaks/dagr/src/branch/main/spec/README.md). This repo is a worked example of using them together.*
