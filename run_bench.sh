#!/usr/bin/env bash
# Benchmark harness for dagr-signed-token.
#
# Builds each language OPTIMIZED, runs its in-process `bench` (warm-up + 50k reps of
# mint & verify, correctness-gated), and tabulates ns/op + token size. Four languages
# (Rust/Swift/TS/Python) also bench an equivalent classic HS256 JWT via that language's
# real JWT library (jsonwebtoken / JWTKit / jsonwebtoken / PyJWT), same claims, for a
# size + speed comparison. (Python is a ctypes binding over the Rust cdylib; Swift's JWTKit
# baseline is a standalone SwiftPM package under examples/swift-jwt-bench — both keep the
# demo/cross-lang builds zero-dep.)
#
# CAVEATS (read before drawing conclusions):
#  • Not a fair JWT fight, by design — Dagr is a typed binary graph with cross-language
#    byte-identity + verify-before-parse; JWT is base64url JSON. The size gap is the
#    honest headline; speed is runtime/crypto-dependent.
#  • Crypto differs per language (Rust/Mojo hand-roll SHA-256; Swift=CommonCrypto,
#    TS=node:crypto, Odin=core:crypto). So verify time reflects the platform's crypto too,
#    not just the format read.
#  • JWT-lib overheads differ too: JWTKit (Swift) is async + BoringSSL HMAC, jsonwebtoken
#    (Rust/TS) is sync native, PyJWT is pure Python — so the `jwt` rows aren't comparable to
#    each other, only each to its own language's `dagr` row.
#  • Numbers are wall-clock ns/op on THIS machine; treat as ratios, not absolutes.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"

if command -v dagr >/dev/null 2>&1; then
  echo "== [gen] dagr build (closed-source CLI found — regenerating gen/) =="
  dagr build --schema "$ROOT/schema.py" --receipt "$ROOT/dagr.lock.json" >/dev/null
else
  echo "== [gen] using committed gen/ (dagr CLI not on PATH) =="
fi

echo "== [build] optimized binaries =="
# `bench` feature: RustCrypto HMAC for Dagr (real-crypto) + the `jsonwebtoken` crate as
# the JWT baseline (proper real-world lib). Off by default → the demo stays zero-dep.
cargo build --release --quiet --features bench --manifest-path examples/rust/Cargo.toml
RUST=(./examples/rust/target/release/dst)
swiftc -O gen/swift/Sources/dagr_signed_token/*.swift examples/swift/Crypto.swift examples/swift/main.swift -o examples/swift/dst-swift
SWIFT=(./examples/swift/dst-swift)
# Swift JWT baseline = Vapor's JWTKit (real lib, like Rust/TS jsonwebtoken). Own SwiftPM
# package so the demo/cross-lang Swift build above stays zero-dep (plain swiftc).
swift build --package-path examples/swift-jwt-bench -c release >/dev/null
SWIFT_JWT=(./examples/swift-jwt-bench/.build/release/swift-jwt-bench)
TS=(npx --yes tsx examples/typescript/demo.ts)
MOJO_PIXI="${MOJO_PIXI:-$ROOT/examples/mojo/pixi.toml}"
pixi run --manifest-path "$MOJO_PIXI" mojo build -I "$ROOT/gen/mojo" \
  "$ROOT/examples/mojo/main.mojo" -o "$ROOT/examples/mojo/dst-mojo" >/dev/null
MOJO=(pixi run --manifest-path "$MOJO_PIXI" "$ROOT/examples/mojo/dst-mojo")
odin build examples/odin -out:examples/odin/dst-odin -o:speed
ODIN=(./examples/odin/dst-odin)
# Python = a ctypes binding over the Rust cdylib; PyJWT is its classic-JWT baseline, set up
# best-effort in a cached bench-only venv (skipped, with just the dagr row, if unavailable).
cargo build --release --quiet --manifest-path examples/python-ffi/dagr_token_ffi/Cargo.toml
PYFFI=(python3 examples/python-ffi/bench.py)
PYVENV="$ROOT/examples/python-ffi/.bench-venv"
[ -x "$PYVENV/bin/python" ] || python3 -m venv "$PYVENV" >/dev/null 2>&1 || true
if [ -x "$PYVENV/bin/python" ]; then
  "$PYVENV/bin/python" -c "import jwt" 2>/dev/null || "$PYVENV/bin/pip" install -q pyjwt >/dev/null 2>&1 || true
  "$PYVENV/bin/python" -c "import jwt" 2>/dev/null && PYFFI=("$PYVENV/bin/python" examples/python-ffi/bench.py)
fi

bench_rust()   { "${RUST[@]}"   bench; }
bench_swift()  { "${SWIFT[@]}"  bench; "${SWIFT_JWT[@]}"; }   # dagr + JWTKit baseline
bench_ts()     { "${TS[@]}"     bench; }
bench_python() { "${PYFFI[@]}"; }                            # dagr (ctypes→Rust) + PyJWT baseline
bench_mojo()   { "${MOJO[@]}"   bench; }
bench_odin()   { "${ODIN[@]}"   bench; }

LANGS=(rust swift ts python mojo odin)
OUT="$(mktemp)"; trap 'rm -f "$OUT"' EXIT

echo
echo "== [run] mint + verify (50k reps each, ns/op) =="
for l in "${LANGS[@]}"; do
  printf '  %-6s …\n' "$l"
  "bench_$l" | grep '^BENCH' >> "$OUT" || { echo "  $l FAILED"; exit 1; }
done

echo
awk '
  BEGIN { printf "  %-7s %-5s %10s %10s %8s\n", "lang", "impl", "mint(ns)", "verify(ns)", "size(B)";
          printf "  %-7s %-5s %10s %10s %8s\n", "-------", "-----", "--------", "----------", "-------" }
  { split($4,a,"="); split($5,b,"="); split($6,c,"=");
    printf "  %-7s %-5s %10d %10d %8d\n", $2, $3, a[2], b[2], c[2] }
' "$OUT"

echo
echo "== [size] Dagr vs classic JWT =="
awk '$3=="dagr"{d[$2]=$6} $3=="jwt" && j==""{j=$6}
  END { split(j,jj,"="); for (l in d) { split(d[l],dd,"="); ds=dd[2]; js=jj[2]; break }
        printf "  Dagr token: %d B   |   classic JWT: %d B   →  Dagr is %.0f%% smaller\n", ds, js, (1-ds/js)*100 }
' "$OUT"

echo
echo "== DONE =="
