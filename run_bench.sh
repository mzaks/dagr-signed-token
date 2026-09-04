#!/usr/bin/env bash
# Benchmark harness for dagr-signed-token.
#
# Builds each language OPTIMIZED, runs its in-process `bench` (warm-up + 50k reps of
# mint & verify, correctness-gated), and tabulates ns/op + token size. Three languages
# (Rust/TS/Python) also bench an equivalent classic HS256 JWT (same claims, same HMAC)
# for a size + speed comparison.
#
# CAVEATS (read before drawing conclusions):
#  • Not a fair JWT fight, by design — Dagr is a typed binary graph with cross-language
#    byte-identity + verify-before-parse; JWT is base64url JSON. The size gap is the
#    honest headline; speed is runtime/crypto-dependent.
#  • Crypto differs per language (Rust/Mojo hand-roll scalar SHA-256; Swift=CryptoKit,
#    TS=node:crypto, Python=hashlib, Odin=core:crypto). So verify time reflects the
#    platform's crypto too, not just the format read.
#  • Numbers are wall-clock ns/op on THIS machine; treat as ratios, not absolutes.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"

echo "== [gen] dagr build =="
dagr build --schema "$ROOT/schema.py" --receipt "$ROOT/dagr.lock.json" >/dev/null

echo "== [build] optimized binaries =="
cargo build --release --quiet --manifest-path examples/rust/Cargo.toml
RUST=(./examples/rust/target/release/dst)
swiftc -O gen/swift/Sources/dagr_signed_token/*.swift examples/swift/Crypto.swift examples/swift/main.swift -o examples/swift/dst-swift
SWIFT=(./examples/swift/dst-swift)
TS=(npx --yes tsx examples/typescript/demo.ts)
PYTHON=(python3 examples/python/demo.py)
MOJO_PIXI="${MOJO_PIXI:-$ROOT/examples/mojo/pixi.toml}"
pixi run --manifest-path "$MOJO_PIXI" mojo build -I "$ROOT/gen/mojo" \
  "$ROOT/examples/mojo/main.mojo" -o "$ROOT/examples/mojo/dst-mojo" >/dev/null
MOJO=(pixi run --manifest-path "$MOJO_PIXI" "$ROOT/examples/mojo/dst-mojo")
odin build examples/odin -out:examples/odin/dst-odin -o:speed
ODIN=(./examples/odin/dst-odin)

bench_rust()   { "${RUST[@]}"   bench; }
bench_swift()  { "${SWIFT[@]}"  bench; }
bench_ts()     { "${TS[@]}"     bench; }
bench_python() { "${PYTHON[@]}" bench; }
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
awk '$3=="dagr"{d[$2]=$6} $3=="jwt"{j=$6}
  END { split(j,jj,"="); for (l in d) { split(d[l],dd,"="); ds=dd[2]; js=jj[2]; break }
        printf "  Dagr token: %d B   |   classic JWT: %d B   →  Dagr is %.0f%% smaller\n", ds, js, (1-ds/js)*100 }
' "$OUT"

echo
echo "== DONE =="
