#!/usr/bin/env bash
# Cross-language validation for dagr-web-token.
#
# Regenerates the code with `dagr build`, then mints the token in each language,
# has every language verify every language's token (N×N), and asserts the minted
# buffers are byte-for-byte identical. One schema → identical wire in all targets.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"

echo "== [gen] dagr build =="
dagr build --schema "$ROOT/schema.py" --receipt "$ROOT/dagr.lock.json"

echo "== [build] Rust =="
cargo build --quiet --manifest-path examples/rust/Cargo.toml
RUST=(cargo run --quiet --manifest-path examples/rust/Cargo.toml --)

echo "== [build] Swift =="
swiftc -O gen/swift/Sources/dagr_web_token/*.swift examples/swift/Crypto.swift examples/swift/main.swift -o examples/swift/dwt-swift
SWIFT=(./examples/swift/dwt-swift)

echo "== [build] TypeScript (tsx, no build step) =="
TS=(npx --yes tsx examples/typescript/demo.ts)

echo "== [build] Python (pure-Python, no build step) =="
PYTHON=(python3 examples/python/demo.py)

echo "== [build] Mojo (compile once via pixi) =="
# Mojo has no compiler on PATH here; use the RethinkingDagrMojo pixi env. Build the
# example once (rather than `mojo run` per call) and run the binary inside that env.
MOJO_PIXI="${MOJO_PIXI:-/Users/mzaks_pro/dev/RethinkingDagr/RethinkingDagrMojo/pixi.toml}"
pixi run --manifest-path "$MOJO_PIXI" mojo build -I "$ROOT/gen/mojo" \
  "$ROOT/examples/mojo/main.mojo" -o "$ROOT/examples/mojo/dwt-mojo"
MOJO=(pixi run --manifest-path "$MOJO_PIXI" "$ROOT/examples/mojo/dwt-mojo")

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Language name → command array (bash: use nameref-free indirection via functions).
emit_rust()   { "${RUST[@]}"   emit   "$1"; }
emit_swift()  { "${SWIFT[@]}"  emit   "$1"; }
emit_ts()     { "${TS[@]}"     emit   "$1"; }
emit_python() { "${PYTHON[@]}" emit   "$1"; }
emit_mojo()   { "${MOJO[@]}"   emit   "$1"; }
verify_rust()   { "${RUST[@]}"   verify "$1"; }
verify_swift()  { "${SWIFT[@]}"  verify "$1"; }
verify_ts()     { "${TS[@]}"     verify "$1"; }
verify_python() { "${PYTHON[@]}" verify "$1"; }
verify_mojo()   { "${MOJO[@]}"   verify "$1"; }

LANGS=(rust swift ts python mojo)

echo
echo "== [emit] each language mints its token =="
for l in "${LANGS[@]}"; do "emit_$l" "$WORK/$l.bin"; done

echo
echo "== [byte-identity] all minted tokens must be identical =="
SIZE=$(wc -c < "$WORK/rust.bin" | tr -d ' ')
ok=1
for l in "${LANGS[@]}"; do cmp -s "$WORK/rust.bin" "$WORK/$l.bin" || ok=0; done
if [ "$ok" = 1 ]; then
  echo "  IDENTICAL ($SIZE bytes) — $(IFS=' == '; echo "${LANGS[*]}" | sed 's/ / == /g')"
else
  echo "  MISMATCH!"
  for l in "${LANGS[@]}"; do echo "    $l: $(wc -c < "$WORK/$l.bin" | tr -d ' ') bytes"; done
  exit 1
fi

echo
echo "== [cross-verify] every verifier reads every language's token =="
for producer in "${LANGS[@]}"; do
  for verifier in "${LANGS[@]}"; do
    printf '  %-6s verifies %-6s :' "$verifier" "$producer"
    "verify_$verifier" "$WORK/$producer.bin" >/dev/null && echo " OK" || { echo " FAIL"; exit 1; }
  done
done

echo
echo "== ALL GREEN =="
