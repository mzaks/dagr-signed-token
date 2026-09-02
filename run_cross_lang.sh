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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Language name → command array (bash: use nameref-free indirection via functions).
emit_rust()  { "${RUST[@]}"  emit   "$1"; }
emit_swift() { "${SWIFT[@]}" emit   "$1"; }
emit_ts()    { "${TS[@]}"    emit   "$1"; }
verify_rust()  { "${RUST[@]}"  verify "$1"; }
verify_swift() { "${SWIFT[@]}" verify "$1"; }
verify_ts()    { "${TS[@]}"    verify "$1"; }

echo
echo "== [emit] each language mints its token =="
emit_rust  "$WORK/rust.bin"
emit_swift "$WORK/swift.bin"
emit_ts    "$WORK/ts.bin"

echo
echo "== [byte-identity] all three minted tokens must be identical =="
SIZE=$(wc -c < "$WORK/rust.bin" | tr -d ' ')
if cmp -s "$WORK/rust.bin" "$WORK/swift.bin" && cmp -s "$WORK/rust.bin" "$WORK/ts.bin"; then
  echo "  IDENTICAL ($SIZE bytes) — rust == swift == ts"
else
  echo "  MISMATCH!"
  for f in rust swift ts; do echo "    $f: $(wc -c < "$WORK/$f.bin" | tr -d ' ') bytes"; done
  exit 1
fi

echo
echo "== [cross-verify] every verifier reads every language's token =="
for producer in rust swift ts; do
  for verifier in rust swift ts; do
    printf '  %-6s verifies %-6s :' "$verifier" "$producer"
    "verify_$verifier" "$WORK/$producer.bin" >/dev/null && echo " OK" || { echo " FAIL"; exit 1; }
  done
done

echo
echo "== ALL GREEN =="
