#!/usr/bin/env bash
# Cross-language validation for dagr-signed-token.
#
# Uses the COMMITTED gen/ (this repo is self-contained). If the `dagr`
# CLI happens to be on PATH it regenerates gen/ first; otherwise it just uses what's
# committed. Then mints the token in each language, has every language verify every
# language's token (N×N), and asserts the buffers are byte-for-byte identical.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"

if command -v dagr >/dev/null 2>&1; then
  echo "== [gen] dagr build (dagr CLI found — regenerating gen/) =="
  dagr build --schema "$ROOT/schema.py" --receipt "$ROOT/dagr.lock.json"
else
  echo "== [gen] using committed gen/ (dagr CLI not on PATH) =="
fi

echo "== [build] Rust =="
cargo build --quiet --manifest-path examples/rust/Cargo.toml
RUST=(cargo run --quiet --manifest-path examples/rust/Cargo.toml --)

echo "== [build] Swift =="
swiftc -O gen/swift/Sources/dagr_signed_token/*.swift examples/swift/Crypto.swift examples/swift/main.swift -o examples/swift/dst-swift
SWIFT=(./examples/swift/dst-swift)

echo "== [build] TypeScript (tsx, no build step) =="
TS=(npx --yes tsx examples/typescript/demo.ts)

echo "== [build] Mojo (compile once via the local pixi project) =="
# Mojo has no compiler on PATH here; examples/mojo is a self-contained pixi project
# (pins mojo/max — no dependency on any other project's env). Build the example once
# (rather than `mojo run` per call) and run the binary inside that env.
MOJO_PIXI="${MOJO_PIXI:-$ROOT/examples/mojo/pixi.toml}"
pixi run --manifest-path "$MOJO_PIXI" mojo build -I "$ROOT/gen/mojo" \
  "$ROOT/examples/mojo/main.mojo" -o "$ROOT/examples/mojo/dst-mojo"
MOJO=(pixi run --manifest-path "$MOJO_PIXI" "$ROOT/examples/mojo/dst-mojo")

echo "== [build] Odin =="
# The example package imports the generated gen/odin package + its runtime sub-package.
# -o:speed, as run_bench.sh: with Odin dev-2026-07, an unoptimized build (-o:none / -o:minimal)
# writes the `custom` claim's later members empty (167 B instead of 207); every optimized level
# (size, speed, aggressive) is byte-identical to the other languages.
odin build examples/odin -out:examples/odin/dst-odin -o:speed
ODIN=(./examples/odin/dst-odin)

echo "== [build] Go =="
(cd examples/go && go build -o dst-go .)
GO=(./examples/go/dst-go)

echo "== [build] C++ =="
c++ -std=c++17 -O2 -Wall -Wextra -I gen/cpp/include examples/cpp/main.cpp -o examples/cpp/dst-cpp
CPP=(./examples/cpp/dst-cpp)

echo "== [build] C =="
cc -std=c11 -O2 -Wall -Wextra -I gen/c/include examples/c/main.c -lm -o examples/c/dst-c
./examples/c/dst-c test
C=(./examples/c/dst-c)

echo "== [build] Java =="
# A JDK 22+: JAVA_HOME when set, else a `javac` on PATH that runs (macOS ships a stub that
# only says "Unable to locate a Java Runtime"), else Homebrew's keg-only openjdk.
JAVA_BIN="${JAVA_HOME:+$JAVA_HOME/bin/}"
if [ -z "$JAVA_BIN" ] && ! javac -version >/dev/null 2>&1 && [ -x /opt/homebrew/opt/openjdk/bin/javac ]; then
  JAVA_BIN=/opt/homebrew/opt/openjdk/bin/
fi
rm -rf examples/java/build
"${JAVA_BIN}javac" --release 22 -d examples/java/build $(find gen/java/src/main/java -name '*.java') examples/java/Main.java
JAVA=("${JAVA_BIN}java" -cp examples/java/build Main)

echo "== [build] Python (pure-Python target, no build step) =="
PY=(python3 examples/python/demo.py)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Language name → command array (bash: use nameref-free indirection via functions).
emit_rust()   { "${RUST[@]}"   emit   "$1"; }
emit_swift()  { "${SWIFT[@]}"  emit   "$1"; }
emit_ts()     { "${TS[@]}"     emit   "$1"; }
emit_mojo()   { "${MOJO[@]}"   emit   "$1"; }
emit_odin()   { "${ODIN[@]}"   emit   "$1"; }
emit_go()     { "${GO[@]}"     emit   "$1"; }
emit_cpp()    { "${CPP[@]}"    emit   "$1"; }
emit_c()      { "${C[@]}"      emit   "$1"; }
emit_java()   { "${JAVA[@]}"   emit   "$1"; }
emit_python() { "${PY[@]}"     emit   "$1"; }
verify_rust()   { "${RUST[@]}"   verify "$1"; }
verify_swift()  { "${SWIFT[@]}"  verify "$1"; }
verify_ts()     { "${TS[@]}"     verify "$1"; }
verify_mojo()   { "${MOJO[@]}"   verify "$1"; }
verify_odin()   { "${ODIN[@]}"   verify "$1"; }
verify_go()     { "${GO[@]}"     verify "$1"; }
verify_cpp()    { "${CPP[@]}"    verify "$1"; }
verify_c()      { "${C[@]}"      verify "$1"; }
verify_java()   { "${JAVA[@]}"   verify "$1"; }
verify_python() { "${PY[@]}"     verify "$1"; }

LANGS=(rust swift ts mojo odin go cpp c java python)

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
