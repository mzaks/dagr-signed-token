# python-ffi — Python over the Rust codec (ctypes)

A **fast, self-contained** Python binding: instead of the pure-Python reflective codec
(which needs the closed-source `dagr_dsl` at runtime and runs ~60 µs/op), Python calls
straight into the **generated Rust codec** through a tiny C ABI.

- `dagr_token_ffi/` — a `cdylib` crate that path-deps the committed `gen/rust` (no `dagr`
  CLI, no extra crates) and exports a flat C ABI: `dagr_token_mint`, `dagr_token_verify`,
  `dagr_token_get` (path query), `dagr_free`. `mint`/`verify` are the demo's arena builder +
  verify-before-parse gate; `get` is the lazy path-query cursor.
- `dagr_token.py` — a ~120-line `ctypes` shim: `mint`, `verify`, and `open()` → a `Claims`
  view whose registered fields are typed properties and whose freeform `custom` claim is a
  lazy path view (`c.custom["roles"][0].value()`), each read touching only its bytes.
- `demo.py` — mint → 5 verify outcomes → path-query reads, with correctness asserts.

## Build + run

```bash
cargo build --release --manifest-path examples/python-ffi/dagr_token_ffi/Cargo.toml
python3 examples/python-ffi/demo.py
```

## What it shows

- **Byte-identical**: the minted token is the same 207 bytes as Rust/Swift/TS/Mojo/Odin.
- **Fast**: ~4.8 µs mint / ~2.9 µs verify here — ~13–17× the pure-Python codec (the residual
  over raw Rust ~0.5/0.2 µs is the ctypes marshaling per call).
- **Path query, not full decode**: `verify` is the crypto gate only; reads are pinpoint
  (`c.expires_at`, `c.custom["mfa"].value()`) — no dict/JSON materialization.
- **Self-contained**: the cdylib is generated Rust output with no closed-source runtime
  dependency, so — unlike the reflective Fork-A target — this Python path can ship publicly.

This is a hand-written stand-in for what a `dagr build --target python-ffi` would emit
(the C ABI + the ctypes shim), sketched in the repo's design notes.
