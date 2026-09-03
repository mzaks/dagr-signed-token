"""dagr-signed-token — a JWT-shaped signed token, defined once, generated everywhere.

A JWT is `header.payload.signature`: the signature is a MAC over the payload so a
verifier can trust the claims *before* acting on them. This schema reproduces that
with Dagr's customizable header ("14 Customizable Header.md"), Shape A:

  • the CLAIMS live in the graph BODY  (the "payload")
  • a packed HEADER node carries {algorithm, keyId, signature}  (the JOSE envelope)
  • signing happens in the write closure, over a stable (rootOffset, body) preimage
  • verification runs in the READ GATE, which aborts before the body is parsed

`dagr build` emits the reader/writer for every target below from this one file.
Edit here, then run `dagr build`.
"""
from dagr_dsl import t, required, timestamp, Node, UnionType, DataGraph
from dagr_config import Library, Swift, Rust, TypeScript, Python, Mojo, Odin

TOKEN = DataGraph(
    "Token",
    root_type=t.ref("Claims"),
    node_types=[
        # The claims record — the "payload". frozen+packed: a fixed, compact,
        # no-evolution layout. Field names are spelled out in full; Dagr is
        # schema-driven and never stores them on the wire, so long names cost 0 bytes.
        Node("Claims", fields=[
            "subject"   >> t.utf8,                              # "sub" — optional (RFC 7519)
            "issuer"    >> t.utf8,                              # "iss" — optional
            "audience"  >> t.utf8,                              # "aud" — optional
            "issuedAt"  >> t.u64 >> required >> timestamp("s"), # "iat" — unix seconds
            "expiresAt" >> t.u64 >> required >> timestamp("s"), # "exp" — unix seconds, required
            "scopes"    >> t.utf8.array,                        # typed profile claim (OAuth-style)
            "custom"    >> t.ref("Json"),                       # freeform private claims
        ], frozen=True, packed=True),

        # A fixed-shape {key, value} object entry. frozen+packed.
        Node("JsonMember", fields=[
            "key"   >> t.utf8 >> required,
            "value" >> t.ref("Json"),
        ], frozen=True, packed=True),

        # A recursive JSON value for arbitrary private claims. Dynamic by nature
        # (variable-length arrays / arbitrary-key objects), so packed but not frozen.
        UnionType("Json", types=[
            ("string", t.utf8),
            ("number", t.f64),
            ("bool",   t.bool),
            ("array",  t.ref("Json").array_with_optionals),
            ("object", t.ref("JsonMember").array),
        ]),
    ],
    # The JOSE-style envelope: emitted packed + self-sized (spec 14 §5); gets no
    # typeId; evolvable via the packed unknown-field tail. `signature` is filled by
    # the producer's signing closure; `algorithm`/`keyId` let a consumer route first.
    header=Node("Jws", fields=[
        "algorithm" >> t.utf8 >> required,   # e.g. "HS256"
        "keyId"     >> t.utf8,               # optional key id, for rotation
        "signature" >> t.data >> required,   # MAC / signature over (rootOffset, body)
    ]),
    # A token is minted once and never mutated — model the arena as append-only
    # (no delete()/is_valid(), no generation tracking; refs collapse to a bare index).
    # Runtime-only: the wire bytes are identical, so this stays byte-for-byte compatible.
    deletable=False,
)

# Targets = the languages that support BOTH the customizable header (spec 14) AND a
# recursive union under a frozen+packed node: Swift, Rust, TypeScript, Python (Fork A),
# Mojo, and Odin. See README "Language coverage" for why the rest are out:
#   • Kotlin / Zig  — no customizable header yet
library = Library(
    "dagr-signed-token",
    schemas=[TOKEN],
    targets=[
        Swift(out="gen/swift"),
        Rust(out="gen/rust"),
        TypeScript(out="gen/typescript"),
        Python(out="gen/python"),
        Mojo(out="gen/mojo"),
        Odin(out="gen/odin"),
    ],
    wire_format_version=1,
)
