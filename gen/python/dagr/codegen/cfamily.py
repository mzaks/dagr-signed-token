"""What C and C++ spell identically (spec/41-cpp-codegen-plan.md §0.4, §8.10, §12).

The C++ emitters import this; a C emitter would too. Everything here is about SPELLING a
value or an identifier in source text — literals that reproduce a value bit for bit, string
literals that survive every `-std`, and the identifiers a program may not use.
"""
from __future__ import annotations
import math
import struct

# ── Identifiers ────────────────────────────────────────────────────────────────

#: C keywords (C99 + C11 + C23) — all of them are also unusable in C++.
C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
    "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
    "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch",
    "typedef", "union", "unsigned", "void", "volatile", "while",
    "alignas", "alignof", "bool", "constexpr", "false", "nullptr", "static_assert",
    "thread_local", "true", "typeof", "typeof_unqual",
})

#: C++ keywords through C++23, including the alternative operator tokens (`and`, `not`, …),
#: which are keywords in C++ and macros in C's <iso646.h>.
CPP_KEYWORDS = C_KEYWORDS | frozenset({
    "and", "and_eq", "asm", "bitand", "bitor", "catch", "char8_t", "char16_t", "char32_t",
    "class", "compl", "concept", "const_cast", "consteval", "constinit", "co_await",
    "co_return", "co_yield", "decltype", "delete", "dynamic_cast", "explicit", "export",
    "friend", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "operator", "or",
    "or_eq", "private", "protected", "public", "reinterpret_cast", "requires",
    "static_cast", "template", "this", "throw", "try", "typeid", "typename", "using",
    "virtual", "wchar_t", "xor", "xor_eq",
    # contextual, but a member or type spelled like one reads as a bug
    "final", "override", "import", "module",
})

#: Identifiers some header is likely to have turned into a MACRO. The generator emits no
#: macro, but it cannot stop <cerrno>, <cstdio>, <cassert>, a GNU dialect (`linux`, `unix`
#: are predefined to 1 under -std=gnu++NN, GCC's default) or <windows.h> from defining
#: one, and a macro rewrites an identifier wherever it appears.
#:
#: Deliberately NOT here: `min` / `max` (function-like macros of <windows.h>). They are
#: common field names (OTLP's histogram has both), `NOMINMAX` is the standard remedy, and
#: MSVC is out of this pass (spec/41 O-X5). Same for `major` / `minor`, which glibc stopped
#: leaking through <sys/types.h> in 2.28.
MACRO_HAZARDS = frozenset({
    "NULL", "EOF", "errno", "assert", "stdin", "stdout", "stderr",
    "NAN", "INFINITY", "HUGE_VAL", "OVERFLOW", "UNDERFLOW", "DOMAIN",
    "linux", "unix", "i386", "BSD", "TRUE", "FALSE",
    "ERROR", "DELETE", "IN", "OUT", "near", "far", "small", "interface",
})


def escape_ident(name: str, reserved=frozenset()) -> str:
    """`name`, made safe to use as an identifier in C or C++: a keyword, a macro hazard or
    a member of `reserved` gets a trailing underscore (there is no raw-identifier syntax);
    a double underscore — reserved to the implementation anywhere in an identifier — is
    collapsed, and so is a leading underscore before a capital (reserved too): `_Foo`
    becomes `Foo_`."""
    while "__" in name:
        name = name.replace("__", "_")
    if len(name) > 1 and name[0] == "_" and name[1].isupper():
        return name[1:] + "_"
    if name in CPP_KEYWORDS or name in MACRO_HAZARDS or name in reserved:
        return name + "_"
    return name


# ── Integer literals ───────────────────────────────────────────────────────────

_INT_BOUNDS = {
    "u8": (0, 2**8 - 1), "u16": (0, 2**16 - 1), "u32": (0, 2**32 - 1), "u64": (0, 2**64 - 1),
    "i8": (-2**7, 2**7 - 1), "i16": (-2**15, 2**15 - 1), "i32": (-2**31, 2**31 - 1),
    "i64": (-2**63, 2**63 - 1),
}


def int_literal(kind: str, v: int) -> str:
    """A bare integer constant expression of value `v` that is valid for a variable of
    Dagr kind `kind`, with no implicit-conversion warning when it initialises one.

    The minimum of a signed type has no literal: `-9223372036854775808` is unary minus
    applied to a constant that fits no signed type. It is spelled `(-MAX - 1)`."""
    lo, hi = _INT_BOUNDS[kind]
    if not lo <= v <= hi:
        raise ValueError(f"{v} does not fit {kind}")
    if kind == "u64":
        return f"{v}ULL"
    if kind == "i64":
        return f"(-{hi}LL - 1)" if v == lo else f"{v}LL"
    if kind == "u32":
        return f"{v}U"
    if kind == "i32":
        return f"(-{hi} - 1)" if v == lo else str(v)
    return str(v)


# ── Floating-point literals ────────────────────────────────────────────────────

def float_literal(kind: str, v: float) -> str:
    """A C++17 expression whose value is exactly `v` as a `float` (kind f32, f16, bf16 —
    their API type) or a `double` (f64). Finite values are hex-float literals, which name
    the bits; the non-finite ones have no literal and go through `std::numeric_limits`
    (the caller includes <limits>)."""
    single = kind != "f64"
    ty = "float" if single else "double"
    if math.isnan(v):
        return f"std::numeric_limits<{ty}>::quiet_NaN()"
    if math.isinf(v):
        return ("-" if v < 0 else "") + f"std::numeric_limits<{ty}>::infinity()"
    if single:
        v = struct.unpack("<f", struct.pack("<f", v))[0]      # the float the wire holds
    if v == 0.0:
        lit = "-0.0" if math.copysign(1.0, v) < 0 else "0.0"
    else:
        lit = float(v).hex()                                   # 0x1.8p+0 — exact by construction
    return lit + ("f" if single else "")


def c_float_literal(kind: str, v: float) -> str:
    """`float_literal` for C: the non-finite values are `<math.h>`'s INFINITY / NAN (a float
    constant expression, exact as a float and as a double) — there is no std::numeric_limits."""
    if math.isnan(v):
        return "NAN"
    if math.isinf(v):
        return "-INFINITY" if v < 0 else "INFINITY"
    return float_literal(kind, v)


# ── String and byte literals ───────────────────────────────────────────────────

_PRINTABLE = set(range(0x20, 0x7f)) - {ord('"'), ord("\\"), ord("?")}


def str_literal(data) -> str:
    """A narrow string literal holding exactly the bytes of `data` (a str is taken as
    UTF-8), valid and identical under every `-std`:

    * non-printable and non-ASCII bytes are `\\xNN` escapes — never `u8""`, whose element
      type changed in C++20, and never raw source characters, whose encoding is the
      compiler's business;
    * a hex escape swallows every following hex digit, so the literal is split
      (`"\\x41" "B"`) wherever the next character would extend one;
    * `?` is always escaped, so no `??x` trigraph can form.

    The literal has a terminating NUL the bytes do not; callers that need the length pass
    it explicitly (`std::string_view(lit, n)`), which also keeps embedded NULs."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    out, after_hex = ['"'], False
    for b in raw:
        if b in _PRINTABLE:
            ch = chr(b)
            if after_hex and ch in "0123456789abcdefABCDEF":
                out.append('" "')
            out.append(ch)
            after_hex = False
        elif b == ord('"'):
            out.append('\\"')
            after_hex = False
        elif b == ord("\\"):
            out.append("\\\\")
            after_hex = False
        elif b == ord("?"):
            out.append("\\?")
            after_hex = False
        else:
            out.append(f"\\x{b:02x}")
            after_hex = True
    out.append('"')
    return "".join(out)


def byte_list(data: bytes) -> str:
    """`0x01, 0x02, …` — the elements of a byte-array initialiser."""
    return ", ".join(f"0x{b:02x}" for b in data)
