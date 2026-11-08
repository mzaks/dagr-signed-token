"""Java identifier mapping (spec/45 §5, spec/23).

Types keep their schema spelling (PascalCase); fields become lowerCamelCase getters
(`created_at` → `createdAt()`, record style — spec/45 O-J4); enum cases become UPPER_SNAKE
constants. A Java keyword, a literal (`true`, `null`) or a name that would collide with a
method every class inherits from `Object` gets a trailing `_` (`class_()`, `wait_()`).
Two schema names the mapping cannot separate (`fooBar` beside `foo_bar`, a node `PointAccessor` beside a
node `Point`, a field `is_valid` beside every handle's `isValid()`) are rejected at `validate()`
(`dagr/reserved_names.py` `java_name_collisions`, `RESERVED["java"]`, spec/45 milestone 9) — and, as a
backstop, refused where they are emitted (`Names`).
"""
from __future__ import annotations

import re

JAVA_KEYWORDS = frozenset("""
abstract assert boolean break byte case catch char class const continue default do double else
enum extends final finally float for goto if implements import instanceof int interface long
native new package private protected public return short static strictfp super switch
synchronized this throw throws transient try void volatile while true false null var yield
record sealed permits non-sealed when _
""".split())

#: Methods of java.lang.Object a no-argument getter would override or clash with.
OBJECT_METHODS = frozenset({"hashCode", "toString", "getClass", "notify", "notifyAll", "wait", "clone",
                            "finalize", "equals"})

#: Simple names generated code uses UNQUALIFIED — `java.lang` types and the package roots of the fully
#: qualified ones (`java.lang.foreign.MemorySegment`, `dagr.runtime.Reader`). A schema TYPE spelled like one
#: becomes a nested class that shadows it inside the holder, so `java_type` escapes it (`String_`).
SHADOWED = frozenset({"String", "Object", "Long", "Integer", "Short", "Byte", "Float", "Double", "Boolean",
                      "Character", "Math", "Override", "IllegalArgumentException", "IllegalStateException",
                      "System", "Thread", "java", "dagr"})

_WORD = re.compile(r"[A-Z]+(?=[A-Z][a-z0-9])|[A-Z]?[a-z0-9]+|[A-Z]+")


def _words(name: str) -> list[str]:
    out: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", name):
        out += _WORD.findall(part)
    return out or [name]


def _escape(ident: str, extra=frozenset()) -> str:
    return ident + "_" if ident in JAVA_KEYWORDS or ident in OBJECT_METHODS or ident in extra else ident


def java_member(name: str, extra=frozenset()) -> str:
    """A field's getter: lowerCamelCase, escaped. `extra`: members the generated class owns."""
    words = _words(name)
    ident = words[0].lower() + "".join(w[:1].upper() + w[1:].lower() if w.isupper() else w[:1].upper() + w[1:]
                                      for w in words[1:])
    if ident[:1].isdigit():
        ident = "_" + ident
    return _escape(ident, extra)


#: The package roots generated code qualifies runtime names through (`dagr.runtime.Writer`,
#: `java.lang.foreign.MemorySegment`). A getter METHOD named `dagr()` is harmless, but a FIELD, parameter
#: or local spelled `dagr` shadows the package for the rest of its scope, so `dagr.runtime.Writer` resolves
#: to the field (`cannot find symbol … variable dagr of type String`). Value-class fields and the arena's
#: factory parameters are named through `java_value_field`.
PACKAGE_ROOTS = frozenset({"java", "dagr"})


def java_value_field(name: str) -> str:
    """A field of a plain value class (the direct builder's, a DataSink record's node value) or a
    parameter named after a schema field: `java_member`, with the package roots escaped (`dagr_`)."""
    return java_member(name, PACKAGE_ROOTS)


def java_part(name: str) -> str:
    """A name inside a composed identifier (`has{Part}`): UpperCamelCase, never escaped."""
    m = java_member(name).rstrip("_") or name
    return m[:1].upper() + m[1:]


def java_type(name: str) -> str:
    """A schema type's class name: its own spelling (already PascalCase in every schema), escaped — a
    keyword, or a name generated code uses unqualified (`SHADOWED`), gets a trailing `_`."""
    ident = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if ident[:1].isdigit():
        ident = "_" + ident
    return _escape(ident, SHADOWED)


def java_variant(label: str) -> str:
    """A union variant's nested record (`{U}.{Variant}`): `java_part`, escaped like a type — a variant
    labelled `string` would be a record `String` shadowing `java.lang.String` inside its union."""
    return _escape(java_part(label), SHADOWED)


def java_const(name: str) -> str:
    """An enum case (or a constant): UPPER_SNAKE."""
    ident = "_".join(w.upper() for w in _words(name))
    if ident[:1].isdigit():
        ident = "_" + ident
    return _escape(ident)


class Names:
    """One scope's identifiers: two schema names that map to ONE Java name are refused (a
    ValueError naming both) rather than emitted as a duplicate declaration."""

    def __init__(self, scope: str):
        self.scope = scope
        self.seen: dict[str, str] = {}

    def claim(self, ident: str, what: str) -> str:
        prev = self.seen.get(ident)
        if prev is not None and prev != what:
            raise ValueError(f"Java: {self.scope}: {prev} and {what} both map to `{ident}` — rename one")
        self.seen[ident] = what
        return ident
