"""C++ identifier mapping — spec/41-cpp-codegen-plan.md §12, spec/23-identifier-mapping.md.

  types          keep the schema's PascalCase             Person, SpanKind
  members        snake_case (getters, value-struct fields) name(), start_time_unix_nano()
  enum cases,    PascalCase with an ALL_CAPS part           SpanKind::SpanKindServer
  union labels   title-cased (Rust's `_rust_variant`)
  namespaces     snake_case, [a-z0-9_]

A name that lands on a keyword or a likely macro gets a trailing underscore
(`dagr/codegen/cfamily.py`); C++ has no raw-identifier syntax. Byte-neutral: identifier
spelling never affects the wire.
"""
from __future__ import annotations
import re

from dagr.codegen.cfamily import escape_ident
from dagr.codegen.shared import _snake, _rust_variant

#: Members every generated accessor has. A schema field that maps onto one is rejected by
#: the generator here, and at `validate()` once `RESERVED["cpp"]` lands (milestone 9).
ACCESSOR_MEMBERS = frozenset({"buffer_pos", "buffer_bytes"})


def cpp_type(name: str) -> str:
    """A schema Node / Enum / UnionType name as a C++ type name."""
    return escape_ident(name)


def cpp_member(name: str) -> str:
    """A schema field name as a getter / value-struct member: snake_case."""
    return escape_ident(_snake(name))


def cpp_part(name: str) -> str:
    """`name` as the STEM of a composed identifier — `set_{f}`, `clear_{f}`, `new_{n}`,
    `{n}_store_`, `restore_{n}`, …: snake_case, NOT escaped (a keyword cannot survive a
    prefix or a suffix), runs of underscores collapsed and none at either end — so that no
    composition ever holds a double underscore, which C++ reserves to the implementation
    (`typeid` composed from its escaped spelling `typeid_` gave `typeid__store_`)."""
    out = re.sub(r"_+", "_", _snake(name)).strip("_")
    return out or "x"


def cpp_member_suffixed(name: str, suffix: str) -> str:
    """The member `{f}{suffix}` derived from field `name` (`{f}_view`, `{f}_blob`): the
    suffix joins the field's snake_case spelling BEFORE escaping, so a keyword field does
    not end in `register__view` (a double underscore is reserved to the implementation)."""
    return escape_ident(_snake(name) + suffix)


def cpp_case(name: str) -> str:
    """An enum case or union label as an enumerator: PascalCase, ALL_CAPS title-cased."""
    out = _rust_variant(name)
    if out and out[0].isdigit():            # `2d` → `_2d`; not reserved inside a namespace
        out = "_" + out
    return escape_ident(out)


def cpp_namespace(name: str) -> str:
    """A library / graph name as one namespace component."""
    out = re.sub(r"[^0-9a-z_]", "_", _snake(name))
    if not out or out[0].isdigit():
        out = "_" + out
    return escape_ident(out)


def accessor(name: str) -> str:
    """The lazy accessor class of node `name`."""
    return f"{cpp_type(name)}Accessor"
