"""dagr-signed-token — Python binding over the Rust cdylib (ctypes).

Python calls straight into the generated Dagr codec for mint/verify/read, so it's
~native speed and byte-identical to the other targets — and self-contained (the cdylib
path-deps the committed gen/rust; no closed-source dagr CLI at runtime, unlike Fork A).

    tok = mint(secret, exp)                 # -> 207-byte token
    verify(tok, secret, now)                # raises Rejected on any failure
    c = open(tok, secret, now)              # verify, then a path-query view
    c.expires_at ; c.subject ; c.audience   # typed registered claims
    c.scopes[0].value() ; len(c.scopes)
    c.custom["roles"][0].value()            # freeform claim, pinpoint read
"""
import ctypes, os, sys
from ctypes import (c_uint8, c_uint64, c_size_t, c_int32, c_int64, c_double,
                    c_char_p, POINTER, byref, string_at, cast, Structure)

class _Str(Structure):   _fields_ = [("ptr", POINTER(c_uint8)), ("len", c_size_t)]
class _Bytes(Structure): _fields_ = [("ptr", POINTER(c_uint8)), ("len", c_size_t)]
class _Val(Structure):   _fields_ = [("kind", c_int32), ("num", c_uint64), ("bytes", _Bytes)]

def _load():
    ext = {"darwin": "dylib", "win32": "dll"}.get(sys.platform, "so")
    here = os.path.dirname(os.path.abspath(__file__))
    return ctypes.CDLL(os.path.join(here, "dagr_token_ffi", "target", "release",
                                    f"libdagr_token_ffi.{ext}"))
_lib = _load()
_lib.dagr_token_mint.restype    = c_int32
_lib.dagr_token_mint.argtypes   = [_Str, _Str, c_uint64, POINTER(_Bytes)]
_lib.dagr_token_verify.restype  = c_int32
_lib.dagr_token_verify.argtypes = [_Str, _Str, c_uint64]
_lib.dagr_token_get.restype     = c_int32
_lib.dagr_token_get.argtypes    = [_Str, c_char_p, POINTER(_Val)]
_lib.dagr_free.argtypes         = [_Bytes]

_CODES = {1: "bad_alg", 2: "bad_signature", 3: "expired", 4: "wrong_audience", 5: "malformed"}
class Rejected(Exception): pass

_ABSENT, _STR, _BYTES, _U64, _I64, _F64, _BOOL, _ARRAY, _OBJECT = range(9)

def _str(x, keep):                          # bytes|str|None -> borrowed _Str (keep holds it alive)
    if x is None: return _Str(None, 0)
    b = x.encode() if isinstance(x, str) else bytes(x)
    keep.append(b)
    return _Str(cast(c_char_p(b), POINTER(c_uint8)), len(b))

def _take(b: _Bytes) -> bytes:              # copy out an owned buffer, then free it
    data = string_at(b.ptr, b.len) if b.ptr else b""
    _lib.dagr_free(b)
    return data

def _coerce(v: _Val):
    k = v.kind
    if k == _ABSENT: return None
    if k in (_STR, _BYTES):
        raw = _take(v.bytes)
        return raw.decode() if k == _STR else raw
    if k == _U64:  return int(v.num)
    if k == _I64:  return c_int64(v.num).value
    if k == _F64:  return c_double.from_buffer_copy(c_uint64(v.num)).value
    if k == _BOOL: return bool(v.num)
    if k in (_ARRAY, _OBJECT): return int(v.num)     # a count; use the view to navigate
    raise Rejected("bad kind")

def mint(secret, exp: int, alg: str = "HS256") -> bytes:
    keep = []; out = _Bytes()
    rc = _lib.dagr_token_mint(_str(secret, keep), _str(alg, keep), exp, byref(out))
    if rc != 0: raise Rejected(_CODES.get(rc, rc))
    return _take(out)

def verify(token: bytes, secret, now: int) -> None:  # raises Rejected on any failure
    keep = []
    rc = _lib.dagr_token_verify(_str(token, keep), _str(secret, keep), now)
    if rc != 0: raise Rejected(_CODES.get(rc, rc))

def get(token: bytes, path: str):
    keep = []; v = _Val()
    rc = _lib.dagr_token_get(_str(token, keep), path.encode(), byref(v))
    if rc != 0: raise Rejected(_CODES.get(rc, rc))
    return _coerce(v)

class _Path:
    """A lazy path into a verified token; nothing is read until .value()/len()."""
    __slots__ = ("_t", "_p")
    def __init__(self, t, p): self._t, self._p = t, p
    def __getitem__(self, k): return _Path(self._t, f"{self._p}.{k}")
    def value(self):          return get(self._t, self._p)
    def __len__(self):
        keep = []; v = _Val()
        _lib.dagr_token_get(_str(self._t, keep), self._p.encode(), byref(v))
        if v.kind not in (_ARRAY, _OBJECT): raise TypeError(f"{self._p} is not a container")
        return int(v.num)

class Claims:
    __slots__ = ("_t",)
    def __init__(self, t): self._t = t
    @property
    def subject(self):    return get(self._t, "subject")
    @property
    def issuer(self):     return get(self._t, "issuer")
    @property
    def audience(self):   return get(self._t, "audience")
    @property
    def issued_at(self):  return get(self._t, "issuedAt")
    @property
    def expires_at(self): return get(self._t, "expiresAt")
    @property
    def scopes(self):     return _Path(self._t, "scopes")
    @property
    def custom(self):     return _Path(self._t, "custom")

def open(token: bytes, secret, now: int) -> Claims:  # verify (gate) THEN a path-query view
    verify(token, secret, now)
    return Claims(token)
