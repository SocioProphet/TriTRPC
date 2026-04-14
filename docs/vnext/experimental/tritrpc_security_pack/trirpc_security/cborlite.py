from __future__ import annotations

import struct
from typing import Any


def _encode_len(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < 2**32:
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", n)


def dumps(value: Any) -> bytes:
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        if value >= 0:
            return _encode_len(0, value)
        return _encode_len(1, -1 - value)
    if isinstance(value, bytes):
        return _encode_len(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _encode_len(3, len(data)) + data
    if isinstance(value, list):
        out = _encode_len(4, len(value))
        for item in value:
            out += dumps(item)
        return out
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        out = _encode_len(5, len(items))
        for k, v in items:
            out += dumps(str(k))
            out += dumps(v)
        return out
    raise TypeError(f"unsupported CBOR type: {type(value)!r}")


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        chunk = self.data[self.pos:self.pos+n]
        if len(chunk) != n:
            raise ValueError("unexpected end of CBOR data")
        self.pos += n
        return chunk

    def read_len(self, ai: int) -> int:
        if ai < 24:
            return ai
        if ai == 24:
            return self.take(1)[0]
        if ai == 25:
            return struct.unpack(">H", self.take(2))[0]
        if ai == 26:
            return struct.unpack(">I", self.take(4))[0]
        if ai == 27:
            return struct.unpack(">Q", self.take(8))[0]
        raise ValueError("indefinite lengths not supported")


def loads(data: bytes) -> Any:
    reader = _Reader(data)
    value = _load(reader)
    if reader.pos != len(data):
        raise ValueError("trailing CBOR data")
    return value


def _load(reader: _Reader) -> Any:
    initial = reader.take(1)[0]
    major = initial >> 5
    ai = initial & 0x1F

    if major in (0, 1):
        n = reader.read_len(ai)
        return n if major == 0 else -1 - n
    if major == 2:
        n = reader.read_len(ai)
        return reader.take(n)
    if major == 3:
        n = reader.read_len(ai)
        return reader.take(n).decode("utf-8")
    if major == 4:
        n = reader.read_len(ai)
        return [_load(reader) for _ in range(n)]
    if major == 5:
        n = reader.read_len(ai)
        out = {}
        for _ in range(n):
            key = _load(reader)
            out[key] = _load(reader)
        return out
    if major == 7:
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return None
    raise ValueError(f"unsupported CBOR major/ai: {major}/{ai}")
