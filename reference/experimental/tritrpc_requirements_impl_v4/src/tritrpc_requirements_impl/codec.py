from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Sequence, Tuple


class TritPack243Error(ValueError):
    """Raised when a TritPack243/TLEB3 canonicality rule is violated."""


class PathProfile(IntEnum):
    PATH_A = 0
    PATH_B = 1
    PATH_H = 2


class ExecLane(IntEnum):
    CLASSICAL = 0
    QUANTUM = 1
    HYBRID = 2


class EvidenceGrade(IntEnum):
    EXACT = 0
    SAMPLED = 1
    VERIFIED = 2


class FallbackPolicy(IntEnum):
    NONE = 0
    CLASSICAL_OK = 1
    HEDGED_OK = 2


class RouteFormat(IntEnum):
    INLINE = 0
    HANDLE = 1
    BEACON_REF = 2


@dataclass(frozen=True)
class Control243:
    profile: PathProfile
    lane: ExecLane
    evidence: EvidenceGrade
    fallback: FallbackPolicy
    routefmt: RouteFormat

    def encode(self) -> int:
        for part in (self.profile, self.lane, self.evidence, self.fallback, self.routefmt):
            if int(part) not in (0, 1, 2):
                raise TritPack243Error("Control243 fields must be trits in canonical output")
        return (
            ((((int(self.profile) * 3) + int(self.lane)) * 3 + int(self.evidence)) * 3 + int(self.fallback))
            * 3
            + int(self.routefmt)
        )

    @classmethod
    def decode(cls, value: int) -> "Control243":
        if not 0 <= value <= 242:
            raise TritPack243Error("Control243 byte must be in 0..242")
        digits = [0, 0, 0, 0, 0]
        working = value
        for idx in range(4, -1, -1):
            digits[idx] = working % 3
            working //= 3
        return cls(
            profile=PathProfile(digits[0]),
            lane=ExecLane(digits[1]),
            evidence=EvidenceGrade(digits[2]),
            fallback=FallbackPolicy(digits[3]),
            routefmt=RouteFormat(digits[4]),
        )


class LifecycleTrit(IntEnum):
    DRAFT = 0
    ACTIVE = 1
    FROZEN = 2


class EpistemicTrit(IntEnum):
    OBSERVED = 0
    DERIVED = 1
    VERIFIED = 2


class NoveltyTrit(IntEnum):
    ROUTINE = 0
    NOVEL = 1
    ANOMALOUS = 2


class FrictionTrit(IntEnum):
    FLUID = 0
    REVIEW = 1
    GATE = 2


class ScopeTrit(IntEnum):
    LOCAL = 0
    COHORT = 1
    GLOBAL = 2


@dataclass(frozen=True)
class State243:
    lifecycle: LifecycleTrit
    epistemic: EpistemicTrit
    novelty: NoveltyTrit
    friction: FrictionTrit
    scope: ScopeTrit

    def encode(self) -> int:
        parts = (self.lifecycle, self.epistemic, self.novelty, self.friction, self.scope)
        for part in parts:
            if int(part) not in (0, 1, 2):
                raise TritPack243Error("State243 fields must be trits in canonical output")
        return (
            ((((int(self.lifecycle) * 3) + int(self.epistemic)) * 3 + int(self.novelty)) * 3 + int(self.friction))
            * 3
            + int(self.scope)
        )

    @classmethod
    def decode(cls, value: int) -> "State243":
        if not 0 <= value <= 242:
            raise TritPack243Error("State243 byte must be in 0..242")
        digits = [0, 0, 0, 0, 0]
        working = value
        for idx in range(4, -1, -1):
            digits[idx] = working % 3
            working //= 3
        return cls(
            lifecycle=LifecycleTrit(digits[0]),
            epistemic=EpistemicTrit(digits[1]),
            novelty=NoveltyTrit(digits[2]),
            friction=FrictionTrit(digits[3]),
            scope=ScopeTrit(digits[4]),
        )

    def label(self) -> str:
        return "/".join(
            (
                self.lifecycle.name.lower(),
                self.epistemic.name.lower(),
                self.novelty.name.lower(),
                self.friction.name.lower(),
                self.scope.name.lower(),
            )
        )


def tritpack243_pack(trits: Sequence[int]) -> bytes:
    out = bytearray()
    i = 0
    while i + 5 <= len(trits):
        val = 0
        for trit in trits[i : i + 5]:
            if trit not in (0, 1, 2):
                raise TritPack243Error(f"invalid trit value {trit}")
            val = val * 3 + int(trit)
        out.append(val)
        i += 5
    tail_len = len(trits) - i
    if tail_len > 0:
        out.append(243 + (tail_len - 1))
        val = 0
        for trit in trits[i:]:
            if trit not in (0, 1, 2):
                raise TritPack243Error(f"invalid trit value {trit}")
            val = val * 3 + int(trit)
        out.append(val)
    return bytes(out)


def tritpack243_unpack(data: bytes) -> list[int]:
    i = 0
    trits: list[int] = []
    while i < len(data):
        value = data[i]
        i += 1
        if value <= 242:
            group = [0, 0, 0, 0, 0]
            working = value
            for idx in range(4, -1, -1):
                group[idx] = working % 3
                working //= 3
            trits.extend(group)
        elif 243 <= value <= 246:
            tail_len = (value - 243) + 1
            if i >= len(data):
                raise TritPack243Error("truncated tail marker")
            tail_value = data[i]
            i += 1
            max_value = 3**tail_len
            if tail_value >= max_value:
                raise TritPack243Error("non-canonical tail value for TritPack243")
            group = [0] * tail_len
            working = tail_value
            for idx in range(tail_len - 1, -1, -1):
                group[idx] = working % 3
                working //= 3
            trits.extend(group)
        else:
            raise TritPack243Error("invalid byte in canonical TritPack243 output (247..255)")
    return trits


def tleb3_encode(n: int) -> bytes:
    if n < 0:
        raise TritPack243Error("TLEB3 encodes non-negative integers only")
    digits: list[int] = []
    if n == 0:
        digits = [0]
    else:
        while n > 0:
            digits.append(n % 9)
            n //= 9
    trits: list[int] = []
    for index, digit in enumerate(digits):
        continuation = 2 if index < len(digits) - 1 else 0
        p1, p0 = divmod(digit, 3)
        trits.extend([continuation, p1, p0])
    return tritpack243_pack(trits)



def _parse_tleb3_trits(trits: Sequence[int]) -> int:
    if len(trits) == 0 or len(trits) % 3 != 0:
        raise TritPack243Error("TLEB3 requires a whole number of tritlets")
    value = 0
    saw_final = False
    for idx in range(0, len(trits), 3):
        continuation, p1, p0 = trits[idx : idx + 3]
        if continuation not in (0, 2):
            raise TritPack243Error("TLEB3 continuation trit must be 0 or 2")
        digit = p1 * 3 + p0
        value += digit * (9 ** (idx // 3))
        if continuation == 0:
            if idx != len(trits) - 3:
                raise TritPack243Error("non-canonical TLEB3: final tritlet must be last")
            saw_final = True
    if not saw_final:
        raise TritPack243Error("incomplete TLEB3: missing final tritlet")
    return value



def tleb3_decode(data: bytes, offset: int = 0) -> Tuple[int, int]:
    if offset < 0 or offset > len(data):
        raise TritPack243Error("invalid TLEB3 offset")
    for end in range(offset + 1, len(data) + 1):
        chunk = data[offset:end]
        try:
            trits = tritpack243_unpack(chunk)
        except TritPack243Error as exc:
            if "truncated tail marker" in str(exc):
                continue
            raise
        try:
            value = _parse_tleb3_trits(trits)
        except TritPack243Error:
            continue
        canonical = tleb3_encode(value)
        if canonical != chunk:
            continue
        return value, end
    raise TritPack243Error("EOF in TLEB3")



def encode_s243(value: int) -> bytes:
    if value < 0:
        raise TritPack243Error("S243 encodes non-negative integers only")
    if value <= 242:
        return bytes([value])
    return bytes([243]) + tleb3_encode(value - 243)



def decode_s243(data: bytes, offset: int = 0) -> Tuple[int, int]:
    if offset >= len(data):
        raise TritPack243Error("EOF in S243")
    prefix = data[offset]
    if prefix <= 242:
        return prefix, offset + 1
    if prefix != 243:
        raise TritPack243Error("invalid leading byte for canonical S243")
    value, new_offset = tleb3_decode(data, offset + 1)
    return 243 + value, new_offset


@dataclass(frozen=True)
class TombstoneHandle:
    pass


TOMBSTONE = TombstoneHandle()


@dataclass(frozen=True)
class HashHandle:
    digest32: bytes

    def __post_init__(self) -> None:
        if len(self.digest32) != 32:
            raise TritPack243Error("HashHandle requires exactly 32 bytes")


@dataclass(frozen=True)
class ExtendedHandle:
    ext_id: int

    def __post_init__(self) -> None:
        if self.ext_id < 0:
            raise TritPack243Error("extended handle IDs must be non-negative")


HandleValue = int | str | HashHandle | ExtendedHandle | TombstoneHandle



def encode_handle243(value: HandleValue) -> bytes:
    if isinstance(value, int):
        if not 0 <= value <= 242:
            raise TritPack243Error("direct Handle243 values must be in 0..242")
        return bytes([value])
    if isinstance(value, ExtendedHandle):
        return bytes([243]) + encode_s243(value.ext_id)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return bytes([244]) + encode_s243(len(raw)) + raw
    if isinstance(value, HashHandle):
        return bytes([245]) + value.digest32
    if value is TOMBSTONE:
        return bytes([246])
    raise TritPack243Error(f"unsupported Handle243 value: {value!r}")



def decode_handle243(data: bytes, offset: int = 0) -> Tuple[HandleValue, int]:
    if offset >= len(data):
        raise TritPack243Error("EOF in Handle243")
    prefix = data[offset]
    if prefix <= 242:
        return prefix, offset + 1
    if prefix == 243:
        ext_id, new_offset = decode_s243(data, offset + 1)
        return ExtendedHandle(ext_id), new_offset
    if prefix == 244:
        length, new_offset = decode_s243(data, offset + 1)
        end = new_offset + length
        if end > len(data):
            raise TritPack243Error("truncated inline UTF-8 handle")
        return data[new_offset:end].decode("utf-8"), end
    if prefix == 245:
        end = offset + 1 + 32
        if end > len(data):
            raise TritPack243Error("truncated hash handle")
        return HashHandle(data[offset + 1 : end]), end
    if prefix == 246:
        return TOMBSTONE, offset + 1
    raise TritPack243Error("invalid leading byte for Handle243")
