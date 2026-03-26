from __future__ import annotations

from dataclasses import dataclass

from .codec import TritPack243Error, encode_s243, decode_s243, tritpack243_pack, tritpack243_unpack


@dataclass(frozen=True)
class Padic3Delta:
    scale: int
    digits: tuple[int, ...]

    def encode(self) -> bytes:
        return encode_s243(self.scale) + encode_s243(len(self.digits)) + tritpack243_pack(self.digits)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple["Padic3Delta", int]:
        scale, offset = decode_s243(data, offset)
        count, offset = decode_s243(data, offset)
        trits: list[int] = []
        start = offset
        while len(trits) < count:
            if offset >= len(data):
                raise TritPack243Error("truncated PADIC3_DELTA digits")
            offset += 1
            try:
                trits = tritpack243_unpack(data[start:offset])
            except TritPack243Error as exc:
                if "truncated tail marker" in str(exc):
                    continue
                raise
        if len(trits) != count:
            canonical = tritpack243_pack(trits[:count])
            offset = start + len(canonical)
            trits = trits[:count]
        return cls(scale=scale, digits=tuple(trits)), offset



def mod3_digits(value: int, digits: int) -> tuple[int, ...]:
    if value < 0:
        raise TritPack243Error("padic reference only models non-negative residues")
    if digits < 0:
        raise TritPack243Error("digits must be non-negative")
    out = [0] * digits
    working = value
    for idx in range(digits):
        out[idx] = working % 3
        working //= 3
    return tuple(out)



def refinement_delta(previous: tuple[int, ...], refined_value: int, refined_digits: int) -> Padic3Delta:
    refined = mod3_digits(refined_value, refined_digits)
    if previous and refined[: len(previous)] != previous:
        raise TritPack243Error("refinement is not 3-adically consistent with previous digits")
    return Padic3Delta(scale=len(previous), digits=tuple(refined[len(previous) :]))



def apply_delta(previous: tuple[int, ...], delta: Padic3Delta) -> tuple[int, ...]:
    if len(previous) != delta.scale:
        raise TritPack243Error("delta scale does not match current precision")
    return previous + delta.digits
