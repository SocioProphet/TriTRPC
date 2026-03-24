from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .codec import (
    Control243,
    HandleValue,
    State243,
    TritPack243Error,
    decode_handle243,
    decode_s243,
    encode_handle243,
    encode_s243,
)
from .naming import decode_braid243, encode_braid243

MAGIC = bytes.fromhex("f32a")


class CryptoSuite(IntEnum):
    RESEARCH_NONAPPROVED = 0
    FIPS_CLASSICAL = 1
    CNSA2_READY = 2
    RESERVED = 3


class FrameKind(IntEnum):
    UNARY_REQ = 0
    UNARY_RSP = 1
    STREAM_OPEN = 2
    STREAM_DATA = 3
    STREAM_CLOSE = 4
    BEACON_CAP = 5
    BEACON_INTENT = 6
    BEACON_COMMIT = 7
    ERROR = 8


class TagProvider(Protocol):
    def tag_for(self, canonical_prefix: bytes, suite: CryptoSuite, sequence: int) -> bytes: ...

    def verify(self, canonical_prefix: bytes, tag: bytes, suite: CryptoSuite, sequence: int) -> bool: ...


@dataclass(frozen=True)
class NullTagProvider:
    tag_byte: int = 0

    def tag_for(self, canonical_prefix: bytes, suite: CryptoSuite, sequence: int) -> bytes:
        return bytes([self.tag_byte]) * 16

    def verify(self, canonical_prefix: bytes, tag: bytes, suite: CryptoSuite, sequence: int) -> bool:
        return tag == self.tag_for(canonical_prefix, suite, sequence)


@dataclass(frozen=True)
class AesGcmDemoTagProvider:
    """Functional demo provider only.

    This proves canonical framing and tag coverage in the sandbox, but it is not itself a
    validated cryptographic module and must not be represented as FIPS-approved operation.
    """

    key: bytes
    nonce_prefix: bytes = b"TRPC"

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise TritPack243Error("AES-256-GCM demo provider requires a 32-byte key")
        if len(self.nonce_prefix) != 4:
            raise TritPack243Error("demo nonce prefix must be exactly 4 bytes")

    def _nonce(self, sequence: int) -> bytes:
        if sequence < 0:
            raise TritPack243Error("sequence numbers must be non-negative")
        return self.nonce_prefix + int(sequence).to_bytes(8, "big")

    def tag_for(self, canonical_prefix: bytes, suite: CryptoSuite, sequence: int) -> bytes:
        aesgcm = AESGCM(self.key)
        return aesgcm.encrypt(self._nonce(sequence), b"", canonical_prefix)

    def verify(self, canonical_prefix: bytes, tag: bytes, suite: CryptoSuite, sequence: int) -> bool:
        try:
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(self._nonce(sequence), tag, canonical_prefix)
            return plaintext == b""
        except Exception:
            return False


@dataclass(frozen=True)
class HotUnaryFrame:
    control: Control243
    suite: CryptoSuite
    epoch: int
    route_handle: HandleValue
    payload: bytes
    sequence: int = 0
    kind: FrameKind = FrameKind.UNARY_REQ
    tag: bytes | None = None


@dataclass(frozen=True)
class StreamOpenFrame:
    control: Control243
    suite: CryptoSuite
    epoch: int
    route_handle: HandleValue
    stream_id: int
    payload: bytes
    default_braid: int | None = None
    default_state: State243 | None = None
    sequence: int = 0
    kind: FrameKind = FrameKind.STREAM_OPEN
    tag: bytes | None = None

    def __post_init__(self) -> None:
        _validate_semantic_pair(self.default_braid, self.default_state, context="stream-open defaults")


@dataclass(frozen=True)
class StreamDataFrame:
    control: Control243
    suite: CryptoSuite
    epoch: int
    stream_id: int
    payload: bytes
    semantic_override_braid: int | None = None
    semantic_override_state: State243 | None = None
    sequence: int = 0
    kind: FrameKind = FrameKind.STREAM_DATA
    tag: bytes | None = None

    def __post_init__(self) -> None:
        _validate_semantic_pair(self.semantic_override_braid, self.semantic_override_state, context="stream-data override")


@dataclass(frozen=True)
class StreamCloseFrame:
    control: Control243
    suite: CryptoSuite
    epoch: int
    stream_id: int
    payload: bytes
    sequence: int = 0
    kind: FrameKind = FrameKind.STREAM_CLOSE
    tag: bytes | None = None


@dataclass(frozen=True)
class BeaconFrame:
    control: Control243
    suite: CryptoSuite
    epoch: int
    identity_handle: HandleValue
    phase: int
    topic: int
    payload: bytes
    sequence: int = 0
    kind: FrameKind = FrameKind.BEACON_CAP
    tag: bytes | None = None


Frame = HotUnaryFrame | StreamOpenFrame | StreamDataFrame | StreamCloseFrame | BeaconFrame


@dataclass(frozen=True)
class ResolvedStreamSemantics:
    braid: int | None
    state: State243 | None
    source: str



def _validate_semantic_pair(braid: int | None, state: State243 | None, context: str) -> None:
    if (braid is None) ^ (state is None):
        raise TritPack243Error(f"{context} must provide both Braid243 and State243 or neither")
    if braid is not None:
        decode_braid243(braid)



def _encode_semantic_pair(braid: int | None, state: State243 | None) -> bytes:
    _validate_semantic_pair(braid, state, context="semantic pair")
    if braid is None or state is None:
        return b""
    return bytes([braid, state.encode()])



def resolve_stream_semantics(open_frame: StreamOpenFrame, data_frame: StreamDataFrame) -> ResolvedStreamSemantics:
    if data_frame.semantic_override_braid is not None and data_frame.semantic_override_state is not None:
        return ResolvedStreamSemantics(data_frame.semantic_override_braid, data_frame.semantic_override_state, "override")
    if open_frame.default_braid is not None and open_frame.default_state is not None:
        return ResolvedStreamSemantics(open_frame.default_braid, open_frame.default_state, "inherited")
    return ResolvedStreamSemantics(None, None, "none")



def _prefix_for_frame(frame: Frame) -> bytes:
    base = bytearray()
    base += MAGIC
    base.append(frame.control.encode())
    base.append(int(frame.kind))
    base.append(int(frame.suite))
    base += encode_s243(frame.epoch)

    if isinstance(frame, HotUnaryFrame):
        base += encode_handle243(frame.route_handle)
        base += encode_s243(len(frame.payload))
        base += frame.payload
        return bytes(base)

    if isinstance(frame, StreamOpenFrame):
        base += encode_handle243(frame.route_handle)
        base += encode_s243(frame.stream_id)
        base += encode_s243(len(frame.payload))
        base += frame.payload
        base += _encode_semantic_pair(frame.default_braid, frame.default_state)
        return bytes(base)

    if isinstance(frame, StreamDataFrame):
        base += encode_s243(frame.stream_id)
        base += encode_s243(len(frame.payload))
        base += frame.payload
        base += _encode_semantic_pair(frame.semantic_override_braid, frame.semantic_override_state)
        return bytes(base)

    if isinstance(frame, StreamCloseFrame):
        base += encode_s243(frame.stream_id)
        base += encode_s243(len(frame.payload))
        base += frame.payload
        return bytes(base)

    if isinstance(frame, BeaconFrame):
        base += encode_handle243(frame.identity_handle)
        base.append(encode_braid243(frame.phase, frame.topic))
        base += encode_s243(len(frame.payload))
        base += frame.payload
        return bytes(base)

    raise TritPack243Error(f"unsupported frame type {type(frame)!r}")



def serialize_frame(frame: Frame, tag_provider: TagProvider | None = None) -> bytes:
    prefix = _prefix_for_frame(frame)
    if frame.tag is not None:
        if len(frame.tag) != 16:
            raise TritPack243Error("canonical hot frames require a 16-byte tag")
        return prefix + frame.tag
    provider = tag_provider or NullTagProvider()
    tag = provider.tag_for(prefix, frame.suite, frame.sequence)
    if len(tag) != 16:
        raise TritPack243Error("tag provider must emit exactly 16 bytes")
    return prefix + tag



def _decode_optional_semantic_tail(data: bytes, payload_end: int) -> tuple[int | None, State243 | None]:
    extra_len = len(data) - payload_end - 16
    if extra_len == 0:
        return None, None
    if extra_len != 2:
        raise TritPack243Error("canonical semantic tails must be either absent or exactly 2 bytes")
    braid = data[payload_end]
    state_byte = data[payload_end + 1]
    decode_braid243(braid)
    state = State243.decode(state_byte)
    return braid, state



def parse_frame(data: bytes) -> Frame:
    if len(data) < 2 + 1 + 1 + 1 + 16:
        raise TritPack243Error("frame is too short to be canonical")
    if data[:2] != MAGIC:
        raise TritPack243Error("invalid magic")

    offset = 2
    control = Control243.decode(data[offset])
    offset += 1
    try:
        kind = FrameKind(data[offset])
    except ValueError as exc:
        raise TritPack243Error(f"invalid frame kind {data[offset]}") from exc
    offset += 1
    try:
        suite = CryptoSuite(data[offset])
    except ValueError as exc:
        raise TritPack243Error(f"invalid suite byte {data[offset]}") from exc
    offset += 1
    epoch, offset = decode_s243(data, offset)

    if kind in {FrameKind.UNARY_REQ, FrameKind.UNARY_RSP, FrameKind.ERROR}:
        route_handle, offset = decode_handle243(data, offset)
        payload_len, offset = decode_s243(data, offset)
        payload_end = offset + payload_len
        if payload_end + 16 != len(data):
            raise TritPack243Error("truncated or overlong unary frame")
        payload = data[offset:payload_end]
        tag = data[payload_end:]
        return HotUnaryFrame(
            control=control,
            kind=kind,
            suite=suite,
            epoch=epoch,
            route_handle=route_handle,
            payload=payload,
            tag=tag,
        )

    if kind == FrameKind.STREAM_OPEN:
        route_handle, offset = decode_handle243(data, offset)
        stream_id, offset = decode_s243(data, offset)
        payload_len, offset = decode_s243(data, offset)
        payload_end = offset + payload_len
        if payload_end + 16 > len(data):
            raise TritPack243Error("truncated stream-open frame")
        payload = data[offset:payload_end]
        braid, state = _decode_optional_semantic_tail(data, payload_end)
        tag = data[len(data) - 16 :]
        return StreamOpenFrame(
            control=control,
            suite=suite,
            epoch=epoch,
            route_handle=route_handle,
            stream_id=stream_id,
            payload=payload,
            default_braid=braid,
            default_state=state,
            tag=tag,
        )

    if kind == FrameKind.STREAM_DATA:
        stream_id, offset = decode_s243(data, offset)
        payload_len, offset = decode_s243(data, offset)
        payload_end = offset + payload_len
        if payload_end + 16 > len(data):
            raise TritPack243Error("truncated stream-data frame")
        payload = data[offset:payload_end]
        braid, state = _decode_optional_semantic_tail(data, payload_end)
        tag = data[len(data) - 16 :]
        return StreamDataFrame(
            control=control,
            suite=suite,
            epoch=epoch,
            stream_id=stream_id,
            payload=payload,
            semantic_override_braid=braid,
            semantic_override_state=state,
            tag=tag,
        )

    if kind == FrameKind.STREAM_CLOSE:
        stream_id, offset = decode_s243(data, offset)
        payload_len, offset = decode_s243(data, offset)
        payload_end = offset + payload_len
        if payload_end + 16 != len(data):
            raise TritPack243Error("truncated or overlong stream-close frame")
        payload = data[offset:payload_end]
        tag = data[payload_end:]
        return StreamCloseFrame(
            control=control,
            suite=suite,
            epoch=epoch,
            stream_id=stream_id,
            payload=payload,
            tag=tag,
        )

    if kind in {FrameKind.BEACON_CAP, FrameKind.BEACON_INTENT, FrameKind.BEACON_COMMIT}:
        identity_handle, offset = decode_handle243(data, offset)
        if offset >= len(data):
            raise TritPack243Error("truncated beacon braid byte")
        phase, topic = decode_braid243(data[offset])
        offset += 1
        payload_len, offset = decode_s243(data, offset)
        payload_end = offset + payload_len
        if payload_end + 16 != len(data):
            raise TritPack243Error("truncated or overlong beacon frame")
        payload = data[offset:payload_end]
        tag = data[payload_end:]
        return BeaconFrame(
            control=control,
            suite=suite,
            epoch=epoch,
            identity_handle=identity_handle,
            phase=phase,
            topic=topic,
            payload=payload,
            kind=kind,
            tag=tag,
        )

    raise TritPack243Error(f"frame kind {kind} is not implemented in parser")
