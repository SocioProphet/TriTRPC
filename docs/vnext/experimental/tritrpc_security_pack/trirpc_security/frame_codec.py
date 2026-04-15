from __future__ import annotations

import enum
import struct
from dataclasses import dataclass

from . import cborlite


MAGIC = b"TRPC"
VERSION = 1
CODEC_CBOR = 1


class MessageType(enum.IntEnum):
    REQUEST = 1
    RESPONSE = 2
    EVENT = 3


@dataclass
class FrameHeader:
    version: int
    codec: int
    flags: int
    message_type: MessageType
    stream_id: int
    body_len: int


@dataclass
class Frame:
    header: FrameHeader
    body: dict


def encode_frame(message_type: MessageType, stream_id: int, body: dict, flags: int = 0) -> bytes:
    body_bytes = cborlite.dumps(body)
    header = MAGIC + bytes([VERSION, CODEC_CBOR, flags, int(message_type)]) + struct.pack(">II", stream_id, len(body_bytes))
    return header + body_bytes


def decode_frame(data: bytes) -> Frame:
    if len(data) < 16:
        raise ValueError("frame too short")
    if data[:4] != MAGIC:
        raise ValueError("bad frame magic")
    version, codec, flags, msg_type = data[4], data[5], data[6], data[7]
    if version != VERSION:
        raise ValueError("unsupported frame version")
    if codec != CODEC_CBOR:
        raise ValueError("unsupported frame codec")
    stream_id, body_len = struct.unpack(">II", data[8:16])
    body = cborlite.loads(data[16:16+body_len])
    if 16 + body_len != len(data):
        raise ValueError("frame length mismatch")
    return Frame(
        header=FrameHeader(version=version, codec=codec, flags=flags, message_type=MessageType(msg_type), stream_id=stream_id, body_len=body_len),
        body=body,
    )
