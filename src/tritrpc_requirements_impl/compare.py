from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from thrift.Thrift import TType
from thrift.protocol import TBinaryProtocol, TCompactProtocol
from thrift.transport import TTransport

from .codec import (
    Control243,
    EvidenceGrade,
    ExecLane,
    FallbackPolicy,
    FrictionTrit,
    LifecycleTrit,
    NoveltyTrit,
    PathProfile,
    RouteFormat,
    ScopeTrit,
    State243,
    EpistemicTrit,
    tritpack243_pack,
)
from .frames import (
    BeaconFrame,
    CryptoSuite,
    FrameKind,
    HotUnaryFrame,
    NullTagProvider,
    StreamDataFrame,
    StreamOpenFrame,
    serialize_frame,
)


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    description: str
    lengths: dict[str, int]
    hex_samples: dict[str, str]
    notes: list[str]


def _control() -> Control243:
    return Control243(
        profile=PathProfile.PATH_A,
        lane=ExecLane.CLASSICAL,
        evidence=EvidenceGrade.EXACT,
        fallback=FallbackPolicy.NONE,
        routefmt=RouteFormat.HANDLE,
    )


def _pb_message_classes() -> dict[str, type]:
    file_proto = descriptor_pb2.FileDescriptorProto()
    file_proto.name = "tritrpc_transport_compare.proto"
    file_proto.package = "tritrpc.compare"
    file_proto.syntax = "proto3"

    def add(name: str, fields: list[tuple[str, int, int, int]]) -> None:
        msg = file_proto.message_type.add()
        msg.name = name
        for fname, number, label, ftype in fields:
            field = msg.field.add()
            field.name = fname
            field.number = number
            field.label = label
            field.type = ftype

    OPT = 1
    REP = 3
    UINT32 = 13
    BYTES = 12
    STRING = 9

    add(
        "HotUnaryHandle",
        [
            ("control", 1, OPT, UINT32),
            ("kind", 2, OPT, UINT32),
            ("suite", 3, OPT, UINT32),
            ("epoch", 4, OPT, UINT32),
            ("route_handle", 5, OPT, UINT32),
            ("payload", 6, OPT, BYTES),
            ("tag", 7, OPT, BYTES),
        ],
    )
    add(
        "HotUnaryFused",
        [
            ("cks", 1, OPT, UINT32),
            ("epoch", 2, OPT, UINT32),
            ("route_handle", 3, OPT, UINT32),
            ("payload", 4, OPT, BYTES),
            ("tag", 5, OPT, BYTES),
        ],
    )
    add(
        "HotUnaryInline",
        [
            ("control", 1, OPT, UINT32),
            ("kind", 2, OPT, UINT32),
            ("suite", 3, OPT, UINT32),
            ("epoch", 4, OPT, UINT32),
            ("service", 5, OPT, STRING),
            ("method", 6, OPT, STRING),
            ("payload", 7, OPT, BYTES),
            ("tag", 8, OPT, BYTES),
        ],
    )
    add(
        "StreamOpenHandle",
        [
            ("control", 1, OPT, UINT32),
            ("kind", 2, OPT, UINT32),
            ("suite", 3, OPT, UINT32),
            ("epoch", 4, OPT, UINT32),
            ("route_handle", 5, OPT, UINT32),
            ("stream_id", 6, OPT, UINT32),
            ("payload", 7, OPT, BYTES),
            ("tag", 8, OPT, BYTES),
        ],
    )
    add(
        "StreamOpenFused",
        [
            ("cks", 1, OPT, UINT32),
            ("epoch", 2, OPT, UINT32),
            ("route_handle", 3, OPT, UINT32),
            ("stream_id", 4, OPT, UINT32),
            ("payload", 5, OPT, BYTES),
            ("tag", 6, OPT, BYTES),
        ],
    )
    add(
        "StreamDataHandle",
        [
            ("control", 1, OPT, UINT32),
            ("kind", 2, OPT, UINT32),
            ("suite", 3, OPT, UINT32),
            ("epoch", 4, OPT, UINT32),
            ("stream_id", 5, OPT, UINT32),
            ("payload", 6, OPT, BYTES),
            ("tag", 7, OPT, BYTES),
        ],
    )
    add(
        "StreamDataFused",
        [
            ("cks", 1, OPT, UINT32),
            ("epoch", 2, OPT, UINT32),
            ("stream_id", 3, OPT, UINT32),
            ("payload", 4, OPT, BYTES),
            ("tag", 5, OPT, BYTES),
        ],
    )
    add(
        "TriStateVector",
        [("v", 1, REP, UINT32)],
    )
    add(
        "CombinedBraid",
        [("coord", 1, OPT, UINT32)],
    )
    add(
        "SplitBraid",
        [("phase", 1, OPT, UINT32), ("topic", 2, OPT, UINT32)],
    )

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_proto)
    out: dict[str, type] = {}
    for name in [
        "HotUnaryHandle",
        "HotUnaryFused",
        "HotUnaryInline",
        "StreamOpenHandle",
        "StreamOpenFused",
        "StreamDataHandle",
        "StreamDataFused",
        "TriStateVector",
        "CombinedBraid",
        "SplitBraid",
    ]:
        out[name] = message_factory.GetMessageClass(pool.FindMessageTypeByName(f"tritrpc.compare.{name}"))
    return out


def _thrift_struct(fields: list[tuple[str, int, int, Any]], protocol: str) -> bytes:
    trans = TTransport.TMemoryBuffer()
    if protocol == "compact":
        proto = TCompactProtocol.TCompactProtocol(trans)
    elif protocol == "binary":
        proto = TBinaryProtocol.TBinaryProtocol(trans)
    else:
        raise ValueError(protocol)
    proto.writeStructBegin("S")
    for name, fid, ttype, value in fields:
        proto.writeFieldBegin(name, ttype, fid)
        if ttype == TType.I16:
            proto.writeI16(value)
        elif ttype == TType.I32:
            proto.writeI32(value)
        elif ttype == TType.STRING:
            if isinstance(value, bytes):
                proto.writeBinary(value)
            else:
                proto.writeString(value)
        elif ttype == TType.LIST:
            elem_type, seq = value
            proto.writeListBegin(elem_type, len(seq))
            for item in seq:
                if elem_type == TType.I32:
                    proto.writeI32(item)
                else:
                    raise ValueError("unsupported thrift list element type")
            proto.writeListEnd()
        else:
            raise ValueError(f"unsupported thrift field type {ttype}")
        proto.writeFieldEnd()
    proto.writeFieldStop()
    proto.writeStructEnd()
    return trans.getvalue()


def _fused_cks(control: int, kind: int, suite: int) -> int:
    return ((control & 0xFF) << 4) ^ ((kind & 0x3) << 2) ^ (suite & 0x3)


def generate_transport_comparison() -> dict[str, Any]:
    pb = _pb_message_classes()
    control = _control()
    control_byte = control.encode()
    cks_hot = _fused_cks(control_byte, FrameKind.UNARY_REQ, CryptoSuite.FIPS_CLASSICAL)
    cks_open = _fused_cks(control_byte, FrameKind.STREAM_OPEN, CryptoSuite.FIPS_CLASSICAL)
    cks_data = _fused_cks(control_byte, FrameKind.STREAM_DATA, CryptoSuite.FIPS_CLASSICAL)
    null = NullTagProvider()
    payload_hot = b'{"op":"add-vertex","id":"a"}'
    payload_open = b'{"cursor":"start"}'
    payload_data = b'{"chunk":1}'
    payload_large = b'x' * 1024
    tag = bytes(16)
    service = "sp.graphbrain.hyper"
    method = "add-vertex"

    tri_hot = serialize_frame(HotUnaryFrame(control=control, suite=CryptoSuite.FIPS_CLASSICAL, epoch=18, route_handle=7, payload=payload_hot, sequence=1), null)
    tri_open = serialize_frame(StreamOpenFrame(control=control, suite=CryptoSuite.FIPS_CLASSICAL, epoch=18, route_handle=7, stream_id=9, payload=payload_open, sequence=2), null)
    tri_data = serialize_frame(StreamDataFrame(control=control, suite=CryptoSuite.FIPS_CLASSICAL, epoch=18, stream_id=9, payload=payload_data, sequence=3), null)
    tri_large = serialize_frame(HotUnaryFrame(control=control, suite=CryptoSuite.FIPS_CLASSICAL, epoch=18, route_handle=7, payload=payload_large, sequence=4), null)

    pb_hot = pb["HotUnaryHandle"](control=control_byte, kind=int(FrameKind.UNARY_REQ), suite=int(CryptoSuite.FIPS_CLASSICAL), epoch=18, route_handle=7, payload=payload_hot, tag=tag).SerializeToString()
    pb_hot_fused = pb["HotUnaryFused"](cks=cks_hot, epoch=18, route_handle=7, payload=payload_hot, tag=tag).SerializeToString()
    pb_hot_inline = pb["HotUnaryInline"](control=control_byte, kind=int(FrameKind.UNARY_REQ), suite=int(CryptoSuite.FIPS_CLASSICAL), epoch=18, service=service, method=method, payload=payload_hot, tag=tag).SerializeToString()
    pb_open = pb["StreamOpenHandle"](control=control_byte, kind=int(FrameKind.STREAM_OPEN), suite=int(CryptoSuite.FIPS_CLASSICAL), epoch=18, route_handle=7, stream_id=9, payload=payload_open, tag=tag).SerializeToString()
    pb_open_fused = pb["StreamOpenFused"](cks=cks_open, epoch=18, route_handle=7, stream_id=9, payload=payload_open, tag=tag).SerializeToString()
    pb_data = pb["StreamDataHandle"](control=control_byte, kind=int(FrameKind.STREAM_DATA), suite=int(CryptoSuite.FIPS_CLASSICAL), epoch=18, stream_id=9, payload=payload_data, tag=tag).SerializeToString()
    pb_data_fused = pb["StreamDataFused"](cks=cks_data, epoch=18, stream_id=9, payload=payload_data, tag=tag).SerializeToString()
    pb_large = pb["HotUnaryHandle"](control=control_byte, kind=int(FrameKind.UNARY_REQ), suite=int(CryptoSuite.FIPS_CLASSICAL), epoch=18, route_handle=7, payload=payload_large, tag=tag).SerializeToString()
    pb_large_fused = pb["HotUnaryFused"](cks=cks_hot, epoch=18, route_handle=7, payload=payload_large, tag=tag).SerializeToString()

    thrift_hot_binary = _thrift_struct([
        ("control", 1, TType.I16, control_byte),
        ("kind", 2, TType.I16, int(FrameKind.UNARY_REQ)),
        ("suite", 3, TType.I16, int(CryptoSuite.FIPS_CLASSICAL)),
        ("epoch", 4, TType.I32, 18),
        ("route_handle", 5, TType.I32, 7),
        ("payload", 6, TType.STRING, payload_hot),
        ("tag", 7, TType.STRING, tag),
    ], "binary")
    thrift_hot_compact = _thrift_struct([
        ("control", 1, TType.I16, control_byte),
        ("kind", 2, TType.I16, int(FrameKind.UNARY_REQ)),
        ("suite", 3, TType.I16, int(CryptoSuite.FIPS_CLASSICAL)),
        ("epoch", 4, TType.I32, 18),
        ("route_handle", 5, TType.I32, 7),
        ("payload", 6, TType.STRING, payload_hot),
        ("tag", 7, TType.STRING, tag),
    ], "compact")
    thrift_hot_compact_fused = _thrift_struct([
        ("cks", 1, TType.I16, cks_hot),
        ("epoch", 2, TType.I32, 18),
        ("route_handle", 3, TType.I32, 7),
        ("payload", 4, TType.STRING, payload_hot),
        ("tag", 5, TType.STRING, tag),
    ], "compact")
    thrift_hot_inline_compact = _thrift_struct([
        ("control", 1, TType.I16, control_byte),
        ("kind", 2, TType.I16, int(FrameKind.UNARY_REQ)),
        ("suite", 3, TType.I16, int(CryptoSuite.FIPS_CLASSICAL)),
        ("epoch", 4, TType.I32, 18),
        ("service", 5, TType.STRING, service),
        ("method", 6, TType.STRING, method),
        ("payload", 7, TType.STRING, payload_hot),
        ("tag", 8, TType.STRING, tag),
    ], "compact")

    thrift_open_compact = _thrift_struct([
        ("control", 1, TType.I16, control_byte),
        ("kind", 2, TType.I16, int(FrameKind.STREAM_OPEN)),
        ("suite", 3, TType.I16, int(CryptoSuite.FIPS_CLASSICAL)),
        ("epoch", 4, TType.I32, 18),
        ("route_handle", 5, TType.I32, 7),
        ("stream_id", 6, TType.I32, 9),
        ("payload", 7, TType.STRING, payload_open),
        ("tag", 8, TType.STRING, tag),
    ], "compact")
    thrift_open_compact_fused = _thrift_struct([
        ("cks", 1, TType.I16, cks_open),
        ("epoch", 2, TType.I32, 18),
        ("route_handle", 3, TType.I32, 7),
        ("stream_id", 4, TType.I32, 9),
        ("payload", 5, TType.STRING, payload_open),
        ("tag", 6, TType.STRING, tag),
    ], "compact")
    thrift_data_compact = _thrift_struct([
        ("control", 1, TType.I16, control_byte),
        ("kind", 2, TType.I16, int(FrameKind.STREAM_DATA)),
        ("suite", 3, TType.I16, int(CryptoSuite.FIPS_CLASSICAL)),
        ("epoch", 4, TType.I32, 18),
        ("stream_id", 5, TType.I32, 9),
        ("payload", 6, TType.STRING, payload_data),
        ("tag", 7, TType.STRING, tag),
    ], "compact")
    thrift_data_compact_fused = _thrift_struct([
        ("cks", 1, TType.I16, cks_data),
        ("epoch", 2, TType.I32, 18),
        ("stream_id", 3, TType.I32, 9),
        ("payload", 4, TType.STRING, payload_data),
        ("tag", 5, TType.STRING, tag),
    ], "compact")
    thrift_large_compact = _thrift_struct([
        ("control", 1, TType.I16, control_byte),
        ("kind", 2, TType.I16, int(FrameKind.UNARY_REQ)),
        ("suite", 3, TType.I16, int(CryptoSuite.FIPS_CLASSICAL)),
        ("epoch", 4, TType.I32, 18),
        ("route_handle", 5, TType.I32, 7),
        ("payload", 6, TType.STRING, payload_large),
        ("tag", 7, TType.STRING, tag),
    ], "compact")
    thrift_large_compact_fused = _thrift_struct([
        ("cks", 1, TType.I16, cks_hot),
        ("epoch", 2, TType.I32, 18),
        ("route_handle", 3, TType.I32, 7),
        ("payload", 4, TType.STRING, payload_large),
        ("tag", 5, TType.STRING, tag),
    ], "compact")

    tristate_values = [idx % 3 for idx in range(100)]
    tri_vec = tritpack243_pack(tristate_values)
    pb_vec = pb["TriStateVector"](v=tristate_values).SerializeToString()
    thrift_vec_compact = _thrift_struct([("v", 1, TType.LIST, (TType.I32, tristate_values))], "compact")
    thrift_vec_binary = _thrift_struct([("v", 1, TType.LIST, (TType.I32, tristate_values))], "binary")

    braid_coord = ((4 - 1) * 27) + (14 - 1)
    pb_braid_combined = pb["CombinedBraid"](coord=braid_coord).SerializeToString()
    pb_braid_split = pb["SplitBraid"](phase=4, topic=14).SerializeToString()
    thrift_braid_combined = _thrift_struct([("coord", 1, TType.I32, braid_coord)], "compact")
    thrift_braid_split = _thrift_struct([("phase", 1, TType.I32, 4), ("topic", 2, TType.I32, 14)], "compact")

    scenarios = {
        "hot_unary_small_secure": ScenarioResult(
            name="hot_unary_small_secure",
            description="Authenticated hot unary request with handle route and 28-byte JSON payload.",
            lengths={
                "tritrpc": len(tri_hot),
                "protobuf_handle": len(pb_hot),
                "protobuf_fused": len(pb_hot_fused),
                "protobuf_inline": len(pb_hot_inline),
                "thrift_compact_handle": len(thrift_hot_compact),
                "thrift_compact_fused": len(thrift_hot_compact_fused),
                "thrift_compact_inline": len(thrift_hot_inline_compact),
                "thrift_binary_handle": len(thrift_hot_binary),
            },
            hex_samples={
                "tritrpc": tri_hot.hex(),
                "protobuf_handle": pb_hot.hex(),
                "protobuf_fused": pb_hot_fused.hex(),
                "thrift_compact_handle": thrift_hot_compact.hex(),
            },
            notes=[
                "TriTRPC advantage here comes from one-byte Control243, one-byte S243 integers, fixed hot framing, and a built-in 16-byte tag.",
                "The fused protobuf/thrift variants are deliberately generous competitors that manually combine control/kind/suite into a single small scalar.",
            ],
        ),
        "stream_open_small_secure": ScenarioResult(
            name="stream_open_small_secure",
            description="Authenticated stream OPEN with handle route, stream_id, and 18-byte JSON payload.",
            lengths={
                "tritrpc": len(tri_open),
                "protobuf_handle": len(pb_open),
                "protobuf_fused": len(pb_open_fused),
                "thrift_compact_handle": len(thrift_open_compact),
                "thrift_compact_fused": len(thrift_open_compact_fused),
            },
            hex_samples={
                "tritrpc": tri_open.hex(),
                "protobuf_handle": pb_open.hex(),
                "protobuf_fused": pb_open_fused.hex(),
                "thrift_compact_handle": thrift_open_compact.hex(),
            },
            notes=[
                "Once stream state is established, TriTRPC avoids repeating route metadata on DATA frames.",
            ],
        ),
        "stream_data_small_secure": ScenarioResult(
            name="stream_data_small_secure",
            description="Authenticated stream DATA with stream_id and 11-byte JSON payload.",
            lengths={
                "tritrpc": len(tri_data),
                "protobuf_handle": len(pb_data),
                "protobuf_fused": len(pb_data_fused),
                "thrift_compact_handle": len(thrift_data_compact),
                "thrift_compact_fused": len(thrift_data_compact_fused),
            },
            hex_samples={
                "tritrpc": tri_data.hex(),
                "protobuf_handle": pb_data.hex(),
                "protobuf_fused": pb_data_fused.hex(),
                "thrift_compact_handle": thrift_data_compact.hex(),
            },
            notes=[
                "This is the cleanest hot-path comparison because route metadata is already interned away.",
            ],
        ),
        "hot_unary_large_secure_1024": ScenarioResult(
            name="hot_unary_large_secure_1024",
            description="Authenticated hot unary request with 1024-byte opaque payload.",
            lengths={
                "tritrpc": len(tri_large),
                "protobuf_handle": len(pb_large),
                "protobuf_fused": len(pb_large_fused),
                "thrift_compact_handle": len(thrift_large_compact),
                "thrift_compact_fused": len(thrift_large_compact_fused),
            },
            hex_samples={
                "tritrpc_prefix": tri_large[:40].hex(),
                "protobuf_handle_prefix": pb_large[:40].hex(),
            },
            notes=[
                "As payload size grows, fixed-header differences become nearly irrelevant; in this benchmark, manually fused protobuf edges TriTRPC by one byte.",
            ],
        ),
        "tristate_vector_100_payload_only": ScenarioResult(
            name="tristate_vector_100_payload_only",
            description="Payload-only comparison for 100 values in {0,1,2}.",
            lengths={
                "tritrpc_tritpack243": len(tri_vec),
                "protobuf_packed_uint32": len(pb_vec),
                "thrift_compact_list_i32": len(thrift_vec_compact),
                "thrift_binary_list_i32": len(thrift_vec_binary),
            },
            hex_samples={
                "tritrpc_tritpack243": tri_vec.hex(),
                "protobuf_packed_uint32": pb_vec.hex(),
                "thrift_compact_list_i32": thrift_vec_compact.hex(),
            },
            notes=[
                "This is where ternary-native packing creates a categorical advantage, because the payload alphabet itself is ternary.",
            ],
        ),
        "braid243_coordinate_only": ScenarioResult(
            name="braid243_coordinate_only",
            description="Coordinate-only comparison for one 7x23 braid state (phase 4, topic 14).",
            lengths={
                "tritrpc_braid243": 1,
                "protobuf_combined_coord": len(pb_braid_combined),
                "protobuf_split_phase_topic": len(pb_braid_split),
                "thrift_compact_combined_coord": len(thrift_braid_combined),
                "thrift_compact_split_phase_topic": len(thrift_braid_split),
            },
            hex_samples={
                "tritrpc_braid243": bytes([braid_coord]).hex(),
                "protobuf_combined_coord": pb_braid_combined.hex(),
                "protobuf_split_phase_topic": pb_braid_split.hex(),
                "thrift_compact_combined_coord": thrift_braid_combined.hex(),
            },
            notes=[
                "Seven phases times 23 topics gives 161 live states, which fit inside one 5-trit byte.",
            ],
        ),
    }

    summary = {
        "payloads": {
            "hot_unary_small_payload_len": len(payload_hot),
            "stream_open_small_payload_len": len(payload_open),
            "stream_data_small_payload_len": len(payload_data),
            "large_payload_len": len(payload_large),
        },
        "constants_for_small_secure_frames": {
            "tritrpc_hot_unary": len(tri_hot) - len(payload_hot),
            "protobuf_hot_unary_handle": len(pb_hot) - len(payload_hot),
            "protobuf_hot_unary_fused": len(pb_hot_fused) - len(payload_hot),
            "thrift_compact_hot_unary_handle": len(thrift_hot_compact) - len(payload_hot),
            "thrift_compact_hot_unary_fused": len(thrift_hot_compact_fused) - len(payload_hot),
            "tritrpc_stream_open": len(tri_open) - len(payload_open),
            "protobuf_stream_open_handle": len(pb_open) - len(payload_open),
            "protobuf_stream_open_fused": len(pb_open_fused) - len(payload_open),
            "thrift_compact_stream_open_handle": len(thrift_open_compact) - len(payload_open),
            "thrift_compact_stream_open_fused": len(thrift_open_compact_fused) - len(payload_open),
            "tritrpc_stream_data": len(tri_data) - len(payload_data),
            "protobuf_stream_data_handle": len(pb_data) - len(payload_data),
            "protobuf_stream_data_fused": len(pb_data_fused) - len(payload_data),
            "thrift_compact_stream_data_handle": len(thrift_data_compact) - len(payload_data),
            "thrift_compact_stream_data_fused": len(thrift_data_compact_fused) - len(payload_data),
        },
    }

    return {
        "summary": {**summary, "totals_for_100_frames": {"hot_unary_small_secure": {k: v*100 for k, v in scenarios["hot_unary_small_secure"].lengths.items()}, "stream_data_small_secure": {k: v*100 for k, v in scenarios["stream_data_small_secure"].lengths.items()}}},
        "scenarios": {name: result.__dict__ for name, result in scenarios.items()},
    }


def render_transport_comparison_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# TriTRPC vs Protobuf vs Thrift transport comparison")
    lines.append("")
    lines.append("This report compares concrete wire lengths for equivalent authenticated hot-path frames and a few payload-only surfaces. It is intentionally generous to the competitors: protobuf and Thrift are shown both in straightforward handle-based form and in manually fused forms that combine control/kind/suite into one small scalar.")
    lines.append("")
    consts = payload["summary"]["constants_for_small_secure_frames"]
    lines.append("## Small secure frame constants")
    lines.append("")
    lines.append(f"- Hot unary: TriTRPC = P + {consts['tritrpc_hot_unary']}, protobuf(handle) = P + {consts['protobuf_hot_unary_handle']}, protobuf(fused) = P + {consts['protobuf_hot_unary_fused']}, thrift compact(handle) = P + {consts['thrift_compact_hot_unary_handle']}, thrift compact(fused) = P + {consts['thrift_compact_hot_unary_fused']}.")
    lines.append(f"- Stream OPEN: TriTRPC = P + {consts['tritrpc_stream_open']}, protobuf(handle) = P + {consts['protobuf_stream_open_handle']}, protobuf(fused) = P + {consts['protobuf_stream_open_fused']}, thrift compact(handle) = P + {consts['thrift_compact_stream_open_handle']}, thrift compact(fused) = P + {consts['thrift_compact_stream_open_fused']}.")
    lines.append(f"- Stream DATA: TriTRPC = P + {consts['tritrpc_stream_data']}, protobuf(handle) = P + {consts['protobuf_stream_data_handle']}, protobuf(fused) = P + {consts['protobuf_stream_data_fused']}, thrift compact(handle) = P + {consts['thrift_compact_stream_data_handle']}, thrift compact(fused) = P + {consts['thrift_compact_stream_data_fused']}.")
    lines.append("")
    for name, scenario in payload["scenarios"].items():
        lines.append(f"## {name}")
        lines.append("")
        lines.append(scenario["description"])
        lines.append("")
        lines.append("| Variant | Bytes |")
        lines.append("|---|---:|")
        for variant, length in sorted(scenario["lengths"].items(), key=lambda item: item[1]):
            lines.append(f"| {variant} | {length} |")
        lines.append("")
        if scenario.get("notes"):
            for note in scenario["notes"]:
                lines.append(f"- {note}")
            lines.append("")
    totals = payload["summary"].get("totals_for_100_frames", {})
    if totals:
        lines.append("## 100-frame totals")
        lines.append("")
        for scenario_name, variants in totals.items():
            lines.append(f"### {scenario_name}")
            lines.append("")
            lines.append("| Variant | Bytes / 100 frames |")
            lines.append("|---|---:|")
            for variant, length in sorted(variants.items(), key=lambda item: item[1]):
                lines.append(f"| {variant} | {length} |")
            lines.append("")
    lines.append("## Bottom line")
    lines.append("")
    lines.append("TriTRPC wins most clearly on four surfaces: authenticated hot control frames, true stream DATA frames after route interning, payloads whose native alphabet is ternary or otherwise very low-cardinality, and any workload that would otherwise repeat long route strings. The gap collapses on large opaque payloads, and it can be narrowed substantially if protobuf or Thrift are given equivalent application-level intelligence such as fused headers and handle dictionaries. In the large-payload benchmark here, fused protobuf is actually one byte smaller than TriTRPC, so the honest claim is not universal dominance but a strong advantage on the agentic hot path TriTRPC is designed for.")
    lines.append("")
    return "\n".join(lines)


def generate_braid_cadence_comparison() -> dict[str, Any]:
    control = _control()
    null = NullTagProvider()
    payload_open = b'{"cursor":"start"}'
    payload_data = b'{"chunk":1}'
    payload_beacon = b'\x01'
    braid = ((4 - 1) * 27) + (14 - 1)
    state = State243(
        lifecycle=LifecycleTrit.ACTIVE,
        epistemic=EpistemicTrit.VERIFIED,
        novelty=NoveltyTrit.ROUTINE,
        friction=FrictionTrit.FLUID,
        scope=ScopeTrit.COHORT,
    )

    base_open = serialize_frame(
        StreamOpenFrame(
            control=control,
            suite=CryptoSuite.FIPS_CLASSICAL,
            epoch=18,
            route_handle=7,
            stream_id=9,
            payload=payload_open,
            sequence=1,
        ),
        null,
    )
    inherited_open = serialize_frame(
        StreamOpenFrame(
            control=control,
            suite=CryptoSuite.FIPS_CLASSICAL,
            epoch=18,
            route_handle=7,
            stream_id=9,
            payload=payload_open,
            default_braid=braid,
            default_state=state,
            sequence=1,
        ),
        null,
    )
    base_data = serialize_frame(
        StreamDataFrame(
            control=control,
            suite=CryptoSuite.FIPS_CLASSICAL,
            epoch=18,
            stream_id=9,
            payload=payload_data,
            sequence=2,
        ),
        null,
    )
    per_frame_data = serialize_frame(
        StreamDataFrame(
            control=control,
            suite=CryptoSuite.FIPS_CLASSICAL,
            epoch=18,
            stream_id=9,
            payload=payload_data,
            semantic_override_braid=braid,
            semantic_override_state=state,
            sequence=2,
        ),
        null,
    )
    beacon = serialize_frame(
        BeaconFrame(
            control=Control243(
                profile=PathProfile.PATH_H,
                lane=ExecLane.HYBRID,
                evidence=EvidenceGrade.VERIFIED,
                fallback=FallbackPolicy.HEDGED_OK,
                routefmt=RouteFormat.BEACON_REF,
            ),
            suite=CryptoSuite.FIPS_CLASSICAL,
            epoch=18,
            identity_handle=19,
            phase=4,
            topic=14,
            payload=payload_beacon,
            kind=FrameKind.BEACON_INTENT,
            sequence=3,
        ),
        null,
    )

    def totals(data_count: int, stream_count: int = 1) -> dict[str, int]:
        base = stream_count * (len(base_open) + data_count * len(base_data))
        per_frame = stream_count * (len(base_open) + data_count * len(per_frame_data))
        inherited = stream_count * (len(inherited_open) + data_count * len(base_data))
        beaconed = len(beacon) + stream_count * (len(base_open) + data_count * len(base_data))
        return {
            "baseline_no_semantics": base,
            "per_frame_braid_state": per_frame,
            "inherited_open_defaults": inherited,
            "beaconed_context": beaconed,
        }

    one_stream_10 = totals(10, 1)
    one_stream_1000 = totals(1000, 1)
    ten_streams_100 = totals(100, 10)

    inherited_saving_vs_per_frame_1000 = one_stream_1000["per_frame_braid_state"] - one_stream_1000["inherited_open_defaults"]
    beacon_saving_vs_per_frame_1000 = one_stream_1000["per_frame_braid_state"] - one_stream_1000["beaconed_context"]

    per_frame_extra_per_data = len(per_frame_data) - len(base_data)
    inherited_extra_per_stream = len(inherited_open) - len(base_open)
    beacon_extra_total = len(beacon)
    inherited_break_even_data_frames = 1 + (inherited_extra_per_stream // max(per_frame_extra_per_data, 1))
    beacon_break_even_data_frames = (beacon_extra_total + per_frame_extra_per_data - 1) // max(per_frame_extra_per_data, 1)

    return {
        "wire_examples": {
            "stream_open_base_hex": base_open.hex(),
            "stream_open_inherited_hex": inherited_open.hex(),
            "stream_data_base_hex": base_data.hex(),
            "stream_data_per_frame_hex": per_frame_data.hex(),
            "beacon_hex": beacon.hex(),
        },
        "lengths": {
            "stream_open_base": len(base_open),
            "stream_open_inherited": len(inherited_open),
            "stream_data_base": len(base_data),
            "stream_data_per_frame": len(per_frame_data),
            "beacon": len(beacon),
            "per_frame_extra_per_data": per_frame_extra_per_data,
            "inherited_extra_per_stream": inherited_extra_per_stream,
        },
        "totals": {
            "one_stream_10_data": one_stream_10,
            "one_stream_1000_data": one_stream_1000,
            "ten_streams_100_data_each": ten_streams_100,
        },
        "break_even": {
            "inherited_vs_per_frame_data_frames": inherited_break_even_data_frames,
            "beacon_vs_per_frame_data_frames": beacon_break_even_data_frames,
        },
        "summary": {
            "state243_label": state.label(),
            "braid243_value": braid,
            "inherited_saving_vs_per_frame_1000": inherited_saving_vs_per_frame_1000,
            "beacon_saving_vs_per_frame_1000": beacon_saving_vs_per_frame_1000,
        },
    }



def render_braid_cadence_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Braid cadence transport comparison")
    lines.append("")
    lines.append("This report isolates the cost of carrying semantic cadence on stream traffic. The baseline is a stream with no semantic bytes. The per-frame case appends Braid243 + State243 to every DATA frame. The inherited case sets Braid243 + State243 once in STREAM_OPEN and lets DATA inherit. The beaconed case pushes the semantics once in a BEACON_INTENT frame and leaves the stream itself clean.")
    lines.append("")
    lines.append("## Primitive frame lengths")
    lines.append("")
    lines.append("| Frame variant | Bytes |")
    lines.append("|---|---:|")
    for key, value in payload["lengths"].items():
        lines.append(f"| {key} | {value} |")
    lines.append("")
    for cohort_name, variants in payload["totals"].items():
        lines.append(f"## {cohort_name}")
        lines.append("")
        lines.append("| Strategy | Total bytes |")
        lines.append("|---|---:|")
        for key, value in variants.items():
            lines.append(f"| {key} | {value} |")
        lines.append("")
    lines.append("## Break-even")
    lines.append("")
    lines.append(f"- Inherited defaults beat per-frame semantics after {payload['break_even']['inherited_vs_per_frame_data_frames']} data frames.")
    lines.append(f"- A separate beacon beats per-frame semantics after {payload['break_even']['beacon_vs_per_frame_data_frames']} data frames, and becomes even better when multiple streams share the same braid/state context.")
    lines.append("")
    lines.append("## Bottom line")
    lines.append("")
    lines.append("The braid is cheapest when it rides the cadence boundary instead of the data boundary. Put default semantics in STREAM_OPEN when a stream is semantically coherent. Move shared semantics into BEACON_INTENT when many streams or agents share the same context. Only pay per-frame semantic bytes when the semantics themselves are changing at frame rate.")
    return "\n".join(lines)
