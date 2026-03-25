from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, List

MAGIC_B2 = bytes([0xF3, 0x2A])
TEST_TAG_KEY = b'TRITRPC_PATH_H_DRAFT_TEST_KEY_32'

KIND243 = {'unary_req': 0, 'unary_rsp': 1, 'stream_open': 2, 'stream_data': 3, 'stream_close': 4, 'beacon_cap': 5, 'beacon_intent': 6, 'beacon_commit': 7, 'error': 8}
ROUTE_H = {'PAIR.OPEN': 11, 'PAIR.HERALD': 12, 'TELEPORT.BSM3': 13, 'FRAME.DEFER': 14, 'WITNESS.REPORT': 15}
PAIR_KIND = {'qubit': 0, 'qutrit': 1}
ENCODING_KIND = {'unknown': 0, 'time-bin': 1, 'frequency-bin': 2, 'path': 3, 'memory-backed': 4}
SUBJECT_KIND = {'link': 0, 'pair': 1, 'path': 2, 'memory': 3, 'swap': 4}
CLOCK_QUALITY = {'ok': 0, 'degraded': 1, 'holdover': 2}
CTRL_MAP = {'PAIR.OPEN': {'profile': 2, 'lane': 2, 'evidence': 0, 'fallback': 1, 'routefmt': 1}, 'PAIR.HERALD': {'profile': 2, 'lane': 1, 'evidence': 1, 'fallback': 0, 'routefmt': 1}, 'TELEPORT.BSM3': {'profile': 2, 'lane': 2, 'evidence': 0, 'fallback': 0, 'routefmt': 1}, 'FRAME.DEFER': {'profile': 2, 'lane': 2, 'evidence': 0, 'fallback': 1, 'routefmt': 1}, 'WITNESS.REPORT': {'profile': 2, 'lane': 2, 'evidence': 2, 'fallback': 0, 'routefmt': 1}}

def tritpack243(trits: List[int]) -> bytes:
    out = bytearray()
    i = 0
    while i + 5 <= len(trits):
        val = 0
        for t in trits[i:i+5]:
            if not (0 <= t <= 2):
                raise ValueError("invalid trit")
            val = val * 3 + t
        out.append(val)
        i += 5
    k = len(trits) - i
    if k > 0:
        out.append(243 + (k - 1))
        val = 0
        for t in trits[i:]:
            if not (0 <= t <= 2):
                raise ValueError("invalid trit")
            val = val * 3 + t
        out.append(val)
    return bytes(out)

def tleb3_encode_len(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative length")
    if n == 0:
        digits = [0]
    else:
        digits = []
        while n > 0:
            digits.append(n % 9)
            n //= 9
    trits: List[int] = []
    for i, d in enumerate(digits):
        c = 2 if i < len(digits) - 1 else 0
        p1 = d // 3
        p0 = d % 3
        trits.extend([c, p1, p0])
    return tritpack243(trits)

def s243(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative integer")
    if n <= 242:
        return bytes([n])
    return bytes([243]) + tleb3_encode_len(n - 243)

def h243(h: int) -> bytes:
    if not (0 <= h <= 242):
        raise ValueError("handle out of short range")
    return bytes([h])

def u8(n: int) -> bytes:
    if not (0 <= n <= 255):
        raise ValueError("u8 range")
    return bytes([n])

def u16be(n: int) -> bytes:
    if not (0 <= n <= 65535):
        raise ValueError("u16 range")
    return n.to_bytes(2, "big")

def u64be(n: int) -> bytes:
    if not (0 <= n <= (1 << 64) - 1):
        raise ValueError("u64 range")
    return n.to_bytes(8, "big")

def bool8(v: bool) -> bytes:
    return bytes([1 if v else 0])

def ctrl243(profile: int, lane: int, evidence: int, fallback: int, routefmt: int) -> bytes:
    return tritpack243([profile, lane, evidence, fallback, routefmt])

def bsm3_u8(code: str) -> bytes:
    if len(code) != 2 or any(c not in "012" for c in code):
        raise ValueError("bsm3_code must be a 2-trit string")
    return bytes([int(code[0]) * 3 + int(code[1])])

def encode_pair_open(obj: Dict[str, Any]) -> bytes:
    flags = (1 if obj["need_memory"] else 0) | ((1 if obj["need_teleport_ready"] else 0) << 1)
    return b"".join([
        s243(obj["seq"]),
        h243(obj["src_site"]),
        h243(obj["dst_site"]),
        u8(PAIR_KIND[obj["pair_kind"]]),
        u8(ENCODING_KIND[obj["encoding_kind"]]),
        u16be(obj["target_fidelity_milli"]),
        s243(obj["ttl_ms"]),
        u8(flags),
    ])

def encode_pair_herald(obj: Dict[str, Any]) -> bytes:
    return b"".join([
        s243(obj["seq"]),
        h243(obj["pair_id"]),
        h243(obj["src_site"]),
        h243(obj["dst_site"]),
        u8(ENCODING_KIND[obj["encoding_kind"]]),
        bool8(obj["herald_success"]),
        u64be(obj["ts_ns"]),
        u16be(obj["fidelity_milli"]),
        u16be(obj["visibility_milli"]),
        s243(obj["ttl_ms"]),
    ])

def encode_teleport_bsm3(obj: Dict[str, Any]) -> bytes:
    flags = (1 if obj["defer_ok"] else 0) | ((1 if obj.get("mem_id") is not None else 0) << 1)
    parts = [
        s243(obj["seq"]),
        h243(obj["pair_id"]),
        u8(obj["basis_id"]),
        bsm3_u8(obj["bsm3_code"]),
        u64be(obj["ts_ns"]),
        u8(flags),
    ]
    if obj.get("mem_id") is not None:
        parts.append(h243(obj["mem_id"]))
    return b"".join(parts)

def encode_frame_defer(obj: Dict[str, Any]) -> bytes:
    return b"".join([
        s243(obj["seq"]),
        h243(obj["pair_id"]),
        u8(obj["frame_shift_x"]),
        u8(obj["frame_shift_z"]),
        s243(obj["frame_epoch"]),
        u64be(obj["ts_ns"]),
    ])

def encode_witness_report(obj: Dict[str, Any]) -> bytes:
    return b"".join([
        s243(obj["seq"]),
        u8(SUBJECT_KIND[obj["subject_kind"]]),
        h243(obj["subject_id"]),
        u64be(obj["delay_ns"]),
        u16be(obj["fidelity_milli"]),
        u16be(obj["visibility_milli"]),
        u16be(obj["snr_milli"]),
        u8(CLOCK_QUALITY[obj["clock_quality_code"]]),
        h243(obj["env_ref"]),
        u64be(obj["ts_ns"]),
    ])

PAYLOAD_ENCODERS = {
    "PAIR.OPEN": encode_pair_open,
    "PAIR.HERALD": encode_pair_herald,
    "TELEPORT.BSM3": encode_teleport_bsm3,
    "FRAME.DEFER": encode_frame_defer,
    "WITNESS.REPORT": encode_witness_report,
}

def test_tag(aad: bytes) -> bytes:
    return hmac.new(TEST_TAG_KEY, aad, hashlib.sha256).digest()[:16]

def encode_frame(event_name: str, obj: Dict[str, Any], *, epoch: int = 18, kind: str = "unary_req") -> bytes:
    if event_name not in PAYLOAD_ENCODERS:
        raise KeyError(f"unknown event {event_name}")
    ctrl = ctrl243(**CTRL_MAP[event_name])
    payload = PAYLOAD_ENCODERS[event_name](obj)
    front = b"".join([
        MAGIC_B2,
        ctrl,
        u8(KIND243[kind]),
        s243(epoch),
        h243(ROUTE_H[event_name]),
        s243(len(payload)),
        payload,
    ])
    return front + test_tag(front)

if __name__ == "__main__":
    samples = {'PAIR.OPEN': {'seq': 1, 'src_site': 7, 'dst_site': 19, 'pair_kind': 'qutrit', 'encoding_kind': 'frequency-bin', 'target_fidelity_milli': 965, 'ttl_ms': 180, 'need_memory': True, 'need_teleport_ready': True}, 'PAIR.HERALD': {'seq': 2, 'pair_id': 61, 'src_site': 7, 'dst_site': 19, 'encoding_kind': 'frequency-bin', 'herald_success': True, 'ts_ns': 1731000000123456789, 'fidelity_milli': 951, 'visibility_milli': 944, 'ttl_ms': 167}, 'TELEPORT.BSM3': {'seq': 3, 'pair_id': 61, 'basis_id': 2, 'bsm3_code': '12', 'ts_ns': 1731000001123456789, 'mem_id': 9, 'defer_ok': True}, 'FRAME.DEFER': {'seq': 4, 'pair_id': 61, 'frame_shift_x': 1, 'frame_shift_z': 2, 'frame_epoch': 1, 'ts_ns': 1731000002123456789}, 'WITNESS.REPORT': {'seq': 5, 'subject_kind': 'pair', 'subject_id': 61, 'delay_ns': 5000000, 'fidelity_milli': 947, 'visibility_milli': 939, 'snr_milli': 1820, 'clock_quality_code': 'degraded', 'env_ref': 33, 'ts_ns': 1731000003123456789}}
    for name, obj in samples.items():
        print(name, encode_frame(name, obj).hex())
