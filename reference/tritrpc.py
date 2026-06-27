
"""
TritRPC v1 reference (Path-A focus) — pack/parse + vectors
- TritPack243 pack/unpack
- TLEB3 encode/decode
- Envelope builder/parser (SERVICE + METHOD, AUX, AEAD lane)
- Avro subset encoder for Hello/Choose/Error + Hypergraph ops
- Streaming with rolling XChaCha20-Poly1305 (or MAC fallback)
"""
from __future__ import annotations
import hashlib, json, struct
from dataclasses import dataclass
from typing import List, Tuple, Optional

# ===== TritPack243 =====

def tritpack243_pack(trits: List[int]) -> bytes:
    out = bytearray()
    i = 0
    while i + 5 <= len(trits):
        val = 0
        for t in trits[i:i+5]:
            if t not in (0,1,2): raise ValueError("invalid trit")
            val = val*3 + t
        out.append(val)  # 0..242
        i += 5
    k = len(trits) - i
    if k > 0:
        out.append(243 + (k-1))
        val = 0
        for t in trits[i:]:
            val = val*3 + t
        out.append(val)
    return bytes(out)

def tritpack243_unpack(b: bytes) -> List[int]:
    i = 0
    trits: List[int] = []
    while i < len(b):
        byte = b[i]; i += 1
        if byte <= 242:
            # expand to 5 trits big-endian base-3
            val = byte
            group = [0,0,0,0,0]
            for j in range(4,-1,-1):
                group[j] = val % 3
                val //= 3
            trits.extend(group)
        elif 243 <= byte <= 246:
            k = (byte - 243) + 1
            if i >= len(b): raise ValueError("trunc tail marker")
            val = b[i]; i += 1
            group = [0]*k
            for j in range(k-1, -1, -1):
                group[j] = val % 3; val //= 3
            trits.extend(group)
        else:
            raise ValueError("invalid byte in canonical output (247..255)")
    return trits

# ===== TLEB3 =====

def tleb3_len_encode(n: int) -> bytes:
    if n < 0: raise ValueError("negative length")
    digits = []
    if n == 0: digits = [0]
    else:
        while n>0:
            digits.append(n % 9)
            n //= 9
    trits: List[int] = []
    for i, d in enumerate(digits):
        C = 2 if i < len(digits)-1 else 0
        P1, P0 = divmod(d, 3)
        trits += [C, P1, P0]
    return tritpack243_pack(trits)

def tleb3_len_decode(b: bytes, offset: int) -> Tuple[int, int]:
    """Decode a TLEB3 length starting at offset; returns (value, new_offset)."""
    # We need to parse packed trits out of the stream. We can consume bytes until we reach a trit with C=0.
    # Because tritpack groups in 5-trit bundles, we decode incrementally.
    # Simpler approach: decode progressively while buffering trits.
    i = offset
    tritbuf: List[int] = []
    # We don't know how many bytes; read at least 1 group
    while True:
        if i >= len(b): raise ValueError("EOF in TLEB3")
        chunk = b[i:i+1]
        i += 1
        ts = tritpack243_unpack(chunk)  # ok for single byte
        tritbuf.extend(ts)
        # scan tritlets
        # tritlets = groups of 3
        if len(tritbuf) < 3: 
            continue
        # Try to parse; continuation 2 except last 0
        val = 0
        ok = False
        # parse all complete tritlets and stop at first C=0
        for j in range(0, len(tritbuf)//3):
            C,P1,P0 = tritbuf[3*j:3*j+3]
            digit = P1*3 + P0
            val += digit * (9**j)
            if C == 0:
                # we've consumed j+1 tritlets; but tritbuf may contain extra trits from the same packed byte.
                # compute how many trits used:
                trits_used = (j+1)*3
                # compute how many bytes were actually needed for these trits:
                # We can't easily reverse-pack; instead, re-encode just those trits and count bytes.
                enc = tritpack243_pack(tritbuf[:trits_used])
                used_bytes = len(enc)
                # Step back to offset + used_bytes
                return val, offset + used_bytes
        # else need more bytes

# ===== Avro subset encoders (Path-A) =====

def zigzag(n: int) -> int:
    return (n << 1) ^ (n >> 63)

def enc_varint(u: int) -> bytes:
    b = bytearray()
    while (u & ~0x7F) != 0:
        b.append((u & 0x7F) | 0x80)
        u >>= 7
    b.append(u)
    return bytes(b)

def enc_long(n:int) -> bytes:
    return enc_varint(zigzag(n))

def enc_int(n:int) -> bytes: return enc_long(n)
def enc_bool(v:bool)->bytes: return b"\x01" if v else b"\x00"
def enc_string(s:str)->bytes:
    bs = s.encode("utf-8")
    return enc_long(len(bs)) + bs
def enc_bytes(b:bytes)->bytes:
    return enc_long(len(b)) + b
def enc_array(items, enc_item)->bytes:
    if not items: return b"\x00"
    out = bytearray()
    out += enc_long(len(items))
    for it in items: out += enc_item(it)
    out += b"\x00"
    return bytes(out)
def enc_map(m:dict, enc_val)->bytes:
    if not m: return b"\x00"
    out = bytearray()
    out += enc_long(len(m))
    for k,v in m.items():
        out += enc_string(k)
        out += enc_val(v)
    out += b"\x00"
    return bytes(out)
def enc_union(index:int, payload:bytes)->bytes:
    return enc_long(index) + payload
def enc_enum(index:int)->bytes: return enc_int(index)

# --- Hello/Choose/Error Avro payloads ---
def enc_Hello(modes:list[str], aead_suites:list[str], compression:list[str], contextURI:Optional[str]=None)->bytes:
    # Hello { modes:[string], aead_suites:[string], compression:[string], contextURI? }
    out = bytearray()
    out += enc_array(modes, enc_string)
    out += enc_array(aead_suites, enc_string)
    out += enc_array(compression, enc_string)
    if contextURI is None:
        out += enc_union(0, b"")
    else:
        out += enc_union(1, enc_string(contextURI))
    return bytes(out)

def enc_Choose(mode:str, aead_suite:str, compression:str)->bytes:
    out = bytearray()
    out += enc_string(mode)
    out += enc_string(aead_suite)
    out += enc_string(compression)
    return bytes(out)

def enc_Error(code:int, message:str, details:Optional[bytes]=None)->bytes:
    out = bytearray()
    out += enc_int(code)
    out += enc_string(message)
    if details is None: out += enc_union(0, b"")
    else: out += enc_union(1, enc_bytes(details))
    return bytes(out)

# --- Hypergraph Avro payloads ---
def enc_Vertex(vid:str, label:Optional[str], attr:dict)->bytes:
    out = bytearray()
    out += enc_string(vid)
    out += enc_union(1, enc_string(label)) if label is not None else enc_union(0, b"")
    out += enc_map(attr, enc_string)
    return bytes(out)

def enc_Hyperedge(eid:str, members:list[str], weight:Optional[int], attr:dict)->bytes:
    out = bytearray()
    out += enc_string(eid)
    out += enc_array(members, enc_string)
    out += enc_union(1, enc_long(weight)) if weight is not None else enc_union(0, b"")
    out += enc_map(attr, enc_string)
    return bytes(out)

def enc_HGRequest_AddVertex(vertex:dict)->bytes:
    out = bytearray()
    out += enc_enum(0)  # AddVertex
    out += enc_union(1, enc_Vertex(vertex["vid"], vertex.get("label"), vertex.get("attr",{})))
    out += enc_union(0, b"")  # edge null
    out += enc_union(0, b"")  # vid null
    out += enc_union(0, b"")  # eid null
    out += enc_union(0, b"")  # k null
    return bytes(out)

def enc_HGRequest_AddHyperedge(edge:dict)->bytes:
    out = bytearray()
    out += enc_enum(1)  # AddHyperedge
    out += enc_union(0, b"")  # vertex null
    out += enc_union(1, enc_Hyperedge(edge["eid"], edge["members"], edge.get("weight"), edge.get("attr",{})))
    out += enc_union(0, b"")  # vid null
    out += enc_union(0, b"")  # eid null
    out += enc_union(0, b"")  # k null
    return bytes(out)

def enc_HGRequest_RemoveVertex(vid:str)->bytes:
    out = bytearray()
    out += enc_enum(2)  # RemoveVertex
    out += enc_union(0, b"")
    out += enc_union(0, b"")
    out += enc_union(1, enc_string(vid))
    out += enc_union(0, b"")
    out += enc_union(0, b"")
    return bytes(out)

def enc_HGRequest_RemoveHyperedge(eid:str)->bytes:
    out = bytearray()
    out += enc_enum(3)  # RemoveHyperedge
    out += enc_union(0, b"")
    out += enc_union(0, b"")
    out += enc_union(0, b"")
    out += enc_union(1, enc_string(eid))
    out += enc_union(0, b"")
    return bytes(out)

def enc_HGRequest_QueryNeighbors(vid:str, k:int)->bytes:
    out = bytearray()
    out += enc_enum(4)  # QueryNeighbors
    out += enc_union(0, b"")
    out += enc_union(0, b"")
    out += enc_union(1, enc_string(vid))
    out += enc_union(0, b"")
    out += enc_union(1, enc_int(k))
    return bytes(out)

def enc_HGRequest_GetSubgraph(vid:str, k:int)->bytes:
    out = bytearray()
    out += enc_enum(5)  # GetSubgraph
    out += enc_union(0, b"")
    out += enc_union(0, b"")
    out += enc_union(1, enc_string(vid))
    out += enc_union(0, b"")
    out += enc_union(1, enc_int(k))
    return bytes(out)

# ===== Envelope fields =====
MAGIC_B2 = bytes.fromhex("f3 2a")  # Appendix A normative example; treat as fixed B2 canonical for 9-trit constant
VER_TRITS   = [1]  # v1
MODE_TRITS  = [0]  # B2
def flags_trits(aead:bool, compress:bool=False)->List[int]:
    return [2 if aead else 0, 2 if compress else 0, 0]  # interpret as bits (2==true)

# IDs (32 bytes each). For vectors, fix them.
SCHEMA_ID = hashlib.sha3_256(b"HG_AVRO_v1").digest()
CONTEXT_ID = hashlib.sha3_256(b"HG_JSONLD_v1").digest()

def len_prefix(b: bytes) -> bytes:
    return tleb3_len_encode(len(b))

def build_envelope(service:str, method:str, payload:bytes, aux:Optional[bytes], aead_tag:Optional[bytes], aead_on:bool, compress:bool=False) -> bytes:
    out = bytearray()
    # Pack fixed trit segments independently (equivalent to ABNF Pack(B3[n]) per segment)
    out += len_prefix(MAGIC_B2) + MAGIC_B2
    ver_b = tritpack243_pack(VER_TRITS)
    out += len_prefix(ver_b) + ver_b
    mode_b = tritpack243_pack(MODE_TRITS)
    out += len_prefix(mode_b) + mode_b
    flags_b = tritpack243_pack(flags_trits(aead_on, compress))
    out += len_prefix(flags_b) + flags_b
    # IDs
    out += len_prefix(SCHEMA_ID) + SCHEMA_ID
    out += len_prefix(CONTEXT_ID) + CONTEXT_ID
    # SERVICE, METHOD, PAYLOAD, AUX?, AEAD?
    svc_b = service.encode("utf-8")
    m_b = method.encode("utf-8")
    out += len_prefix(svc_b) + svc_b
    out += len_prefix(m_b) + m_b
    out += len_prefix(payload) + payload
    if aux is not None:
        out += len_prefix(aux) + aux
    if aead_tag is not None:
        out += len_prefix(aead_tag) + aead_tag
    return bytes(out)

# ===== AEAD =====
def aead_compute_tag(aad: bytes, key: bytes, nonce: bytes) -> Tuple[bytes,str]:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
        aead = XChaCha20Poly1305(key)
        ct = aead.encrypt(nonce, b"", aad)
        return ct[-16:], "XCHACHA20-POLY1305"
    except Exception:
        # fallback mac (non-AEAD)
        h = hashlib.blake2b(aad, key=key, digest_size=16)
        return h.digest(), "BLAKE2b-MAC"

# ===== AUX PoE (Avro as bytes in a map field) =====
def enc_PoE(schema_id_hex:str, context_id_hex:str, payload_digest:bytes, method:str, timestamp:int, signer:str)->bytes:
    # PoE { schema_id, context_id, payload_digest, method, timestamp, signer }
    out = bytearray()
    out += enc_string(schema_id_hex)
    out += enc_string(context_id_hex)
    out += enc_bytes(payload_digest)
    out += enc_string(method)
    out += enc_long(timestamp)
    out += enc_string(signer)
    return bytes(out)

# ===== Rolling nonce for streaming =====
def derive_stream_nonce(base:bytes, chunk_index:int)->bytes:
    # 24-byte XChaCha nonce; increment last 4 bytes as big-endian counter
    if len(base) != 24: raise ValueError("base nonce must be 24 bytes")
    prefix = base[:-4]
    ctr = int.from_bytes(base[-4:], "big") + chunk_index
    return prefix + (ctr & 0xffffffff).to_bytes(4, "big")

# ===== Kafka mapping =====
def kafka_record(value_bytes: bytes, key_fields: tuple[str,str,str,str]) -> dict:
    key = "|".join(key_fields).encode("utf-8")
    return {"key_hex": key.hex(), "value_hex": value_bytes.hex()}



# ===== Additional encoders: Trace, HGResponse, HGStream* (toy Path-A subset) =====
def enc_Trace(trace_id:str, span_id:str, parent:Optional[str])->bytes:
    out = bytearray()
    out += enc_string(trace_id)
    out += enc_string(span_id)
    if parent is None:
        out += enc_union(0, b"")
    else:
        out += enc_union(1, enc_string(parent))
    return bytes(out)

def enc_HGResponse(ok:bool, err:Optional[str], vertices:list[dict], edges:list[dict])->bytes:
    def _enc_vertex(v): return enc_Vertex(v["vid"], v.get("label"), v.get("attr", {}))
    def _enc_edge(e): return enc_Hyperedge(e["eid"], e.get("members", []), e.get("weight"), e.get("attr", {}))
    out = bytearray()
    out += enc_bool(ok)
    if err is None:
        out += enc_union(0, b"")
    else:
        out += enc_union(1, enc_string(err))
    out += enc_array(vertices, _enc_vertex)
    out += enc_array(edges, _enc_edge)
    return bytes(out)

# Stream chunk records encoded as: Open(trace, req_bytes), Data(trace, chunkIndex, resp_bytes), Close(poe_bytes?)
def enc_HGStreamOpen(trace:dict, req_bytes:bytes)->bytes:
    out = bytearray()
    out += enc_Trace(trace["trace_id"], trace["span_id"], trace.get("parent_span_id"))
    out += enc_bytes(req_bytes)
    return bytes(out)

def enc_HGStreamData(trace:dict, chunk_index:int, resp_bytes:bytes)->bytes:
    out = bytearray()
    out += enc_Trace(trace["trace_id"], trace["span_id"], trace.get("parent_span_id"))
    out += enc_int(chunk_index)
    out += enc_bytes(resp_bytes)
    return bytes(out)

def enc_HGStreamClose(poe_bytes:Optional[bytes])->bytes:
    if poe_bytes is None:
        return enc_union(0, b"")  # union [null, bytes] → null
    else:
        return enc_union(1, enc_bytes(poe_bytes))



# ===== Generic HGRequest dispatcher (by op string) =====
def enc_HGRequest(obj: dict) -> bytes:
    """Encode HGRequest from a dict with 'op' and associated fields."""
    op = obj.get("op")
    if op == "AddVertex":
        return enc_HGRequest_AddVertex(obj["vertex"])
    if op == "AddHyperedge":
        return enc_HGRequest_AddHyperedge(obj["edge"])
    if op == "RemoveVertex":
        return enc_HGRequest_RemoveVertex(obj["vid"])
    if op == "RemoveHyperedge":
        return enc_HGRequest_RemoveHyperedge(obj["eid"])
    if op == "QueryNeighbors":
        return enc_HGRequest_QueryNeighbors(obj["vid"], obj.get("k", 1))
    if op == "GetSubgraph":
        return enc_HGRequest_GetSubgraph(obj["vid"], obj.get("k", 1))
    raise ValueError(f"Unknown op: {op}")

# ===== Nested stream chunk records (no *_bytes fields) =====
def enc_HGStreamOpenN(trace:dict, request_obj:dict)->bytes:
    # record: { trace:Trace, request:HGRequest }
    out = bytearray()
    out += enc_Trace(trace["trace_id"], trace["span_id"], trace.get("parent_span_id"))
    out += enc_HGRequest(request_obj)
    return bytes(out)

def enc_HGStreamDataN(trace:dict, chunk_index:int, response_obj:dict)->bytes:
    # record: { trace:Trace, chunk_index:int, response:HGResponse }
    out = bytearray()
    out += enc_Trace(trace["trace_id"], trace["span_id"], trace.get("parent_span_id"))
    out += enc_int(chunk_index)
    out += enc_HGResponse(response_obj.get("ok", True),
                          response_obj.get("err"),
                          response_obj.get("vertices", []),
                          response_obj.get("edges", []))
    return bytes(out)

def enc_HGStreamCloseN(poe_obj:dict|None)->bytes:
    # union [null, PoE]
    if poe_obj is None:
        return enc_union(0, b"")
    else:
        return enc_union(1, enc_PoE(poe_obj["schema_id"], poe_obj["context_id"],
                                    poe_obj["payload_digest"], poe_obj["method"],
                                    poe_obj["timestamp"], poe_obj["signer"]))
