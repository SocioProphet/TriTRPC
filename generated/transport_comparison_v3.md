# TriTRPC vs Protobuf vs Thrift transport comparison

This report compares concrete wire lengths for equivalent authenticated hot-path frames and a few payload-only surfaces. It is intentionally generous to the competitors: protobuf and Thrift are shown both in straightforward handle-based form and in manually fused forms that combine control/kind/suite into one small scalar.

## Small secure frame constants

- Hot unary: TriTRPC = P + 24, protobuf(handle) = P + 28, protobuf(fused) = P + 26, thrift compact(handle) = P + 31, thrift compact(fused) = P + 27.
- Stream OPEN: TriTRPC = P + 25, protobuf(handle) = P + 32, protobuf(fused) = P + 28, thrift compact(handle) = P + 33, thrift compact(fused) = P + 29.
- Stream DATA: TriTRPC = P + 24, protobuf(handle) = P + 30, protobuf(fused) = P + 26, thrift compact(handle) = P + 31, thrift compact(fused) = P + 27.

## hot_unary_small_secure

Authenticated hot unary request with handle route and 28-byte JSON payload.

| Variant | Bytes |
|---|---:|
| tritrpc | 52 |
| protobuf_fused | 54 |
| thrift_compact_fused | 55 |
| protobuf_handle | 56 |
| thrift_compact_handle | 59 |
| protobuf_inline | 87 |
| thrift_binary_handle | 88 |
| thrift_compact_inline | 90 |

- TriTRPC advantage here comes from one-byte Control243, one-byte S243 integers, fixed hot framing, and a built-in 16-byte tag.
- The fused protobuf/thrift variants are deliberately generous competitors that manually combine control/kind/suite into a single small scalar.

## stream_open_small_secure

Authenticated stream OPEN with handle route, stream_id, and 18-byte JSON payload.

| Variant | Bytes |
|---|---:|
| tritrpc | 43 |
| protobuf_fused | 46 |
| thrift_compact_fused | 47 |
| protobuf_handle | 50 |
| thrift_compact_handle | 51 |

- Once stream state is established, TriTRPC avoids repeating route metadata on DATA frames.

## stream_data_small_secure

Authenticated stream DATA with stream_id and 11-byte JSON payload.

| Variant | Bytes |
|---|---:|
| tritrpc | 35 |
| protobuf_fused | 37 |
| thrift_compact_fused | 38 |
| protobuf_handle | 41 |
| thrift_compact_handle | 42 |

- This is the cleanest hot-path comparison because route metadata is already interned away.

## hot_unary_large_secure_1024

Authenticated hot unary request with 1024-byte opaque payload.

| Variant | Bytes |
|---|---:|
| protobuf_fused | 1051 |
| tritrpc | 1052 |
| thrift_compact_fused | 1052 |
| protobuf_handle | 1053 |
| thrift_compact_handle | 1056 |

- As payload size grows, fixed-header differences become nearly irrelevant; in this benchmark, manually fused protobuf edges TriTRPC by one byte.

## tristate_vector_100_payload_only

Payload-only comparison for 100 values in {0,1,2}.

| Variant | Bytes |
|---|---:|
| tritrpc_tritpack243 | 20 |
| protobuf_packed_uint32 | 102 |
| thrift_compact_list_i32 | 104 |
| thrift_binary_list_i32 | 409 |

- This is where ternary-native packing creates a categorical advantage, because the payload alphabet itself is ternary.

## braid243_coordinate_only

Coordinate-only comparison for one 7x23 braid state (phase 4, topic 14).

| Variant | Bytes |
|---|---:|
| tritrpc_braid243 | 1 |
| protobuf_combined_coord | 2 |
| protobuf_split_phase_topic | 4 |
| thrift_compact_combined_coord | 4 |
| thrift_compact_split_phase_topic | 5 |

- Seven phases times 23 topics gives 161 live states, which fit inside one 5-trit byte.

## 100-frame totals

### hot_unary_small_secure

| Variant | Bytes / 100 frames |
|---|---:|
| tritrpc | 5200 |
| protobuf_fused | 5400 |
| thrift_compact_fused | 5500 |
| protobuf_handle | 5600 |
| thrift_compact_handle | 5900 |
| protobuf_inline | 8700 |
| thrift_binary_handle | 8800 |
| thrift_compact_inline | 9000 |

### stream_data_small_secure

| Variant | Bytes / 100 frames |
|---|---:|
| tritrpc | 3500 |
| protobuf_fused | 3700 |
| thrift_compact_fused | 3800 |
| protobuf_handle | 4100 |
| thrift_compact_handle | 4200 |

## Bottom line

TriTRPC wins most clearly on four surfaces: authenticated hot control frames, true stream DATA frames after route interning, payloads whose native alphabet is ternary or otherwise very low-cardinality, and any workload that would otherwise repeat long route strings. The gap collapses on large opaque payloads, and it can be narrowed substantially if protobuf or Thrift are given equivalent application-level intelligence such as fused headers and handle dictionaries. In the large-payload benchmark here, fused protobuf is actually one byte smaller than TriTRPC, so the honest claim is not universal dominance but a strong advantage on the agentic hot path TriTRPC is designed for.
