# Braid cadence transport comparison

This report isolates the cost of carrying semantic cadence on stream traffic. The baseline is a stream with no semantic bytes. The per-frame case appends Braid243 + State243 to every DATA frame. The inherited case sets Braid243 + State243 once in STREAM_OPEN and lets DATA inherit. The beaconed case pushes the semantics once in a BEACON_INTENT frame and leaves the stream itself clean.

## Primitive frame lengths

| Frame variant | Bytes |
|---|---:|
| stream_open_base | 43 |
| stream_open_inherited | 45 |
| stream_data_base | 35 |
| stream_data_per_frame | 37 |
| beacon | 26 |
| per_frame_extra_per_data | 2 |
| inherited_extra_per_stream | 2 |

## one_stream_10_data

| Strategy | Total bytes |
|---|---:|
| baseline_no_semantics | 393 |
| per_frame_braid_state | 413 |
| inherited_open_defaults | 395 |
| beaconed_context | 419 |

## one_stream_1000_data

| Strategy | Total bytes |
|---|---:|
| baseline_no_semantics | 35043 |
| per_frame_braid_state | 37043 |
| inherited_open_defaults | 35045 |
| beaconed_context | 35069 |

## ten_streams_100_data_each

| Strategy | Total bytes |
|---|---:|
| baseline_no_semantics | 35430 |
| per_frame_braid_state | 37430 |
| inherited_open_defaults | 35450 |
| beaconed_context | 35456 |

## Break-even

- Inherited defaults beat per-frame semantics after 2 data frames.
- A separate beacon beats per-frame semantics after 13 data frames, and becomes even better when multiple streams share the same braid/state context.

## Bottom line

The braid is cheapest when it rides the cadence boundary instead of the data boundary. Put default semantics in STREAM_OPEN when a stream is semantically coherent. Move shared semantics into BEACON_INTENT when many streams or agents share the same context. Only pay per-frame semantic bytes when the semantics themselves are changing at frame rate.