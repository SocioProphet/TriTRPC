# TritRPC Path-H Draft Reference Fixtures and Encoder

This file set accompanies the earlier Path-H mini-spec and adds a **simulation-first reference encoder** plus **five canonical draft fixtures**.

## What this is

These fixtures are **draft engineering fixtures**, not the final protocol authority.  
They are meant to prove the shape of the Path-H control lane and support simulator-first work.

## Important note about authentication

The current fixtures use a **deterministic test tag**:

- tag = `HMAC-SHA256(test_key, frame_without_tag)[:16]`

This is only to make the fixtures stable and reproducible while the final profile is still being designed.  
It is **not** the final protocol commitment for `compat-v1`, `hot-v1.1`, or `fips-v1`.

## Hot frame shape used here

`MAGIC[2] | CTRL243[1] | KIND243[1] | epoch[S243] | route_h[Handle243] | payload_len[S243] | payload | tag[16]`

- `MAGIC` reuses the current repo magic: `F3 2A`
- `CTRL243` is 5 trits packed into one byte
- `KIND243` is one direct byte
- `epoch` is encoded with `S243`
- `route_h` is a one-byte short handle in this draft
- `payload_len` is encoded with `S243`
- `tag` is the deterministic draft test tag

## Five canonical draft fixtures

- `PAIR.OPEN`
- `PAIR.HERALD`
- `TELEPORT.BSM3`
- `FRAME.DEFER`
- `WITNESS.REPORT`

## Payload encoding rule in this draft

Payloads are **positional and schema-fixed** by `route_h`.  
That means no per-field tags are placed in the payload for the hot lane.

## bsm3_code

`bsm3_code` is semantically a **two-trit field** with legal values:

`00, 01, 02, 10, 11, 12, 20, 21, 22`

On this draft hot wire, it is encoded as the one-byte canonical numeric image:

- `00 -> 0`
- `01 -> 1`
- `02 -> 2`
- `10 -> 3`
- `11 -> 4`
- `12 -> 5`
- `20 -> 6`
- `21 -> 7`
- `22 -> 8`

That preserves the qutrit-shaped correction alphabet while keeping the hot wire compact.

## Files

- `tritrpc_path_h_reference.py`
- `tritrpc_path_h_fixtures.json`
