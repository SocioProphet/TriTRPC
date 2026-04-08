from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SemaphoreOp:
    family: str
    op: str
    value: str


@dataclass(frozen=True)
class TypedBeaconDeltaV1:
    schema_version: str
    delta_class: str
    epoch: int
    phase: int | None = None
    topic: int | None = None
    state243: int | None = None
    route_handle: int | None = None
    context_handle: int | None = None
    semaphore_ops: tuple[SemaphoreOp, ...] = ()
    policy_bundle_ref: str | None = None


def encode_typed_beacon_delta(delta: TypedBeaconDeltaV1) -> bytes:
    payload = asdict(delta)
    payload["semaphore_ops"] = [asdict(item) for item in delta.semaphore_ops]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_typed_beacon_delta(payload: bytes) -> TypedBeaconDeltaV1:
    raw = json.loads(payload.decode("utf-8"))
    return TypedBeaconDeltaV1(
        schema_version=str(raw["schema_version"]),
        delta_class=str(raw["delta_class"]),
        epoch=int(raw["epoch"]),
        phase=raw.get("phase"),
        topic=raw.get("topic"),
        state243=raw.get("state243"),
        route_handle=raw.get("route_handle"),
        context_handle=raw.get("context_handle"),
        semaphore_ops=tuple(SemaphoreOp(**item) for item in raw.get("semaphore_ops", [])),
        policy_bundle_ref=raw.get("policy_bundle_ref"),
    )
