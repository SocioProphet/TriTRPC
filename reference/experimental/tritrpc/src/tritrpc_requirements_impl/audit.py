from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from .frames import Frame, serialize_frame


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    timestamp: str
    event_type: str
    decision: str
    suite: str
    frame_kind: str | None = None
    braided_identity: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = ""
    record_hash: str = ""

    def unsigned_mapping(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "decision": self.decision,
            "suite": self.suite,
            "frame_kind": self.frame_kind,
            "braided_identity": self.braided_identity,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }



def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")



def compute_record_hash(record: AuditRecord, hash_name: str = "sha384") -> str:
    hasher = hashlib.new(hash_name)
    hasher.update(_canonical_json(record.unsigned_mapping()))
    return hasher.hexdigest()



def append_audit_record(chain: list[AuditRecord], record: AuditRecord, hash_name: str = "sha384") -> AuditRecord:
    previous_hash = chain[-1].record_hash if chain else ""
    new_record = AuditRecord(
        sequence=record.sequence,
        timestamp=record.timestamp,
        event_type=record.event_type,
        decision=record.decision,
        suite=record.suite,
        frame_kind=record.frame_kind,
        braided_identity=record.braided_identity,
        details=record.details,
        previous_hash=previous_hash,
        record_hash="",
    )
    return AuditRecord(**{**new_record.__dict__, "record_hash": compute_record_hash(new_record, hash_name=hash_name)})



def verify_audit_chain(chain: Iterable[AuditRecord], hash_name: str = "sha384") -> bool:
    previous_hash = ""
    for index, record in enumerate(chain, start=1):
        if record.sequence != index:
            return False
        if record.previous_hash != previous_hash:
            return False
        if compute_record_hash(record, hash_name=hash_name) != record.record_hash:
            return False
        previous_hash = record.record_hash
    return True



def audit_record_from_frame(
    frame: Frame,
    timestamp: str,
    decision: str,
    details: dict[str, Any] | None = None,
    braided_identity: str | None = None,
) -> AuditRecord:
    serialized = serialize_frame(frame)
    return AuditRecord(
        sequence=0,
        timestamp=timestamp,
        event_type="frame-emit",
        decision=decision,
        suite=frame.suite.name,
        frame_kind=frame.kind.name,
        braided_identity=braided_identity,
        details={
            "frame_len": len(serialized),
            "frame_hex_prefix": serialized[:16].hex(),
            **(details or {}),
        },
    )
