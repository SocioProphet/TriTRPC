#!/usr/bin/env python3
"""Verify SOC relay contracts bind to the TriTRPC Receipt Transport Binding SOC profile.

The Obfuscation-Manifesto relay contract records semantic labour but not the transport path — an
incomplete receipt by the binding's rule. This gate enforces that every SOC relay contract carries
an owner-sealed, URI-addressed transport block, so each hop's receipt is complete-to-owner and
cloaked-to-observers:

  (a) transport is owner-sealed (protocol=tritrpc, sealed:true + sealed_to);
  (b) route_id/peer_id/chain_id/sealed_to use the binding's URI shapes (route://, node://, soc://,
      owner://) — not ad-hoc ids like "relay~kali" — so hops correlate across a trace;
      failure_class (if present) is in the SOC-extended set.

Self-testing (stdlib, repo convention): the canonical example passes; the ad-hoc-id and unsealed
negatives are rejected. A validate_schema drift-guard keeps the schema and this validator in lockstep.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "jsonschema" / "soc-relay-contract.v0.schema.json"
EX = ROOT / "examples" / "transport"
VALID = EX / "soc_relay_contract.example.json"
INVALID = [EX / "soc_relay_contract.adhoc-id.invalid.json", EX / "soc_relay_contract.unsealed.invalid.json"]

TASKS = {"schema_transform", "opaque_compute", "dag_commit", "braid", "relay"}
FAILURE_CLASSES = {"upstream_unreachable", "deadline_exceeded", "sabotage", "refused_by_policy"}
URI = {"route_id": "route://", "peer_id": "node://", "chain_id": "soc://", "sealed_to": "owner://"}
TRANSPORT_KEYS = {"protocol", "route_id", "peer_id", "envelope_hash", "chain_id", "chain_position",
                  "sealed", "sealed_to", "retry_count", "timeout_count", "failure_class"}
CONTRACT_KEYS = {"contract_id", "sender", "relay", "task", "trust_min", "token_bid",
                 "privacy_required", "transport", "signature"}


class ContractError(Exception):
    pass


def fail(m: str) -> None:
    raise ContractError(m)


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def need_str(o: dict, k: str) -> str:
    v = o.get(k)
    if not isinstance(v, str) or not v:
        fail(f"{k}: expected non-empty string")
    return v


def verify_contract(rec: Any) -> None:
    if not isinstance(rec, dict):
        fail("contract must be an object")
    extra = sorted(set(rec) - CONTRACT_KEYS)
    if extra:
        fail(f"unexpected contract fields: {extra}")
    for k in ("contract_id", "sender", "relay", "signature"):
        need_str(rec, k)
    if rec.get("task") not in TASKS:
        fail(f"task must be one of {sorted(TASKS)}")
    if not isinstance(rec.get("trust_min"), int) or rec["trust_min"] < 0:
        fail("trust_min must be a non-negative integer")

    t = rec.get("transport")
    if not isinstance(t, dict):
        fail("transport must be an object (an owner-sealed transport block is required)")
    tx_extra = sorted(set(t) - TRANSPORT_KEYS)
    if tx_extra:
        fail(f"unexpected transport fields: {tx_extra}")
    if t.get("protocol") != "tritrpc":
        fail("transport.protocol must be 'tritrpc'")
    # (b) URI shapes — ad-hoc ids like "relay~kali" are refused
    for key, prefix in URI.items():
        val = need_str(t, key)
        if not val.startswith(prefix):
            fail(f"transport.{key} must use the {prefix!r} URI shape (got {val!r})")
    if not re.match(r"^sha256:", str(t.get("envelope_hash", ""))):
        fail("transport.envelope_hash must be a sha256: digest")
    if not isinstance(t.get("chain_position"), int) or t["chain_position"] < 0:
        fail("transport.chain_position must be a non-negative integer")
    # (a) owner-sealed
    if t.get("sealed") is not True:
        fail("transport.sealed must be true (owner-sealed) for a SOC hop")
    if "failure_class" in t and t["failure_class"] not in FAILURE_CLASSES:
        fail(f"transport.failure_class must be one of {sorted(FAILURE_CLASSES)}")


def validate_schema(schema: Any) -> None:
    """Schema and validator must not drift (dependency-light, repo convention)."""
    if not isinstance(schema, dict) or schema.get("additionalProperties") is not False:
        fail("schema root must be strict")
    props = schema.get("properties", {})
    tx = props.get("transport", {})
    if tx.get("additionalProperties") is not False:
        fail("schema transport must be strict")
    txp = tx.get("properties", {})
    if txp.get("protocol", {}).get("const") != "tritrpc":
        fail("schema must pin transport.protocol const 'tritrpc'")
    if txp.get("sealed", {}).get("const") is not True:
        fail("schema must pin transport.sealed const true (owner-sealed)")
    for key, prefix in URI.items():
        if txp.get(key, {}).get("pattern") != f"^{prefix}":
            fail(f"schema must pin transport.{key} pattern ^{prefix}")
    if set(tx.get("required", [])) < {"protocol", "route_id", "peer_id", "chain_id", "sealed", "sealed_to"}:
        fail("schema transport.required drifted from the owner-sealed/URI invariant")


def main() -> int:
    try:
        validate_schema(load(SCHEMA))
        verify_contract(load(VALID))
        for path in INVALID:
            try:
                verify_contract(load(path))
            except ContractError:
                continue
            fail(f"expected {path.name} to be rejected, but it passed")
    except ContractError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 2
    print("OK: SOC relay-contract binding validated (1 example, 2 invalid rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
