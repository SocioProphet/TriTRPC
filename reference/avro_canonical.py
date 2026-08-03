#!/usr/bin/env python3
"""Avro Parsing Canonical Form (PCF) + the mesh SCHEMA-ID / body-CID — recompute, don't trust.

A WorkUnitPack's `schema_id` is defined as SHA3-256 of the Avro *Parsing Canonical Form* of its body
schema (the SCHEMA-ID), and its `body_cid` as SHA-256 of the body's canonical serialization. Both must
be REPRODUCIBLE by any node from the artifacts alone — otherwise two honest nodes could disagree on
what they computed. This module implements PCF (the subset the mesh uses: records, enums, arrays,
maps, unions, primitives) per the Avro spec transformations PRIMITIVES/FULLNAMES/STRIP/ORDER/STRINGS,
then the two content hashes.

FIPS: SCHEMA-ID over SHA3-256 (FIPS 202), body CID over SHA-256 (FIPS 180-4) — both approved. The
body CID here is over the body's canonical JSON (JCS-style: sorted keys, no whitespace) as a
dependency-free stand-in for Avro binary; the invariant that matters is that all honest nodes derive
the SAME cid from the SAME body, which canonical JSON guarantees. Does not touch the v4/vNext wire.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

PRIMITIVES = {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}
# Per PCF [ORDER]: name, type, fields, symbols, items, values, size.
_ORDER = ["name", "type", "fields", "symbols", "items", "values", "size"]


def _fullname(node: dict, enclosing_ns: str | None) -> str:
    name = node["name"]
    if "." in name:
        return name
    ns = node.get("namespace", enclosing_ns)
    return f"{ns}.{name}" if ns else name


def canonical_form(schema: Any, enclosing_ns: str | None = None) -> str:
    """Return the Avro Parsing Canonical Form string of a schema."""
    if isinstance(schema, str):
        return json.dumps(schema)  # a primitive or a named-type reference (already a fullname)
    if isinstance(schema, list):  # union
        return "[" + ",".join(canonical_form(s, enclosing_ns) for s in schema) + "]"
    if not isinstance(schema, dict):
        raise ValueError(f"not an Avro schema: {schema!r}")

    t = schema.get("type")
    if t in PRIMITIVES and set(schema) <= {"type"} | set(_ORDER) and "name" not in schema:
        return json.dumps(t)

    if t in ("record", "error", "enum", "fixed"):
        ns = schema.get("namespace", enclosing_ns)
        parts = [f'"name":{json.dumps(_fullname(schema, enclosing_ns))}', f'"type":{json.dumps(t)}']
        if t in ("record", "error"):
            fields = []
            for f in schema["fields"]:
                fields.append('{"name":' + json.dumps(f["name"]) + ',"type":' + canonical_form(f["type"], ns) + "}")
            parts.append('"fields":[' + ",".join(fields) + "]")
        elif t == "enum":
            parts.append('"symbols":[' + ",".join(json.dumps(s) for s in schema["symbols"]) + "]")
        elif t == "fixed":
            parts.append(f'"size":{int(schema["size"])}')
        return "{" + ",".join(parts) + "}"

    if t == "array":
        return '{"type":"array","items":' + canonical_form(schema["items"], enclosing_ns) + "}"
    if t == "map":
        return '{"type":"map","values":' + canonical_form(schema["values"], enclosing_ns) + "}"
    # a wrapped primitive with extra attrs: {"type":"string", ...} -> "string"
    if t in PRIMITIVES:
        return json.dumps(t)
    raise ValueError(f"unsupported Avro type: {t!r}")


def schema_id(schema: Any) -> str:
    """SCHEMA-ID = sha3-256: of the Parsing Canonical Form bytes."""
    pcf = canonical_form(schema).encode("utf-8")
    return "sha3-256:" + hashlib.sha3_256(pcf).hexdigest()


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def body_cid(body: Any) -> str:
    """body_cid = sha256: of the body's canonical JSON serialization."""
    return "sha256:" + hashlib.sha256(_canonical_json(body)).hexdigest()


if __name__ == "__main__":
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/avro/work_unit_body.v0.avsc").read_text())
    print("PCF:", canonical_form(schema))
    print("schema_id:", schema_id(schema))
