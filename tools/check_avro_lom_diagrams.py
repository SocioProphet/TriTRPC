#!/usr/bin/env python3
"""Check checked-in Avro LOM DOT diagrams for schema coverage drift.

The diagrams are non-normative views over `.avsc` sources. This checker enforces
that every rendered Avro field name and expected type label remains represented
in the checked-in DOT artifact. It is intentionally stable for hand-tuned DOT
layouts while still failing when a schema evolves and the diagram is not updated.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
PRIMITIVES = {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}
DIAGRAMS: Tuple[Tuple[str, str], ...] = (
    (
        "fixtures/descriptors/heller/v1/heller_event_envelope.avsc",
        "docs/diagrams/heller_event_envelope_lom.dot",
    ),
)


def normalize(avro_type: Any) -> Tuple[str, Any]:
    if isinstance(avro_type, str):
        return ("primitive", avro_type) if avro_type in PRIMITIVES else ("named", avro_type)
    if isinstance(avro_type, list):
        return "union", avro_type
    if isinstance(avro_type, dict):
        if "logicalType" in avro_type and isinstance(avro_type.get("type"), str):
            return "logical", avro_type
        type_value = avro_type.get("type")
        if type_value in {"record", "enum", "fixed", "array", "map"}:
            return type_value, avro_type
        if isinstance(type_value, list):
            return "union", type_value
        if isinstance(type_value, str):
            return normalize(type_value)
    return "unknown", avro_type


def qualified_name(schema: dict[str, Any]) -> str:
    name = schema.get("name", "Root")
    namespace = schema.get("namespace")
    return f"{namespace}.{name}" if namespace else name


def type_label(avro_type: Any) -> str:
    kind, obj = normalize(avro_type)
    if kind in {"primitive", "named"}:
        return str(obj)
    if kind == "logical":
        return f"{obj.get('type')}({obj.get('logicalType')})"
    if kind == "record":
        return f"record {qualified_name(obj)}"
    if kind == "enum":
        return f"enum {obj.get('name')}"
    if kind == "fixed":
        return f"fixed {qualified_name(obj)}[{obj.get('size')}]"
    if kind == "array":
        return "items[]"
    if kind == "map":
        return "values{}"
    if kind == "union":
        return " | ".join(type_label(option) for option in obj)
    return json.dumps(obj, sort_keys=True)


def collect_expected_labels(schema: dict[str, Any]) -> Set[str]:
    labels: Set[str] = {qualified_name(schema), schema.get("name", "Root")}
    registry: dict[str, Any] = {}

    def register(avro_type: Any) -> None:
        kind, obj = normalize(avro_type)
        if kind in {"record", "enum", "fixed"} and isinstance(obj, dict) and "name" in obj:
            registry[obj["name"]] = obj
            registry[qualified_name(obj)] = obj
        if kind == "record":
            for field_obj in obj.get("fields", []):
                register(field_obj.get("type"))
        elif kind == "array":
            register(obj.get("items"))
        elif kind == "map":
            register(obj.get("values"))
        elif kind == "union":
            for option in obj:
                register(option)

    def resolve(avro_type: Any) -> Tuple[str, Any]:
        kind, obj = normalize(avro_type)
        if kind == "named" and obj in registry:
            return normalize(registry[obj])
        return kind, obj

    def visit_type(avro_type: Any) -> None:
        kind, obj = resolve(avro_type)
        labels.add(type_label(avro_type))
        if kind == "record":
            labels.add(obj.get("name", "record"))
            for field_obj in obj.get("fields", []):
                labels.add(field_obj["name"])
                visit_type(field_obj["type"])
        elif kind == "array":
            labels.add("items[]")
            visit_type(obj.get("items"))
        elif kind == "map":
            labels.add("values{}")
            visit_type(obj.get("values"))
        elif kind == "union":
            labels.add("union")
            for option in obj:
                visit_type(option)
        elif kind == "enum":
            labels.add(f"enum {obj.get('name')}")

    register(schema)
    visit_type(schema)
    return {label for label in labels if label and label != "record"}


def check_pair(schema_rel: str, diagram_rel: str) -> bool:
    schema_path = ROOT / schema_rel
    diagram_path = ROOT / diagram_rel
    if not schema_path.exists():
        print(f"[FAIL] missing schema source: {schema_rel}", file=sys.stderr)
        return False
    if not diagram_path.exists():
        print(f"[FAIL] missing diagram artifact: {diagram_rel}", file=sys.stderr)
        return False

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    diagram = diagram_path.read_text(encoding="utf-8")
    missing = sorted(label for label in collect_expected_labels(schema) if label not in diagram)
    if not missing:
        print(f"[OK] {diagram_rel} covers {schema_rel}")
        return True

    print(f"[FAIL] {diagram_rel} is missing labels from {schema_rel}:", file=sys.stderr)
    for label in missing:
        print(f"  - {label}", file=sys.stderr)
    return False


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)

    ok = True
    for schema_rel, diagram_rel in DIAGRAMS:
        ok = check_pair(schema_rel, diagram_rel) and ok
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
