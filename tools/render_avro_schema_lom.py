#!/usr/bin/env python3
"""Render an Avro record schema as a deterministic LOM-style Graphviz DOT diagram.

The output is a non-normative view over the normative `.avsc` source. DOT is used
so diagrams remain reviewable and reproducible in protocol documentation.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PRIMITIVES = {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}
LANES = ("Schema", "Category", "Aggregate Element", "Simple Data Element", "Datatype", "Value")


@dataclass
class Node:
    key: str
    label: str
    lane: int
    shape: str = "rounded"
    children: List["Node"] = field(default_factory=list)


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


def qualified_name(schema: Dict[str, Any]) -> str:
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
        return f"enum {qualified_name(obj)}"
    if kind == "fixed":
        return f"fixed {qualified_name(obj)}[{obj.get('size')}]"
    if kind == "array":
        return f"array<{type_label(obj.get('items'))}>"
    if kind == "map":
        return f"map<string,{type_label(obj.get('values'))}>"
    if kind == "union":
        return " | ".join(type_label(option) for option in obj)
    return json.dumps(obj, sort_keys=True)


def union_branch_label(avro_type: Any) -> str:
    kind, obj = normalize(avro_type)
    if kind in {"record", "enum", "fixed"}:
        return qualified_name(obj)
    return type_label(avro_type)


class Builder:
    def __init__(self, schema: Dict[str, Any], max_depth: int) -> None:
        if schema.get("type") != "record":
            raise ValueError("root schema must be an Avro record")
        self.schema = schema
        self.max_depth = max_depth
        self.registry: Dict[str, Dict[str, Any]] = {}
        self._register(schema)

    def _register(self, avro_type: Any) -> None:
        kind, obj = normalize(avro_type)
        if kind in {"record", "enum", "fixed"} and isinstance(obj, dict) and "name" in obj:
            self.registry[obj["name"]] = obj
            self.registry[qualified_name(obj)] = obj
        if kind == "record":
            for field_obj in obj.get("fields", []):
                self._register(field_obj.get("type"))
        elif kind == "array":
            self._register(obj.get("items"))
        elif kind == "map":
            self._register(obj.get("values"))
        elif kind == "union":
            for option in obj:
                self._register(option)

    def build(self) -> Node:
        root = Node(qualified_name(self.schema), qualified_name(self.schema), 0)
        for field_obj in self.schema.get("fields", []):
            self.add_field(root, field_obj["name"], field_obj["type"], 1, f"{root.key}.{field_obj['name']}")
        return root

    def resolve(self, avro_type: Any) -> Tuple[str, Any]:
        kind, obj = normalize(avro_type)
        if kind == "named" and obj in self.registry:
            return normalize(self.registry[obj])
        return kind, obj

    def add_field(self, parent: Node, name: str, avro_type: Any, depth: int, path: str) -> None:
        node = Node(path, name, min(depth, self.max_depth))
        parent.children.append(node)
        self.expand(node, avro_type, depth, path)

    def expand(self, node: Node, avro_type: Any, depth: int, path: str) -> None:
        kind, obj = self.resolve(avro_type)
        if kind == "record" and depth < self.max_depth:
            for field_obj in obj.get("fields", []):
                self.add_field(node, field_obj["name"], field_obj["type"], depth + 1, f"{path}.{field_obj['name']}")
        elif kind == "array" and depth < self.max_depth:
            child = Node(f"{path}.items", "items[]", min(depth + 1, self.max_depth))
            node.children.append(child)
            self.expand(child, obj.get("items"), depth + 1, f"{path}.items")
        elif kind == "map" and depth < self.max_depth:
            child = Node(f"{path}.values", "values{}", min(depth + 1, self.max_depth))
            node.children.append(child)
            self.expand(child, obj.get("values"), depth + 1, f"{path}.values")
        elif kind == "union" and depth < self.max_depth:
            union_node = Node(f"{path}.union", "union", min(depth + 1, self.max_depth))
            node.children.append(union_node)
            for index, option in enumerate(obj):
                branch = Node(f"{path}.union.{index}", union_branch_label(option), min(depth + 2, self.max_depth))
                union_node.children.append(branch)
                self.expand(branch, option, depth + 2, f"{path}.union.{index}")
        else:
            node.children.append(Node(f"{path}.datatype", type_label(avro_type), 4, "box"))
            node.children.append(Node(f"{path}.value", "...", 5, "plain"))


def walk(root: Node) -> Tuple[List[Node], List[Tuple[Node, Node]]]:
    nodes: List[Node] = []
    edges: List[Tuple[Node, Node]] = []

    def rec(node: Node) -> None:
        nodes.append(node)
        for child in node.children:
            edges.append((node, child))
            rec(child)

    rec(root)
    return nodes, edges


def esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def node_id(key: str, index: int) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]", "_", key)
    if not safe or safe[0].isdigit():
        safe = "n_" + safe
    return f"{safe}_{index}"


def wrap(value: str, width: int = 28) -> str:
    if len(value) <= width:
        return value
    chunks: List[str] = []
    while len(value) > width:
        cut = max(value.rfind(".", 0, width), value.rfind("_", 0, width), value.rfind("|", 0, width))
        if cut < 8:
            cut = width
        chunks.append(value[:cut].strip())
        value = value[cut:].strip(" ._|,/")
    if value:
        chunks.append(value)
    return "\\n".join(chunks)


def render(root: Node, title: str) -> str:
    nodes, edges = walk(root)
    ids = {id(node): node_id(node.key, index) for index, node in enumerate(nodes)}
    out = [
        "digraph avro_lom_schema {",
        f'  graph [rankdir=LR, splines=ortho, nodesep="0.35", ranksep="0.70", labelloc="b", label="{esc(title)}"];',
        '  node [fontname="Helvetica", fontsize="10"];',
        '  edge [color="black", arrowsize="0.6"];',
    ]
    headers = []
    for index, lane in enumerate(LANES):
        header = f"lane_{index}"
        headers.append(header)
        out.append(f'  {header} [shape=plaintext, label="{esc(lane)}"];')
    for node in nodes:
        shape = "plaintext" if node.shape == "plain" else "box"
        style = "rounded" if node.shape == "rounded" else "solid"
        out.append(f'  {ids[id(node)]} [shape={shape}, style="{style}", label="{esc(wrap(node.label))}"];')
    for lane_index in range(len(LANES)):
        lane_nodes = [ids[id(node)] for node in nodes if node.lane == lane_index]
        if lane_nodes:
            out.append("  { rank=same; " + headers[lane_index] + "; " + "; ".join(lane_nodes) + "; }")
    for left, right in zip(headers, headers[1:]):
        out.append(f"  {left} -> {right} [style=invis, weight=20];")
    for parent, child in edges:
        out.append(f"  {ids[id(parent)]} -> {ids[id(child)]};")
    out.append("}")
    return "\n".join(out) + "\n"


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Render Avro .avsc as a LOM-style Graphviz DOT diagram")
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--title")
    parser.add_argument("--max-depth", type=int, default=3)
    args = parser.parse_args(argv)

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    root = Builder(schema, args.max_depth).build()
    title = args.title or f"LOM-style Avro schema view: {qualified_name(schema)}"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(root, title), encoding="utf-8")
    print(f"[OK] wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
