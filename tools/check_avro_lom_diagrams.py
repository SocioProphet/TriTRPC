#!/usr/bin/env python3
"""Regenerate checked-in Avro LOM DOT diagrams and fail on exact drift.

The diagrams are non-normative views over `.avsc` sources, but once committed
they must be reproducible from `tools/render_avro_schema_lom.py`. This checker
runs the renderer for each registered schema/diagram pair and compares the
result byte-for-byte against the checked-in DOT file.
"""
from __future__ import annotations

import argparse
import difflib
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Tuple

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "tools" / "render_avro_schema_lom.py"


@dataclass(frozen=True)
class DiagramSpec:
    schema: str
    diagram: str
    max_depth: int = 1


DIAGRAMS: Tuple[DiagramSpec, ...] = (
    DiagramSpec(
        schema="fixtures/descriptors/heller/v1/heller_event_envelope.avsc",
        diagram="docs/diagrams/heller_event_envelope_lom.dot",
        max_depth=1,
    ),
)


def render_to_temp(spec: DiagramSpec, output_path: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(RENDERER),
            "--schema",
            str(ROOT / spec.schema),
            "--out",
            str(output_path),
            "--max-depth",
            str(spec.max_depth),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def check_spec(spec: DiagramSpec) -> bool:
    schema_path = ROOT / spec.schema
    diagram_path = ROOT / spec.diagram
    if not schema_path.exists():
        print(f"[FAIL] missing schema source: {spec.schema}", file=sys.stderr)
        return False
    if not diagram_path.exists():
        print(f"[FAIL] missing diagram artifact: {spec.diagram}", file=sys.stderr)
        return False

    with tempfile.TemporaryDirectory(prefix="avro-lom-diagram-") as tmpdir:
        generated_path = Path(tmpdir) / Path(spec.diagram).name
        render_to_temp(spec, generated_path)
        expected = diagram_path.read_text(encoding="utf-8")
        actual = generated_path.read_text(encoding="utf-8")

    if expected == actual:
        print(f"[OK] {spec.diagram} exactly matches renderer output for {spec.schema}")
        return True

    print(f"[FAIL] {spec.diagram} drifted from renderer output for {spec.schema}", file=sys.stderr)
    diff = difflib.unified_diff(
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile=spec.diagram,
        tofile=f"generated:{spec.diagram}",
    )
    sys.stderr.writelines(diff)
    return False


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)

    ok = True
    for spec in DIAGRAMS:
        ok = check_spec(spec) and ok
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
