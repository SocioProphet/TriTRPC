#!/usr/bin/env python3
"""Regenerate checked-in Avro LOM DOT diagrams and fail on drift.

This keeps non-normative schema diagrams mechanically tied to their normative
`.avsc` sources. Add new schema/diagram pairs to DIAGRAMS when a generated DOT
artifact is committed.
"""
from __future__ import annotations

import argparse
import difflib
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "tools" / "render_avro_schema_lom.py"

DIAGRAMS: Tuple[Tuple[str, str], ...] = (
    (
        "fixtures/descriptors/heller/v1/heller_event_envelope.avsc",
        "docs/diagrams/heller_event_envelope_lom.dot",
    ),
)


def render_to_temp(schema_path: Path, output_path: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(RENDERER),
            "--schema",
            str(schema_path),
            "--out",
            str(output_path),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def check_pair(schema_rel: str, diagram_rel: str) -> bool:
    schema_path = ROOT / schema_rel
    diagram_path = ROOT / diagram_rel
    if not schema_path.exists():
        print(f"[FAIL] missing schema source: {schema_rel}", file=sys.stderr)
        return False
    if not diagram_path.exists():
        print(f"[FAIL] missing diagram artifact: {diagram_rel}", file=sys.stderr)
        return False

    with tempfile.TemporaryDirectory(prefix="avro-lom-diagram-") as tmpdir:
        generated_path = Path(tmpdir) / Path(diagram_rel).name
        render_to_temp(schema_path, generated_path)
        expected = diagram_path.read_text(encoding="utf-8")
        actual = generated_path.read_text(encoding="utf-8")

    if expected == actual:
        print(f"[OK] {diagram_rel} matches {schema_rel}")
        return True

    print(f"[FAIL] {diagram_rel} drifted from {schema_rel}", file=sys.stderr)
    diff = difflib.unified_diff(
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile=diagram_rel,
        tofile=f"generated:{diagram_rel}",
    )
    sys.stderr.writelines(diff)
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
