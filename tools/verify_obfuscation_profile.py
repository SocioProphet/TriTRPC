#!/usr/bin/env python3
"""Verify TriTRPC obfuscation profiles (traffic-analysis resistance) — fail-closed parameters.

The v1 AEAD lane hides payloads, not traffic patterns. This gate checks that a declared obfuscation
profile actually provides anonymity: K-fold ≥ 2 (K=1 is no anonymity), a bounded positive jitter
window, and a braid of ≥ 2 participants when braiding is on. A profile that provides no cover is
refused. Self-testing (stdlib, repo convention): the example passes; the no-anonymity and bad-jitter
negatives are rejected.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "examples" / "transport"
VALID = EX / "obfuscation_profile.example.json"
INVALID = [EX / "obfuscation_profile.no-anonymity.invalid.json",
           EX / "obfuscation_profile.bad-jitter.invalid.json"]
KEYS = {"profileId", "kFold", "decoyEntropyRatio", "braiding", "jitterMs", "paddingBytes"}


class ProfileError(Exception):
    pass


def fail(m: str) -> None:
    raise ProfileError(m)


def load(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def verify_profile(rec: Any) -> None:
    if not isinstance(rec, dict):
        fail("profile must be an object")
    extra = sorted(set(rec) - KEYS)
    if extra:
        fail(f"unexpected fields: {extra}")
    if not isinstance(rec.get("profileId"), str) or not rec["profileId"]:
        fail("profileId: expected non-empty string")

    k = rec.get("kFold")
    if not isinstance(k, int) or isinstance(k, bool) or k < 2:
        fail("kFold must be an integer >= 2 (K=1 provides zero anonymity)")

    r = rec.get("decoyEntropyRatio")
    if r is not None and (not isinstance(r, (int, float)) or isinstance(r, bool) or not (0 < r <= 1)):
        fail("decoyEntropyRatio must be in (0, 1]")

    braid = rec.get("braiding")
    if braid is not None:
        if not isinstance(braid, dict) or not isinstance(braid.get("enabled"), bool):
            fail("braiding must be an object with a boolean 'enabled'")
        if braid.get("enabled"):
            mp = braid.get("minParticipants")
            if not isinstance(mp, int) or isinstance(mp, bool) or mp < 2:
                fail("braiding.minParticipants must be >= 2 when braiding is enabled (a braid of one is not a braid)")

    j = rec.get("jitterMs")
    if not isinstance(j, dict):
        fail("jitterMs must be an object")
    lo, hi = j.get("min"), j.get("max")
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (lo, hi)):
        fail("jitterMs.min and .max must be integers")
    if not (1 <= lo <= hi):
        fail(f"jitterMs must satisfy 1 <= min <= max (got min={lo}, max={hi})")

    pad = rec.get("paddingBytes")
    if pad is not None and (not isinstance(pad, int) or isinstance(pad, bool) or pad < 0):
        fail("paddingBytes must be a non-negative integer")


def main() -> int:
    try:
        verify_profile(load(VALID))
        for path in INVALID:
            try:
                verify_profile(load(path))
            except ProfileError:
                continue
            fail(f"expected {path.name} to be rejected, but it passed")
    except ProfileError as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return 2
    print("OK: obfuscation profile validated (1 example, 2 invalid rejected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
