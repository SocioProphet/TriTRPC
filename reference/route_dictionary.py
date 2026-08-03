"""Route-handle dictionary negotiation (vNext hot-path gap #3) — fail-closed.

Hot frames carry a 1-byte Handle243 (direct 0..242) instead of a full route string. That byte only
has meaning against an AGREED dictionary. This reference builds a dictionary, computes its agreement
token (SHA-256 of the canonical entries), negotiates agreement between two peers, and resolves a
handle to its route — refusing, fail-closed, an unknown handle, a duplicate handle, or a dictionary
mismatch.

FIPS: the agreement token is SHA-256 (FIPS 180-4). Additive — explains the existing route_handle byte;
does not change the frame wire (TritPack243/S243/Handle243 unchanged).
"""
from __future__ import annotations

import hashlib
import json


class RouteDictError(Exception):
    pass


def _canonical(entries: list) -> bytes:
    # sort by handle; compact JSON; deterministic across platforms.
    norm = sorted(({"handle": e["handle"], "route": e["route"]} for e in entries), key=lambda e: e["handle"])
    return json.dumps(norm, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_dictionary(mappings: dict) -> dict:
    """mappings: {handle:int -> route:str}. Returns a RouteDictionary with its SHA-256 agreement token."""
    entries = []
    seen = set()
    for handle, route in mappings.items():
        h = int(handle)
        if not 0 <= h <= 242:
            raise RouteDictError(f"handle {h} out of Handle243 direct range 0..242")
        if h in seen:
            raise RouteDictError(f"duplicate handle {h}")
        if not str(route):
            raise RouteDictError(f"empty route for handle {h}")
        seen.add(h)
        entries.append({"handle": h, "route": str(route)})
    token = "sha256:" + hashlib.sha256(_canonical(entries)).hexdigest()
    return {"dictionaryId": token, "entries": entries}


def dictionary_id(d: dict) -> str:
    return "sha256:" + hashlib.sha256(_canonical(d["entries"])).hexdigest()


def resolve(d: dict, handle: int) -> str:
    """Resolve a handle to its route, fail-closed if the dictionary is inconsistent or the handle unknown."""
    if dictionary_id(d) != d.get("dictionaryId"):
        raise RouteDictError("dictionary agreement token does not match its entries (tampered/stale)")
    for e in d["entries"]:
        if e["handle"] == handle:
            return e["route"]
    raise RouteDictError(f"route_handle {handle} is not in the agreed dictionary (unresolvable — refused)")


def negotiate(local: dict, remote: dict) -> dict:
    """Two peers agree iff their dictionary tokens match; otherwise refuse (no ambiguous resolution)."""
    if dictionary_id(local) != local.get("dictionaryId") or dictionary_id(remote) != remote.get("dictionaryId"):
        raise RouteDictError("a peer's dictionary token does not match its entries")
    if local["dictionaryId"] != remote["dictionaryId"]:
        raise RouteDictError("dictionary mismatch — peers advertise different handle->route maps (refused)")
    return local
