from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .codec import TritPack243Error
from .naming import BraidedId


@dataclass(frozen=True)
class RouteDescriptor:
    service: str
    method: str
    schema: str
    context_policy: str
    default_profile: str
    reply_semantics: str


@dataclass
class RouteRegistry:
    routes: dict[int, RouteDescriptor] = field(default_factory=dict)
    identities: dict[int, BraidedId] = field(default_factory=dict)

    @classmethod
    def load_yaml(cls, path: str | Path) -> "RouteRegistry":
        with open(path, "r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        routes: dict[int, RouteDescriptor] = {}
        for key, value in (raw.get("routes") or {}).items():
            routes[int(key)] = RouteDescriptor(**value)
        identities: dict[int, BraidedId] = {}
        for key, value in (raw.get("identities") or {}).items():
            identities[int(key)] = BraidedId.parse(value["canonical_id"])
        return cls(routes=routes, identities=identities)

    def route(self, handle: int) -> RouteDescriptor:
        try:
            return self.routes[handle]
        except KeyError as exc:
            raise TritPack243Error(f"unknown route handle {handle}") from exc

    def identity(self, handle: int) -> BraidedId:
        try:
            return self.identities[handle]
        except KeyError as exc:
            raise TritPack243Error(f"unknown identity handle {handle}") from exc

    def to_mapping(self) -> dict[str, Any]:
        return {
            "routes": {str(key): value.__dict__ for key, value in self.routes.items()},
            "identities": {str(key): {"canonical_id": value.to_canonical()} for key, value in self.identities.items()},
        }
