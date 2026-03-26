from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .codec import TritPack243Error

BASE_ID_RE = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){2,}$")
CANONICAL_ID_RE = re.compile(
    r"^(?P<base>[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){2,})"
    r"(?:\[(?P<surface>[a-z0-9+:-]+)\])?"
    r"@e(?P<epoch>[1-9][0-9]*)"
    r"\.p(?P<phase>[1-7])"
    r"\.f(?P<focus>(?:[1-9]|1[0-9]|2[0-3]))"
    r"\.(?P<state>[a-z][a-z0-9-]*)"
    r"\+l(?P<lineage>[1-9][0-9]*)"
    r"(?:#(?P<env>[A-Za-z0-9._:-]+))?$"
)

DEFAULT_ALLOWED_STATES = {
    "draft",
    "active",
    "review",
    "verified",
    "frozen",
    "deprecated",
    "canonical",
    "attested",
    "simulated",
}


@dataclass(frozen=True)
class TopicCode:
    index: int
    code: str
    label: str
    family: str = "general"
    aliases: tuple[str, ...] = ()
    description: str = ""


PROPOSED_TOPIC23: tuple[TopicCode, ...] = (
    TopicCode(1, "idn", "identity", "core", ("identity", "principal", "subject"), "stable actors and workload identity"),
    TopicCode(2, "rte", "routing", "transport", ("route", "path", "dispatch"), "route families, handles, and delivery cohorts"),
    TopicCode(3, "pol", "policy", "governance", ("policy", "rule", "constraint"), "authorization and governance policy state"),
    TopicCode(4, "trt", "trust", "governance", ("trust", "assurance"), "trust zone and trust relationship state"),
    TopicCode(5, "rsk", "risk", "governance", ("risk", "hazard"), "risk posture and harm bands"),
    TopicCode(6, "asr", "assurance", "governance", ("assurance", "validation"), "evidence and assurance posture"),
    TopicCode(7, "nov", "novelty", "adaptation", ("novelty", "surprise"), "novelty detection and adaptation mode"),
    TopicCode(8, "cmp", "competence", "adaptation", ("competence", "capability-bound"), "self-knowledge of competence envelope"),
    TopicCode(9, "cap", "capability", "adaptation", ("capability", "affordance"), "advertised abilities and supported tasks"),
    TopicCode(10, "prv", "provenance", "knowledge", ("provenance", "lineage"), "origin, lineage, and replay anchors"),
    TopicCode(11, "cau", "causality", "knowledge", ("causal", "cause"), "causal links and explanatory structure"),
    TopicCode(12, "sch", "schema", "knowledge", ("schema", "event-schema"), "schemas, frames, and structured event knowledge"),
    TopicCode(13, "wrd", "world-model", "knowledge", ("world", "model"), "world-model state and external environment assumptions"),
    TopicCode(14, "dlg", "dialogue", "interaction", ("dialogue", "conversation"), "dialogue acts and conversational posture"),
    TopicCode(15, "tem", "team", "interaction", ("team", "coordination"), "teaming and shared mental models"),
    TopicCode(16, "cul", "culture", "interaction", ("culture", "social"), "cultural and local knowledge overlays"),
    TopicCode(17, "wfl", "workflow", "control", ("workflow", "process"), "workflow and process-stage coordination"),
    TopicCode(18, "lrn", "learning", "control", ("learning", "training"), "learning-loop and adaptation state"),
    TopicCode(19, "mem", "memory", "knowledge", ("memory", "cache"), "working memory and retained context"),
    TopicCode(20, "ret", "retrieval", "knowledge", ("retrieval", "search"), "retrieval and in-flow knowledge selection"),
    TopicCode(21, "pln", "planning", "control", ("planning", "decision"), "planning and decision horizon"),
    TopicCode(22, "act", "actuation", "control", ("action", "execution"), "execution, tool use, and actuation"),
    TopicCode(23, "inc", "incident", "governance", ("incident", "response"), "incident mode, containment, and recovery"),
)


@dataclass(frozen=True)
class TopicRegistry:
    version: str = "topic23.proposed.v1"
    topics: tuple[TopicCode, ...] = field(default_factory=lambda: PROPOSED_TOPIC23)

    @classmethod
    def load_yaml(cls, path: str | Path) -> "TopicRegistry":
        with open(path, "r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        topics = tuple(
            TopicCode(
                index=int(item["index"]),
                code=item["code"],
                label=item["label"],
                family=item.get("family", "general"),
                aliases=tuple(item.get("aliases") or ()),
                description=item.get("description", ""),
            )
            for item in raw.get("topics") or ()
        )
        if len(topics) != 23:
            raise TritPack243Error("TopicRegistry must define exactly 23 topics for topic23.v1")
        return cls(version=raw.get("version", "topic23.proposed.v1"), topics=topics)

    def get(self, index: int) -> TopicCode:
        for topic in self.topics:
            if topic.index == index:
                return topic
        raise TritPack243Error(f"topic index {index} is not registered")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "topics": [
                {
                    "index": topic.index,
                    "code": topic.code,
                    "label": topic.label,
                    "family": topic.family,
                    "aliases": list(topic.aliases),
                    "description": topic.description,
                }
                for topic in self.topics
            ],
        }


@dataclass(frozen=True)
class CyclePhase:
    index: int
    code: str
    label: str
    machine_gray: str
    description: str = ""


PROPOSED_CYCLE7: tuple[CyclePhase, ...] = (
    CyclePhase(1, "obs", "observe", "000", "sense or receive incoming evidence"),
    CyclePhase(2, "prs", "parse", "001", "parse and normalize raw inputs"),
    CyclePhase(3, "str", "structure", "011", "structure evidence into canonical cells"),
    CyclePhase(4, "dec", "decide", "010", "decide policy and routing posture"),
    CyclePhase(5, "act", "act", "110", "execute, dispatch, or emit control"),
    CyclePhase(6, "rev", "review", "111", "review results and apply friction if needed"),
    CyclePhase(7, "frz", "freeze", "101", "freeze, checkpoint, or promote durable state"),
)


@dataclass(frozen=True)
class CycleRegistry:
    version: str = "cycle7.proposed.v1"
    phases: tuple[CyclePhase, ...] = field(default_factory=lambda: PROPOSED_CYCLE7)
    reserved_gray: str = "100"

    @classmethod
    def load_yaml(cls, path: str | Path) -> "CycleRegistry":
        with open(path, "r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        phases = tuple(
            CyclePhase(
                index=int(item["index"]),
                code=item["code"],
                label=item["label"],
                machine_gray=item["machine_gray"],
                description=item.get("description", ""),
            )
            for item in raw.get("phases") or ()
        )
        if len(phases) != 7:
            raise TritPack243Error("CycleRegistry must define exactly 7 phases for cycle7.v1")
        return cls(
            version=raw.get("version", "cycle7.proposed.v1"),
            phases=phases,
            reserved_gray=raw.get("reserved_gray", "100"),
        )

    def get(self, index: int) -> CyclePhase:
        for phase in self.phases:
            if phase.index == index:
                return phase
        raise TritPack243Error(f"cycle phase {index} is not registered")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "reserved_gray": self.reserved_gray,
            "phases": [
                {
                    "index": phase.index,
                    "code": phase.code,
                    "label": phase.label,
                    "machine_gray": phase.machine_gray,
                    "description": phase.description,
                }
                for phase in self.phases
            ],
        }


@dataclass(frozen=True)
class BraidedId:
    base_id: str
    epoch: int
    phase: int
    focus_topic: int
    state: str
    lineage: int
    runtime_env: str | None = None
    topic_surface: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not BASE_ID_RE.fullmatch(self.base_id):
            raise TritPack243Error(f"invalid base_id syntax: {self.base_id}")
        if self.epoch < 1:
            raise TritPack243Error("epoch must be >= 1")
        if not 1 <= self.phase <= 7:
            raise TritPack243Error("phase must be in 1..7")
        if not 1 <= self.focus_topic <= 23:
            raise TritPack243Error("focus topic must be in 1..23")
        if self.state not in DEFAULT_ALLOWED_STATES:
            raise TritPack243Error(f"unregistered lifecycle state: {self.state}")
        if self.lineage < 1:
            raise TritPack243Error("lineage must be >= 1")
        for surface in self.topic_surface:
            if not re.fullmatch(r"[a-z0-9:+-]+", surface):
                raise TritPack243Error(f"invalid topic surface fragment: {surface}")

    def to_canonical(self) -> str:
        surface = f"[{'+'.join(self.topic_surface)}]" if self.topic_surface else ""
        env = f"#{self.runtime_env}" if self.runtime_env else ""
        return (
            f"{self.base_id}{surface}@e{self.epoch}.p{self.phase}.f{self.focus_topic}."
            f"{self.state}+l{self.lineage}{env}"
        )

    def to_braid243(self) -> int:
        return encode_braid243(self.phase, self.focus_topic)

    @classmethod
    def parse(cls, text: str) -> "BraidedId":
        match = CANONICAL_ID_RE.fullmatch(text)
        if not match:
            raise TritPack243Error(f"invalid braided identifier: {text}")
        surface = tuple(match.group("surface").split("+")) if match.group("surface") else ()
        return cls(
            base_id=match.group("base"),
            epoch=int(match.group("epoch")),
            phase=int(match.group("phase")),
            focus_topic=int(match.group("focus")),
            state=match.group("state"),
            lineage=int(match.group("lineage")),
            runtime_env=match.group("env"),
            topic_surface=surface,
        )



def encode_braid243(phase: int, topic: int) -> int:
    if not 1 <= phase <= 7:
        raise TritPack243Error("phase must be in 1..7 for Braid243")
    if not 1 <= topic <= 23:
        raise TritPack243Error("topic must be in 1..23 for Braid243")
    phase_code = phase - 1
    topic_code = topic - 1
    return phase_code * 27 + topic_code



def decode_braid243(value: int) -> tuple[int, int]:
    if not 0 <= value <= 242:
        raise TritPack243Error("Braid243 byte must be in 0..242")
    phase_code, topic_code = divmod(value, 27)
    if phase_code > 6 or topic_code > 22:
        raise TritPack243Error("reserved Braid243 coordinate")
    return phase_code + 1, topic_code + 1



def braid243_label(
    value: int,
    registry: TopicRegistry | None = None,
    cycle_registry: CycleRegistry | None = None,
) -> str:
    phase, topic = decode_braid243(value)
    registry = registry or TopicRegistry()
    cycle_registry = cycle_registry or CycleRegistry()
    return f"{cycle_registry.get(phase).code}:{registry.get(topic).code}"



def project_display_name(
    identity: BraidedId,
    registry: TopicRegistry | None = None,
    cycle_registry: CycleRegistry | None = None,
) -> str:
    registry = registry or TopicRegistry()
    cycle_registry = cycle_registry or CycleRegistry()
    topic = registry.get(identity.focus_topic)
    phase = cycle_registry.get(identity.phase)
    return (
        f"{identity.base_id.split('.')[-1]} — Epoch {identity.epoch} / {phase.label.title()} / "
        f"Focus {topic.code} / {identity.state.title()} / Lineage {identity.lineage}"
    )



def topic_surface_from_indices(indices: Iterable[int], registry: TopicRegistry | None = None) -> tuple[str, ...]:
    registry = registry or TopicRegistry()
    return tuple(registry.get(index).code for index in indices)
