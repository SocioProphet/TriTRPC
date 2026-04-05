from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from .audit import AuditRecord, append_audit_record, audit_record_from_frame, verify_audit_chain
from .boundary import BoundaryManifest, validate_boundary
from .codec import (
    Control243,
    PathProfile,
    ExecLane,
    EvidenceGrade,
    FallbackPolicy,
    RouteFormat,
    State243,
    LifecycleTrit,
    EpistemicTrit,
    NoveltyTrit,
    FrictionTrit,
    ScopeTrit,
)
from .deployment import DeploymentManifest, validate_deployment
from .frames import (
    AesGcmDemoTagProvider,
    BeaconFrame,
    CryptoSuite,
    FrameKind,
    HotUnaryFrame,
    NullTagProvider,
    StreamDataFrame,
    StreamOpenFrame,
    serialize_frame,
)
from .naming import BraidedId, CycleRegistry, TopicRegistry
from .policy import ProfileConfig, has_errors, validate_profile
from .compare import (
    generate_transport_comparison,
    render_transport_comparison_markdown,
    generate_braid_cadence_comparison,
    render_braid_cadence_markdown,
)
from .route_policy_vector_validator import validate_vector_file



def _load_profile(path: str | Path) -> ProfileConfig:
    with open(path, "r", encoding="utf-8") as handle:
        return ProfileConfig.from_mapping(yaml.safe_load(handle))



def cmd_validate(args: argparse.Namespace) -> int:
    profile = _load_profile(args.config)
    findings = validate_profile(profile, require_validated_module=not args.relaxed)
    payload = [finding.__dict__ for finding in findings]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if has_errors(findings) else 0



def cmd_validate_boundary(args: argparse.Namespace) -> int:
    boundary = BoundaryManifest.load_yaml(args.config)
    findings = validate_boundary(boundary, require_certificate=args.require_certificate)
    payload = [finding.__dict__ for finding in findings]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if has_errors(findings) else 0



def cmd_validate_deployment(args: argparse.Namespace) -> int:
    manifest = DeploymentManifest.load_yaml(args.config)
    findings = validate_deployment(manifest)
    payload = [finding.__dict__ for finding in findings]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if has_errors(findings) else 0



def _sample_frames(null_tag: bool):
    provider = NullTagProvider() if null_tag else AesGcmDemoTagProvider(bytes(range(32)))
    control = Control243(
        profile=PathProfile.PATH_A,
        lane=ExecLane.CLASSICAL,
        evidence=EvidenceGrade.EXACT,
        fallback=FallbackPolicy.NONE,
        routefmt=RouteFormat.HANDLE,
    )
    hot = HotUnaryFrame(
        control=control,
        suite=CryptoSuite.FIPS_CLASSICAL,
        epoch=18,
        route_handle=7,
        payload=b'{"op":"add-vertex","id":"a"}',
        sequence=1,
        kind=FrameKind.UNARY_REQ,
    )
    identity = BraidedId(
        base_id="sp.agentplane.runtime.workflow.executor",
        epoch=18,
        phase=4,
        focus_topic=21,
        state="verified",
        lineage=3,
        runtime_env="prod.use1",
        topic_surface=("wfl", "pln"),
    )
    state = State243(
        lifecycle=LifecycleTrit.ACTIVE,
        epistemic=EpistemicTrit.VERIFIED,
        novelty=NoveltyTrit.ROUTINE,
        friction=FrictionTrit.FLUID,
        scope=ScopeTrit.COHORT,
    )
    stream_open = StreamOpenFrame(
        control=control,
        suite=CryptoSuite.FIPS_CLASSICAL,
        epoch=18,
        route_handle=7,
        stream_id=9,
        payload=b'{"cursor":"start"}',
        default_braid=identity.to_braid243(),
        default_state=state,
        sequence=2,
    )
    stream_data = StreamDataFrame(
        control=control,
        suite=CryptoSuite.FIPS_CLASSICAL,
        epoch=18,
        stream_id=9,
        payload=b'{"chunk":1}',
        sequence=3,
    )
    beacon = BeaconFrame(
        control=Control243(
            profile=PathProfile.PATH_H,
            lane=ExecLane.HYBRID,
            evidence=EvidenceGrade.VERIFIED,
            fallback=FallbackPolicy.HEDGED_OK,
            routefmt=RouteFormat.BEACON_REF,
        ),
        suite=CryptoSuite.CNSA2_READY,
        epoch=18,
        identity_handle=19,
        phase=identity.phase,
        topic=identity.focus_topic,
        payload=bytes([state.encode()]) + identity.to_canonical().encode("utf-8"),
        sequence=4,
        kind=FrameKind.BEACON_COMMIT,
    )
    return provider, hot, stream_open, stream_data, beacon, identity, state



def cmd_emit_vectors(args: argparse.Namespace) -> int:
    provider, hot, stream_open, stream_data, beacon, identity, state = _sample_frames(args.null_tag)
    vectors = {
        "hot_unary": serialize_frame(hot, provider).hex(),
        "stream_open_inherited": serialize_frame(stream_open, provider).hex(),
        "stream_data_inherit": serialize_frame(stream_data, provider).hex(),
        "stream_data_override": serialize_frame(StreamDataFrame(control=stream_data.control, suite=stream_data.suite, epoch=stream_data.epoch, stream_id=stream_data.stream_id, payload=stream_data.payload, semantic_override_braid=identity.to_braid243(), semantic_override_state=state, sequence=30), provider).hex(),
        "beacon_commit": serialize_frame(beacon, provider).hex(),
        "beacon_identity": identity.to_canonical(),
        "state243": state.encode(),
    }
    output = Path(args.output)
    output.write_text(json.dumps(vectors, indent=2, sort_keys=True), encoding="utf-8")
    print(output)
    return 0



def cmd_emit_audit(args: argparse.Namespace) -> int:
    provider, hot, stream_open, stream_data, beacon, identity, _state = _sample_frames(args.null_tag)
    frames = [hot, stream_open, stream_data, beacon]
    chain: list[AuditRecord] = []
    for idx, frame in enumerate(frames, start=1):
        record = audit_record_from_frame(
            frame,
            timestamp=f"2026-03-11T03:0{idx}:00Z",
            decision="allow",
            braided_identity=identity.to_canonical() if idx == len(frames) else None,
        )
        record = AuditRecord(**{**record.__dict__, "sequence": idx})
        chain.append(append_audit_record(chain, record, hash_name=args.hash_name))
    payload = {
        "hash_name": args.hash_name,
        "valid": verify_audit_chain(chain, hash_name=args.hash_name),
        "records": [record.__dict__ for record in chain],
    }
    output = Path(args.output)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(output)
    return 0



def cmd_compare_transports(args: argparse.Namespace) -> int:
    payload = generate_transport_comparison()
    output = Path(args.output)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    if args.markdown:
        md = Path(args.markdown)
        md.write_text(render_transport_comparison_markdown(payload), encoding="utf-8")
        print(md)
    print(output)
    return 0


def cmd_compare_braid(args: argparse.Namespace) -> int:
    payload = generate_braid_cadence_comparison()
    output = Path(args.output)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    if args.markdown:
        md = Path(args.markdown)
        md.write_text(render_braid_cadence_markdown(payload), encoding="utf-8")
        print(md)
    print(output)
    return 0


def cmd_emit_codebooks(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    topic_path = output_dir / "topic23_v1_proposed.yaml"
    cycle_path = output_dir / "cycle7_v1_proposed.yaml"
    topic_path.write_text(yaml.safe_dump(TopicRegistry().to_mapping(), sort_keys=False), encoding="utf-8")
    cycle_path.write_text(yaml.safe_dump(CycleRegistry().to_mapping(), sort_keys=False), encoding="utf-8")
    print(topic_path)
    print(cycle_path)
    return 0



def cmd_validate_route_policy_vectors(args: argparse.Namespace) -> int:
    payload = [validate_vector_file(path) for path in args.paths]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tritrpc-vnext-ref")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate")
    p_validate.add_argument("config")
    p_validate.add_argument("--relaxed", action="store_true", help="allow standards-inspired validation without requiring a certificate-bound module")
    p_validate.set_defaults(func=cmd_validate)

    p_boundary = sub.add_parser("validate-boundary")
    p_boundary.add_argument("config")
    p_boundary.add_argument("--require-certificate", action="store_true")
    p_boundary.set_defaults(func=cmd_validate_boundary)

    p_deploy = sub.add_parser("validate-deployment")
    p_deploy.add_argument("config")
    p_deploy.set_defaults(func=cmd_validate_deployment)

    p_vectors = sub.add_parser("emit-vectors")
    p_vectors.add_argument("output")
    p_vectors.add_argument("--null-tag", action="store_true")
    p_vectors.set_defaults(func=cmd_emit_vectors)

    p_compare = sub.add_parser("compare-transports")
    p_compare.add_argument("output")
    p_compare.add_argument("--markdown")
    p_compare.set_defaults(func=cmd_compare_transports)

    p_braid = sub.add_parser("compare-braid-cadence")
    p_braid.add_argument("output")
    p_braid.add_argument("--markdown")
    p_braid.set_defaults(func=cmd_compare_braid)

    p_codebooks = sub.add_parser("emit-codebooks")
    p_codebooks.add_argument("output_dir")
    p_codebooks.set_defaults(func=cmd_emit_codebooks)

    p_route_policy = sub.add_parser("validate-route-policy-vectors")
    p_route_policy.add_argument("paths", nargs="+")
    p_route_policy.set_defaults(func=cmd_validate_route_policy_vectors)

    p_audit = sub.add_parser("emit-audit")
    p_audit.add_argument("output")
    p_audit.add_argument("--null-tag", action="store_true")
    p_audit.add_argument("--hash-name", default="sha384")
    p_audit.set_defaults(func=cmd_emit_audit)
    return parser



def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
