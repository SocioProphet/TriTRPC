"""Reference implementation for TriTRPC vNext requirements work."""

from .audit import AuditRecord, append_audit_record, verify_audit_chain
from .boundary import BoundaryManifest, validate_boundary, validate_boundary_for_profile
from .codec import (
    Control243,
    TritPack243Error,
    decode_s243,
    encode_s243,
    tritpack243_pack,
    tritpack243_unpack,
)
from .deployment import AssuranceTarget, DeploymentManifest, validate_deployment
from .frames import (
    AesGcmDemoTagProvider,
    BeaconFrame,
    CryptoSuite,
    FrameKind,
    HotUnaryFrame,
    MAGIC,
    NullTagProvider,
    parse_frame,
    serialize_frame,
)
from .naming import BraidedId, decode_braid243, encode_braid243
from .policy import ProfileConfig, ValidationFinding, validate_profile, validate_profile_semantics

__all__ = [
    "AuditRecord",
    "append_audit_record",
    "verify_audit_chain",
    "BoundaryManifest",
    "validate_boundary",
    "validate_boundary_for_profile",
    "Control243",
    "TritPack243Error",
    "decode_s243",
    "encode_s243",
    "tritpack243_pack",
    "tritpack243_unpack",
    "AssuranceTarget",
    "DeploymentManifest",
    "validate_deployment",
    "AesGcmDemoTagProvider",
    "BeaconFrame",
    "CryptoSuite",
    "FrameKind",
    "HotUnaryFrame",
    "MAGIC",
    "NullTagProvider",
    "parse_frame",
    "serialize_frame",
    "BraidedId",
    "decode_braid243",
    "encode_braid243",
    "ProfileConfig",
    "ValidationFinding",
    "validate_profile",
    "validate_profile_semantics",
]

from .compare import generate_transport_comparison, render_transport_comparison_markdown
