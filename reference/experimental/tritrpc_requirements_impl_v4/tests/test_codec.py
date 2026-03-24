from tritrpc_requirements_impl.codec import (
    Control243,
    EvidenceGrade,
    EpistemicTrit,
    ExecLane,
    ExtendedHandle,
    FallbackPolicy,
    FrictionTrit,
    HashHandle,
    LifecycleTrit,
    NoveltyTrit,
    PathProfile,
    RouteFormat,
    ScopeTrit,
    State243,
    TOMBSTONE,
    decode_handle243,
    decode_s243,
    encode_handle243,
    encode_s243,
    tleb3_decode,
    tleb3_encode,
    tritpack243_pack,
    tritpack243_unpack,
)


def test_tritpack243_roundtrip_with_tail() -> None:
    trits = [2, 1, 0, 2, 1, 2, 0]
    packed = tritpack243_pack(trits)
    assert tritpack243_unpack(packed) == trits



def test_tleb3_roundtrip() -> None:
    for value in [0, 1, 8, 9, 242, 243, 244, 4096, 65535]:
        encoded = tleb3_encode(value)
        decoded, new_offset = tleb3_decode(encoded)
        assert decoded == value
        assert new_offset == len(encoded)



def test_s243_roundtrip() -> None:
    for value in [0, 1, 242, 243, 244, 9999]:
        encoded = encode_s243(value)
        decoded, new_offset = decode_s243(encoded)
        assert decoded == value
        assert new_offset == len(encoded)



def test_control243_roundtrip() -> None:
    control = Control243(
        profile=PathProfile.PATH_H,
        lane=ExecLane.HYBRID,
        evidence=EvidenceGrade.VERIFIED,
        fallback=FallbackPolicy.HEDGED_OK,
        routefmt=RouteFormat.BEACON_REF,
    )
    assert Control243.decode(control.encode()) == control



def test_state243_roundtrip() -> None:
    state = State243(
        lifecycle=LifecycleTrit.ACTIVE,
        epistemic=EpistemicTrit.VERIFIED,
        novelty=NoveltyTrit.NOVEL,
        friction=FrictionTrit.REVIEW,
        scope=ScopeTrit.COHORT,
    )
    assert State243.decode(state.encode()) == state



def test_handle243_variants() -> None:
    for handle in [7, ExtendedHandle(1000), "route/name", HashHandle(b"h" * 32), TOMBSTONE]:
        encoded = encode_handle243(handle)
        decoded, new_offset = decode_handle243(encoded)
        assert decoded == handle
        assert new_offset == len(encoded)
