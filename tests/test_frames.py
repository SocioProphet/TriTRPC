from tritrpc_requirements_impl.codec import (
    Control243,
    EvidenceGrade,
    EpistemicTrit,
    ExecLane,
    FallbackPolicy,
    FrictionTrit,
    LifecycleTrit,
    NoveltyTrit,
    PathProfile,
    RouteFormat,
    ScopeTrit,
    State243,
)
from tritrpc_requirements_impl.frames import (
    AesGcmDemoTagProvider,
    BeaconFrame,
    CryptoSuite,
    FrameKind,
    HotUnaryFrame,
    StreamDataFrame,
    StreamOpenFrame,
    parse_frame,
    resolve_stream_semantics,
    serialize_frame,
)
from tritrpc_requirements_impl.naming import encode_braid243



def _control() -> Control243:
    return Control243(
        profile=PathProfile.PATH_A,
        lane=ExecLane.CLASSICAL,
        evidence=EvidenceGrade.EXACT,
        fallback=FallbackPolicy.NONE,
        routefmt=RouteFormat.HANDLE,
    )



def _state() -> State243:
    return State243(
        lifecycle=LifecycleTrit.ACTIVE,
        epistemic=EpistemicTrit.VERIFIED,
        novelty=NoveltyTrit.ROUTINE,
        friction=FrictionTrit.FLUID,
        scope=ScopeTrit.COHORT,
    )



def test_hot_unary_roundtrip() -> None:
    frame = HotUnaryFrame(
        control=_control(),
        suite=CryptoSuite.FIPS_CLASSICAL,
        epoch=18,
        route_handle=7,
        payload=b'{"hello":"world"}',
    )
    raw = serialize_frame(frame)
    parsed = parse_frame(raw)
    assert parsed == HotUnaryFrame(
        control=frame.control,
        suite=frame.suite,
        epoch=frame.epoch,
        route_handle=frame.route_handle,
        payload=frame.payload,
        kind=frame.kind,
        tag=raw[-16:],
    )



def test_stream_data_roundtrip_without_semantics() -> None:
    frame = StreamDataFrame(
        control=_control(),
        suite=CryptoSuite.FIPS_CLASSICAL,
        epoch=18,
        stream_id=9,
        payload=b'{"chunk":1}',
    )
    raw = serialize_frame(frame)
    parsed = parse_frame(raw)
    assert parsed.payload == frame.payload
    assert parsed.kind == FrameKind.STREAM_DATA
    assert parsed.semantic_override_braid is None



def test_stream_open_and_data_with_braid_semantics() -> None:
    braid = encode_braid243(4, 14)
    state = _state()
    open_frame = StreamOpenFrame(
        control=_control(),
        suite=CryptoSuite.FIPS_CLASSICAL,
        epoch=18,
        route_handle=7,
        stream_id=9,
        payload=b'{"cursor":"start"}',
        default_braid=braid,
        default_state=state,
    )
    data_frame = StreamDataFrame(
        control=_control(),
        suite=CryptoSuite.FIPS_CLASSICAL,
        epoch=18,
        stream_id=9,
        payload=b'{"chunk":1}',
    )
    raw_open = serialize_frame(open_frame)
    raw_data = serialize_frame(data_frame)
    parsed_open = parse_frame(raw_open)
    parsed_data = parse_frame(raw_data)
    resolved = resolve_stream_semantics(parsed_open, parsed_data)
    assert resolved.braid == braid
    assert resolved.state == state
    assert resolved.source == "inherited"



def test_stream_data_override_semantics_roundtrip() -> None:
    braid = encode_braid243(4, 14)
    state = _state()
    frame = StreamDataFrame(
        control=_control(),
        suite=CryptoSuite.FIPS_CLASSICAL,
        epoch=18,
        stream_id=9,
        payload=b'{"chunk":1}',
        semantic_override_braid=braid,
        semantic_override_state=state,
    )
    raw = serialize_frame(frame)
    parsed = parse_frame(raw)
    assert parsed.semantic_override_braid == braid
    assert parsed.semantic_override_state == state



def test_beacon_roundtrip_with_aesgcm_demo_provider() -> None:
    provider = AesGcmDemoTagProvider(bytes(range(32)))
    frame = BeaconFrame(
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
        phase=4,
        topic=14,
        payload=b'commit',
        sequence=77,
        kind=FrameKind.BEACON_COMMIT,
    )
    raw = serialize_frame(frame, provider)
    assert provider.verify(raw[:-16], raw[-16:], frame.suite, frame.sequence)
    parsed = parse_frame(raw)
    assert parsed.phase == 4
    assert parsed.topic == 14
