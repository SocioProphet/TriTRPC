from tritrpc_requirements_impl.beacon_delta_v2 import SemaphoreOp, TypedBeaconDeltaV1, decode_typed_beacon_delta, encode_typed_beacon_delta



def test_typed_beacon_delta_round_trip() -> None:
    delta = TypedBeaconDeltaV1(
        schema_version="tritrpc.beacon.delta.v1",
        delta_class="intent",
        epoch=18,
        phase=4,
        topic=23,
        semaphore_ops=(SemaphoreOp(family="review_mode", op="set", value="human_required"),),
        policy_bundle_ref="policy.control.v1",
    )
    encoded = encode_typed_beacon_delta(delta)
    decoded = decode_typed_beacon_delta(encoded)
    assert decoded == delta
