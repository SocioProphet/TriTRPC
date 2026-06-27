from tritrpc_requirements_impl.compare import generate_braid_cadence_comparison, generate_transport_comparison


def test_hot_unary_comparison_lengths():
    payload = generate_transport_comparison()
    hot = payload["scenarios"]["hot_unary_small_secure"]["lengths"]
    assert hot["tritrpc"] == 52
    assert hot["protobuf_handle"] == 56
    assert hot["protobuf_fused"] == 54
    assert hot["thrift_compact_handle"] == 59
    assert hot["thrift_compact_fused"] == 55



def test_stream_data_comparison_lengths():
    payload = generate_transport_comparison()
    data = payload["scenarios"]["stream_data_small_secure"]["lengths"]
    assert data["tritrpc"] == 35
    assert data["protobuf_handle"] == 41
    assert data["protobuf_fused"] == 37
    assert data["thrift_compact_handle"] == 42
    assert data["thrift_compact_fused"] == 38



def test_tristate_vector_surface():
    payload = generate_transport_comparison()
    vec = payload["scenarios"]["tristate_vector_100_payload_only"]["lengths"]
    assert vec["tritrpc_tritpack243"] == 20
    assert vec["protobuf_packed_uint32"] == 102
    assert vec["thrift_compact_list_i32"] == 104



def test_large_payload_surface_not_universal():
    payload = generate_transport_comparison()
    large = payload["scenarios"]["hot_unary_large_secure_1024"]["lengths"]
    assert large["tritrpc"] == 1052
    assert large["protobuf_fused"] == 1051



def test_braid_cadence_inheritance_beats_per_frame():
    payload = generate_braid_cadence_comparison()
    lengths = payload["lengths"]
    assert lengths["stream_open_inherited"] == lengths["stream_open_base"] + 2
    assert lengths["stream_data_per_frame"] == lengths["stream_data_base"] + 2
    totals = payload["totals"]["one_stream_1000_data"]
    assert totals["inherited_open_defaults"] < totals["per_frame_braid_state"]
    assert payload["break_even"]["inherited_vs_per_frame_data_frames"] == 2
