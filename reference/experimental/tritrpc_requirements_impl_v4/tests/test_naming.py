from tritrpc_requirements_impl.naming import (
    BraidedId,
    CycleRegistry,
    TopicRegistry,
    braid243_label,
    decode_braid243,
    encode_braid243,
    project_display_name,
    topic_surface_from_indices,
)



def test_braided_id_roundtrip() -> None:
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
    parsed = BraidedId.parse(identity.to_canonical())
    assert parsed == identity



def test_braid243_roundtrip() -> None:
    value = encode_braid243(phase=7, topic=23)
    assert decode_braid243(value) == (7, 23)



def test_display_projection_contains_phase_label_and_lineage() -> None:
    identity = BraidedId(
        base_id="sp.ux.identity.user-profile",
        epoch=5,
        phase=2,
        focus_topic=1,
        state="active",
        lineage=2,
    )
    text = project_display_name(identity)
    assert "Parse" in text
    assert "Lineage 2" in text



def test_topic_surface_uses_registry_codes() -> None:
    assert topic_surface_from_indices([17, 21]) == ("wfl", "pln")



def test_braid243_label_uses_cycle_and_topic_registry() -> None:
    value = encode_braid243(4, 21)
    assert braid243_label(value, TopicRegistry(), CycleRegistry()) == "dec:pln"
