from pathlib import Path

from tritrpc_requirements_impl.route_registry_v2 import RouteRegistryV2


BASE = Path(__file__).resolve().parents[1] / "configs"



def test_extended_sample_registry_loads() -> None:
    registry = RouteRegistryV2.load_yaml(BASE / "sample_registry_v2.yaml")
    route = registry.route(7)
    assert route.semantic_topic == 22
    assert route.observability_class == "standard"
    assert "local_terminal" in route.allowed_execution_venues



def test_extended_beacon_route_has_forensic_posture() -> None:
    registry = RouteRegistryV2.load_yaml(BASE / "sample_registry_v2.yaml")
    route = registry.route(19)
    assert route.semantic_topic == 23
    assert route.observability_class == "forensic"
    assert "incident_mode:contain" in route.latched_semaphores
