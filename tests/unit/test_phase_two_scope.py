"""Phase 2 source-boundary guardrails."""

from __future__ import annotations

from pathlib import Path


def test_registration_packages_exclude_phase_three_network_and_innovation_surfaces() -> None:
    root = Path(__file__).parents[2] / "src" / "saga"
    scanned = (
        tuple((root / "protocols").glob("*.py"))
        + tuple((root / "adapters" / "persistence").glob("*.py"))
        + tuple((root / "ports").glob("*.py"))
    )
    forbidden = (
        "fastapi",
        "pydantic",
        "proverif",
        "benchmark",
        "contactpolicymatcher",
        "wildcard",
        "pair_counter",
        "otk_allocate",
        "otk_consume",
        "act_service",
        "task_authorization",
        "tool_authorization",
        "socket.",
        "http.server",
        "time.sleep",
    )
    source = "\n".join(path.read_text(encoding="utf-8").lower() for path in scanned)
    assert all(token not in source for token in forbidden)


def test_registration_services_keep_time_and_randomness_explicitly_injected() -> None:
    root = Path(__file__).parents[2] / "src" / "saga" / "protocols"
    user_source = (root / "user_registration.py").read_text(encoding="utf-8")
    agent_source = (root / "agent_registration.py").read_text(encoding="utf-8")
    assert "random_source: RandomSource" in user_source
    assert "clock: Clock" in user_source
    assert "clock: Clock" in agent_source
    assert "time.sleep" not in user_source + agent_source
