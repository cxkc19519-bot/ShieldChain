"""Phase 2 source-boundary guardrails.

These checks deliberately inspect production packages recursively.  A flat
``glob`` left nested domain and persistence modules outside the Phase 2 scope
proof, which would make the guardrail easy to bypass by moving a feature.
"""

from __future__ import annotations

from pathlib import Path

PHASE_TWO_PACKAGE_ROOTS = ("domain", "ports", "protocols", "adapters")
FORBIDDEN_PHASE_TWO_SURFACES = (
    # Phase 3: contact-policy evaluation and pair-counting state.
    "contactpolicymatcher",
    "policy_matcher",
    "policyengine",
    "policy_engine",
    "wildcard",
    "pair_counter",
    "paircounter",
    # Phase 3: OTK allocation/lifecycle (registration may only store OTKs).
    "otk_allocate",
    "allocate_otk",
    "otk_consume",
    "consume_otk",
    "otk_lifecycle",
    "one_time_key_allocation",
    # Phase 4: ACT protocol and state.
    "act_service",
    "actservice",
    "act_protocol",
    "actprotocol",
    "act_state",
    "actstate",
    # Phase 5+ transport/API and experimentation surfaces.
    "fastapi",
    "pydantic",
    "starlette",
    "uvicorn",
    "socket.",
    "http.server",
    "httpserver",
    "start_server",
    "listener",
    "proverif",
    "benchmark",
    # Post-baseline innovation: task/tool-call authorization.
    "task_authorization",
    "tool_authorization",
    "tool_call_authorization",
    "agent_tool_authorization",
)


def _phase_two_source_files(saga_root: Path) -> tuple[Path, ...]:
    """Return every Python production file in the Phase 2-owned packages."""
    return tuple(
        sorted(
            (
                path
                for package_root in PHASE_TWO_PACKAGE_ROOTS
                for path in (saga_root / package_root).rglob("*.py")
            ),
            key=lambda path: path.relative_to(saga_root).as_posix(),
        )
    )


def _forbidden_tokens_by_path(paths: tuple[Path, ...]) -> dict[Path, tuple[str, ...]]:
    """Map source files to the out-of-scope surfaces they introduce."""
    matches: dict[Path, tuple[str, ...]] = {}
    for path in paths:
        source = path.read_text(encoding="utf-8").lower()
        tokens = tuple(token for token in FORBIDDEN_PHASE_TWO_SURFACES if token in source)
        if tokens:
            matches[path] = tokens
    return matches


def test_phase_two_scope_scan_recursively_covers_all_owned_production_packages() -> None:
    saga_root = Path(__file__).parents[2] / "src" / "saga"
    scanned = _phase_two_source_files(saga_root)
    scanned_relative_paths = {path.relative_to(saga_root).as_posix() for path in scanned}

    assert all((saga_root / package_root).is_dir() for package_root in PHASE_TWO_PACKAGE_ROOTS)
    assert {
        "domain/users.py",
        "domain/agents.py",
        "ports/registries.py",
        "protocols/user_registration.py",
        "protocols/agent_registration.py",
        "adapters/persistence/memory.py",
        "adapters/persistence/sqlite.py",
    } <= scanned_relative_paths


def test_registration_packages_exclude_later_phase_and_innovation_surfaces() -> None:
    saga_root = Path(__file__).parents[2] / "src" / "saga"

    assert _forbidden_tokens_by_path(_phase_two_source_files(saga_root)) == {}


def test_scope_scan_and_forbidden_check_cannot_be_bypassed_by_nested_module(
    tmp_path: Path,
) -> None:
    for package_root in PHASE_TWO_PACKAGE_ROOTS:
        (tmp_path / package_root).mkdir(parents=True)
    nested_module = tmp_path / "adapters" / "persistence" / "deep" / "future.py"
    nested_module.parent.mkdir(parents=True)
    nested_module.write_text("class PolicyEngine: pass\n", encoding="utf-8")

    scanned = _phase_two_source_files(tmp_path)

    assert nested_module in scanned
    assert _forbidden_tokens_by_path(scanned) == {nested_module: ("policyengine",)}


def test_registration_services_keep_time_and_randomness_explicitly_injected() -> None:
    root = Path(__file__).parents[2] / "src" / "saga" / "protocols"
    user_source = (root / "user_registration.py").read_text(encoding="utf-8")
    agent_source = (root / "agent_registration.py").read_text(encoding="utf-8")
    assert "random_source: RandomSource" in user_source
    assert "clock: Clock" in user_source
    assert "clock: Clock" in agent_source
    assert "time.sleep" not in user_source + agent_source
