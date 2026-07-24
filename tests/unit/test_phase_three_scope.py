"""Phase 3 source-boundary guardrails for contact-state implementation roots."""

from __future__ import annotations

from pathlib import Path

PHASE_THREE_PRODUCTION_ROOTS = ("domain", "ports", "protocols", "adapters")
FORBIDDEN_PHASE_THREE_SURFACES = (
    # Phase 5+ surfaces that must not appear yet
    "fastapi",
    "socket",
    "http.server",
    "network",
    "proverif",
    "formal",
    "benchmark",
    "tool_authoriz",
)


def _phase_three_source_files(saga_root: Path) -> tuple[Path, ...]:
    return tuple(
        sorted(
            path
            for root in PHASE_THREE_PRODUCTION_ROOTS
            for path in (saga_root / root).rglob("*.py")
        )
    )


def _forbidden_tokens_by_path(paths: tuple[Path, ...]) -> dict[Path, tuple[str, ...]]:
    matches: dict[Path, tuple[str, ...]] = {}
    for path in paths:
        source = path.read_text(encoding="utf-8").lower()
        tokens = tuple(token for token in FORBIDDEN_PHASE_THREE_SURFACES if token in source)
        if tokens:
            matches[path] = tokens
    return matches


def test_phase_three_guard_recursively_covers_all_contact_implementation_roots() -> None:
    saga_root = Path(__file__).parents[2] / "src" / "saga"
    scanned = _phase_three_source_files(saga_root)
    scanned_relative_paths = {path.relative_to(saga_root).as_posix() for path in scanned}

    assert {
        "domain/policies.py",
        "domain/otk.py",
        "domain/contact.py",
        "ports/registries.py",
        "protocols/user_registration.py",
        "adapters/persistence/memory.py",
        "adapters/persistence/sqlite.py",
    } <= scanned_relative_paths
    assert all(path.is_file() for path in scanned)
    assert _forbidden_tokens_by_path(scanned) == {}


def test_phase_three_guard_rejects_nested_surfaces_but_excludes_crypto_root(
    tmp_path: Path,
) -> None:
    for root in PHASE_THREE_PRODUCTION_ROOTS:
        module = tmp_path / root / "nested" / "allowed.py"
        module.parent.mkdir(parents=True)
        module.write_text("pass\n", encoding="utf-8")
    forbidden = tmp_path / "adapters" / "nested" / "future.py"
    forbidden.write_text("import fastapi\n", encoding="utf-8")
    ignored_crypto = tmp_path / "crypto" / "future.py"
    ignored_crypto.parent.mkdir(parents=True)
    ignored_crypto.write_text("class SOTK: pass\n", encoding="utf-8")

    scanned = _phase_three_source_files(tmp_path)

    assert forbidden in scanned
    assert ignored_crypto not in scanned
    assert _forbidden_tokens_by_path(scanned) == {forbidden: ("fastapi",)}

