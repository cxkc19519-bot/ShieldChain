import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_python_lock_is_exact_local_and_covers_declared_dependencies() -> None:
    lock_lines = [
        line.strip()
        for line in _read("backend/requirements.lock").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert lock_lines[0] == "-e .[test]"
    pins = {}
    for line in lock_lines[1:]:
        assert "==" in line
        assert "http://" not in line and "https://" not in line and "git+" not in line
        requirement, _, marker = line.partition(";")
        name, version = requirement.strip().split("==", 1)
        assert re.fullmatch(r"[A-Za-z0-9_.-]+", name)
        assert re.fullmatch(r"[A-Za-z0-9_.+-]+", version)
        normalized_name = re.sub(r"[-_.]+", "-", name).casefold()
        if marker:
            expected_markers = {
                "pywin32": 'sys_platform == "win32"',
                "uvloop": 'sys_platform != "win32"',
            }
            assert marker.strip() == expected_markers[normalized_name]
        pins[normalized_name] = version

    pyproject = _read("backend/pyproject.toml")
    for dependency in (
        "alembic",
        "beautifulsoup4",
        "defusedxml",
        "fastapi",
        "httpx",
        "httpx2",
        "mcp",
        "openpyxl",
        "pydantic-settings",
        "pypdf",
        "python-docx",
        "python-multipart",
        "pyyaml",
        "sqlalchemy",
        "structlog",
        "uvicorn",
    ):
        assert dependency in pyproject.casefold()
        assert dependency in pins

    runtime_lock = _read("backend/requirements-runtime.lock")
    assert "pytest" not in runtime_lock and "ruff" not in runtime_lock
    for line in runtime_lock.splitlines():
        requirement = line.split(";", 1)[0].strip()
        assert "==" in requirement
    dockerfile = _read("backend/Dockerfile")
    assert "COPY backend/requirements-runtime.lock" in dockerfile
    assert "pip install -r /build/backend/requirements-runtime.lock" in dockerfile
    assert "pip install --no-deps /build/backend" in dockerfile


def test_npm_lock_has_integrity_for_every_registry_package() -> None:
    lock = json.loads(_read("frontend/package-lock.json"))
    assert lock["lockfileVersion"] == 3
    assert lock["packages"][""]["name"] == "shieldchain-frontend"
    registry_packages = 0
    for path, package in lock["packages"].items():
        if not path:
            continue
        resolved = package.get("resolved", "")
        if resolved.startswith("https://registry.npmjs.org/"):
            registry_packages += 1
            assert package.get("integrity", "").startswith("sha512-")
        assert not resolved.startswith("git+")
        assert "token=" not in resolved.casefold()
    assert registry_packages >= 100


def test_ci_actions_are_sha_pinned_and_least_privilege() -> None:
    workflow = _read(".github/workflows/ci.yml")
    assert "permissions:\n  contents: read" in workflow
    assert "pull_request_target" not in workflow
    uses = re.findall(r"uses:\s*([^\s#]+)", workflow)
    assert uses
    for action in uses:
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)
    assert "persist-credentials: false" in workflow
    assert "timeout-minutes:" in workflow


def test_container_smoke_is_bounded_optional_and_cleans_its_own_project() -> None:
    script = _read("tests/scripts/run-phase8-container-smoke.ps1")
    assert "DOCKER_RUNTIME_TESTED=False" in script
    assert "DOCKER_RUNTIME_TESTED=True" in script
    assert "Get-Command docker" in script
    assert "[switch]$StaticOnly" in script
    assert "service_healthy" not in script
    assert "--wait" in script
    assert "Invoke-RestMethod" in script
    assert "id -u" in script
    assert "ReadonlyRootfs" in script
    assert "down --volumes --remove-orphans" in script
    assert "shieldchain-phase8-" in script
    assert "Remove-Item" not in script


@pytest.mark.parametrize(
    ("response", "exit_code"),
    [
        ("'ok'", 0),
        ('"ok`n"', 0),
        ('"ok`r`n"', 0),
        ("'not ok'", 1),
        ("''", 1),
        ("$null", 1),
    ],
)
def test_container_health_accepts_plain_text_line_endings(response, exit_code) -> None:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell is required to execute the container smoke predicate")
    script = _read("tests/scripts/run-phase8-container-smoke.ps1")
    condition = re.search(r"if \(([^\n]*\$frontendHealth[^\n]*)\) \{", script)
    assert condition is not None
    result = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$frontendHealth = {response}; "
            f"if ({condition.group(1)}) {{ exit 1 }} else {{ exit 0 }}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == exit_code, result.stderr


def test_compose_volume_is_project_scoped_for_safe_smoke_cleanup() -> None:
    compose = _read("compose.yaml")
    volume_section = compose.split("\nvolumes:\n", 1)[1]
    assert "shieldchain-data:" in volume_section
    assert "name:" not in volume_section
