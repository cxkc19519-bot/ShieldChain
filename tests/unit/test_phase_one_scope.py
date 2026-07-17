import ast
import sys
from pathlib import Path

import pytest

_ALLOWED_LAYER_PREFIXES = {
    "domain": ("saga.domain",),
    "crypto": ("saga.domain", "saga.crypto", "cryptography"),
    "ports": ("saga.domain", "saga.ports"),
}


def _absolute_imports(path: Path, source_root: Path = Path("src")) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[str] = []
    relative = path.relative_to(source_root)
    package_parts = relative.with_suffix("").parts[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parents_to_drop = node.level - 1
                if parents_to_drop >= len(package_parts):
                    imports.append("<invalid-relative-import>")
                    continue
                base_parts = package_parts[: len(package_parts) - parents_to_drop]
            else:
                base_parts = ()
            if node.module is not None:
                base_parts = (*base_parts, *node.module.split("."))
            base = ".".join(base_parts)
            if base:
                imports.append(base)
                imports.extend(f"{base}.{alias.name}" for alias in node.names if alias.name != "*")
            else:
                imports.append("<invalid-relative-import>")
    return tuple(imports)


def _is_allowed(imported: str, allowed_prefixes: tuple[str, ...]) -> bool:
    root = imported.partition(".")[0]
    return root in sys.stdlib_module_names or any(
        imported == prefix or imported.startswith(f"{prefix}.") for prefix in allowed_prefixes
    )


def _layer_violations(layer: str, source_root: Path = Path("src")) -> tuple[tuple[Path, str], ...]:
    layer_root = source_root / "saga" / layer
    allowed_prefixes = _ALLOWED_LAYER_PREFIXES[layer]
    return tuple(
        (path, imported)
        for path in layer_root.rglob("*.py")
        for imported in _absolute_imports(path, source_root)
        if not _is_allowed(imported, allowed_prefixes)
    )


def test_phase_one_foundations_do_not_depend_on_later_layers() -> None:
    assert tuple(Path("src/saga/domain").rglob("*.py"))
    assert tuple(Path("src/saga/crypto").rglob("*.py"))
    assert _layer_violations("domain") == ()
    assert _layer_violations("crypto") == ()


def test_phase_two_ports_depend_only_on_stdlib_and_domain() -> None:
    assert tuple(Path("src/saga/ports").rglob("*.py"))
    assert _layer_violations("ports") == ()


def test_relative_import_resolution_catches_root_and_nested_layer_escapes(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    files = {
        "saga/domain/root_bad.py": "from ..ports import Clock\n",
        "saga/domain/nested/deep_bad.py": "from ...ports.clock import Clock\n",
        "saga/ports/root_bad.py": "from ..crypto import signatures\n",
        "saga/ports/nested/deep_bad.py": "from ...crypto.signatures import verify\n",
    }
    for relative, content in files.items():
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    assert "saga.ports" in _absolute_imports(source_root / "saga/domain/root_bad.py", source_root)
    assert "saga.ports.clock" in _absolute_imports(
        source_root / "saga/domain/nested/deep_bad.py", source_root
    )
    assert "saga.crypto" in _absolute_imports(source_root / "saga/ports/root_bad.py", source_root)
    assert "saga.crypto.signatures" in _absolute_imports(
        source_root / "saga/ports/nested/deep_bad.py", source_root
    )


@pytest.mark.parametrize(
    ("layer", "content", "expected"),
    [
        ("domain", "from ..ports import Clock\n", "saga.ports"),
        ("crypto", "from ..ports import Clock\n", "saga.ports"),
        ("ports", "from ..crypto import signatures\n", "saga.crypto"),
    ],
)
def test_layer_violation_gate_rejects_synthetic_relative_imports(
    tmp_path: Path, layer: str, content: str, expected: str
) -> None:
    source_root = tmp_path / "src"
    path = source_root / "saga" / layer / "nested" / "bad.py"
    path.parent.mkdir(parents=True)
    path.write_text(content.replace("..", "..."), encoding="utf-8")
    violations = _layer_violations(layer, source_root)
    assert any(imported == expected for _, imported in violations)
