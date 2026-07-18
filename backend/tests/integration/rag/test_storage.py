from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from shieldchain.rag.ports import ContentNotFoundError, ContentStoreError
from shieldchain.rag.storage import LocalContentStore


def test_local_store_uses_server_generated_uuid_key_and_streams_to_an_atomic_file(
    tmp_path: Path,
) -> None:
    store = LocalContentStore(tmp_path / "knowledge")

    stored = store.put((b"safe ", b"content"), media_type="text/plain")

    assert stored.storage_key.startswith("knowledge/")
    assert stored.content_sha256 == hashlib.sha256(b"safe content").hexdigest()
    assert stored.size_bytes == 12
    assert store.read(stored.storage_key) == b"safe content"
    assert list((tmp_path / "knowledge").rglob("*.partial")) == []


def test_local_store_rejects_path_traversal_and_never_reads_or_deletes_outside_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "knowledge"
    store = LocalContentStore(root)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"keep")

    for key in ("../outside.txt", "knowledge/../outside.txt", str(outside), "knowledge/not-a-uuid"):
        with pytest.raises((ContentStoreError, ContentNotFoundError)):
            store.read(key)
        with pytest.raises(ContentStoreError):
            store.delete(key)

    assert outside.read_bytes() == b"keep"


def test_local_store_delete_is_idempotent_and_put_failure_leaves_no_partial_file(
    tmp_path: Path,
) -> None:
    root = tmp_path / "knowledge"
    store = LocalContentStore(root)
    stored = store.put([b"content"], media_type="text/plain")

    store.delete(stored.storage_key)
    store.delete(stored.storage_key)
    with pytest.raises(ContentNotFoundError):
        store.read(stored.storage_key)

    def broken_stream():
        yield b"start"
        raise RuntimeError("source failed")

    with pytest.raises(ContentStoreError):
        store.put(broken_stream(), media_type="text/plain")
    assert list(root.rglob("*.partial")) == []


def test_local_store_refuses_real_reparse_point_ancestor(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "junction"
    if os.name == "nt":
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            shell=False,
            capture_output=True,
            text=True,
        )
    else:
        link.symlink_to(target, target_is_directory=True)
    try:
        root = link / "knowledge"
        with pytest.raises(ContentStoreError) as error:
            LocalContentStore(root)
        assert error.value.__cause__ is None
    finally:
        if link.exists() or link.is_symlink():
            link.rmdir()


def test_local_store_best_effort_detects_reparse_swap_before_replace(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "knowledge"
    store = LocalContentStore(root)
    reparse_paths: set[Path] = set()
    original = LocalContentStore._is_reparse_point
    monkeypatch.setattr(
        LocalContentStore,
        "_is_reparse_point",
        staticmethod(lambda path: path in reparse_paths or original(path)),
    )

    def swap_after_first_check(phase: str) -> None:
        if phase == "put.before_replace":
            reparse_paths.add(root)

    store._security_hook = swap_after_first_check
    with pytest.raises(ContentStoreError) as error:
        store.put([b"content"], media_type="text/plain")
    assert str(error.value) == "content cleanup failed"
    assert len(list(root.glob("*.partial"))) == 1


def test_storage_suppresses_sensitive_causes_and_cleans_up_on_base_exception(
    tmp_path: Path,
) -> None:
    root = tmp_path / "knowledge"
    store = LocalContentStore(root)

    def broken_stream():
        yield b"start"
        raise RuntimeError("C:\\users\\secret API_KEY")

    with pytest.raises(ContentStoreError) as error:
        store.put(broken_stream(), media_type="text/plain")
    assert error.value.__cause__ is None
    assert "secret" not in str(error.value).lower()
    assert list(root.glob("*.partial")) == []

    class StopNow(BaseException):
        pass

    def interrupted_stream():
        yield b"start"
        raise StopNow()

    with pytest.raises(StopNow):
        store.put(interrupted_stream(), media_type="text/plain")
    assert list(root.glob("*.partial")) == []


def test_storage_reports_cleanup_failure_instead_of_silently_masking_it(
    tmp_path: Path, monkeypatch
) -> None:
    store = LocalContentStore(tmp_path / "knowledge")
    monkeypatch.setattr(store, "_cleanup_partial", lambda path: False)

    def broken_stream():
        yield b"start"
        raise RuntimeError("secret")

    with pytest.raises(ContentStoreError) as error:
        store.put(broken_stream(), media_type="text/plain")
    assert str(error.value) == "content cleanup failed"
    assert error.value.__cause__ is None
