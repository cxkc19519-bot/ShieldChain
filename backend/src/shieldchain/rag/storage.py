"""Local, contained content store for server-generated RAG document keys."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterable
from pathlib import Path
from uuid import UUID, uuid4

from shieldchain.rag.ports import ContentNotFoundError, ContentStoreError, StoredContent

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_FileIdentity = tuple[int, int]


class LocalContentStore:
    """Stores UUID-addressed files below an application-account-exclusive content root.

    Static and operation-boundary reparse/identity checks are defense in depth, not a claim to
    defeat a local concurrent attacker who can write the root or an ancestor. Such write access is
    outside the Phase 3 threat model; a future object-store or Win32-handle adapter can narrow that
    race further.
    """

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise TypeError("root must be a Path")
        self._root = root.absolute()
        self._security_hook: Callable[[str], None] = lambda _phase: None
        self._create_or_verify_root()
        self._root_real = self._root.resolve(strict=True)
        self._root_identity = self._identity(self._root.lstat())
        self._verify_root()

    def put(self, content: Iterable[bytes], *, media_type: str) -> StoredContent:
        if not isinstance(media_type, str) or not media_type.strip():
            raise ContentStoreError("invalid content metadata")
        self._verify_root()
        content_id = uuid4()
        target = self._target_for_uuid(content_id)
        temporary = self._root / f".{uuid4()}.partial"
        digest = hashlib.sha256()
        size_bytes = 0
        temporary_identity: _FileIdentity | None = None
        committed = False
        try:
            self._assert_absent(temporary)
            self._checkpoint("put.before_open")
            self._verify_root()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                for chunk in content:
                    if not isinstance(chunk, bytes | bytearray | memoryview):
                        raise ContentStoreError("invalid content stream")
                    block = bytes(chunk)
                    output.write(block)
                    digest.update(block)
                    size_bytes += len(block)
                output.flush()
                os.fsync(output.fileno())
                temporary_identity = self._identity(os.fstat(output.fileno()))
            if size_bytes == 0:
                raise ContentStoreError("empty content is not accepted")
            self._verify_existing_target(temporary, temporary_identity)
            self._checkpoint("put.before_replace")
            self._verify_root()
            self._verify_existing_target(temporary, temporary_identity)
            self._assert_absent(target)
            os.replace(temporary, target)
            self._verify_root()
            self._verify_existing_target(target, temporary_identity)
            committed = True
        except BaseException as error:
            if not committed and not self._cleanup_failed_write(
                temporary, target, temporary_identity
            ):
                raise ContentStoreError("content cleanup failed") from None
            if isinstance(error, ContentStoreError):
                raise
            if isinstance(error, Exception):
                raise ContentStoreError("content write failed") from None
            raise
        return StoredContent(
            storage_key=f"knowledge/{content_id}",
            content_sha256=digest.hexdigest(),
            size_bytes=size_bytes,
            media_type=media_type.strip().lower(),
        )

    def read(self, storage_key: str) -> bytes:
        target = self._target_for_key(storage_key)
        identity = self._existing_identity_or_not_found(target)
        try:
            self._verify_existing_target(target, identity)
            self._checkpoint("read.before_open")
            self._verify_root()
            self._verify_existing_target(target, identity)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags)
            with os.fdopen(descriptor, "rb") as source:
                if self._identity(os.fstat(source.fileno())) != identity:
                    raise ContentStoreError("stored content changed during read")
                self._verify_existing_target(target, identity)
                result = source.read()
            self._verify_root()
            self._verify_existing_target(target, identity)
            return result
        except ContentStoreError:
            raise
        except FileNotFoundError:
            raise ContentNotFoundError("stored content was not found") from None
        except OSError:
            raise ContentStoreError("stored content could not be read") from None

    def delete(self, storage_key: str) -> None:
        target = self._target_for_key(storage_key)
        try:
            identity = self._existing_identity_or_not_found(target)
        except ContentNotFoundError:
            return
        try:
            self._verify_existing_target(target, identity)
            self._checkpoint("delete.before_unlink")
            self._verify_root()
            self._verify_existing_target(target, identity)
            target.unlink()
            self._verify_root()
        except ContentStoreError:
            raise
        except FileNotFoundError:
            return
        except OSError:
            raise ContentStoreError("stored content could not be deleted") from None

    def _target_for_key(self, storage_key: str) -> Path:
        if not isinstance(storage_key, str) or not storage_key.startswith("knowledge/"):
            raise ContentStoreError("invalid storage key")
        identifier = storage_key.removeprefix("knowledge/")
        try:
            parsed = UUID(identifier)
        except (TypeError, ValueError, AttributeError):
            raise ContentStoreError("invalid storage key") from None
        if identifier != str(parsed):
            raise ContentStoreError("invalid storage key")
        return self._target_for_uuid(parsed)

    def _target_for_uuid(self, identifier: UUID) -> Path:
        self._verify_root()
        target = self._root / str(identifier)
        if target.parent != self._root:
            raise ContentStoreError("storage containment failure")
        return target

    def _create_or_verify_root(self) -> None:
        try:
            self._assert_existing_ancestors_safe(self._root.parent)
            try:
                details = self._root.lstat()
            except FileNotFoundError:
                self._root.mkdir(parents=False)
            else:
                if self._is_reparse_point(self._root) or not stat.S_ISDIR(details.st_mode):
                    raise ContentStoreError("content root is unavailable")
            self._assert_existing_ancestors_safe(self._root)
        except ContentStoreError:
            raise
        except OSError:
            raise ContentStoreError("content root is unavailable") from None

    def _verify_root(self) -> None:
        try:
            self._assert_existing_ancestors_safe(self._root)
            details = self._root.lstat()
            if self._is_reparse_point(self._root) or not stat.S_ISDIR(details.st_mode):
                raise ContentStoreError("content root is unavailable")
            resolved = self._root.resolve(strict=True)
            if resolved != self._root_real or self._identity(details) != self._root_identity:
                raise ContentStoreError("content root changed")
            self._assert_existing_ancestors_safe(self._root)
        except ContentStoreError:
            raise
        except OSError:
            raise ContentStoreError("content root is unavailable") from None

    def _verify_existing_target(
        self, target: Path, expected_identity: _FileIdentity | None
    ) -> None:
        self._verify_root()
        if target.parent != self._root:
            raise ContentStoreError("storage containment failure")
        try:
            details = target.lstat()
            if self._is_reparse_point(target) or self._identity(details) != expected_identity:
                raise ContentStoreError("stored content changed")
            if target.resolve(strict=True) != self._root_real / target.name:
                raise ContentStoreError("storage containment failure")
            self._verify_root()
        except ContentStoreError:
            raise
        except OSError:
            raise ContentStoreError("stored content is unavailable") from None

    def _existing_identity_or_not_found(self, target: Path) -> _FileIdentity:
        self._verify_root()
        try:
            details = target.lstat()
        except FileNotFoundError:
            raise ContentNotFoundError("stored content was not found") from None
        except OSError:
            raise ContentStoreError("stored content is unavailable") from None
        if self._is_reparse_point(target) or not stat.S_ISREG(details.st_mode):
            raise ContentStoreError("stored content is unavailable")
        return self._identity(details)

    def _assert_absent(self, target: Path) -> None:
        try:
            target.lstat()
        except FileNotFoundError:
            return
        except OSError:
            raise ContentStoreError("storage target is unavailable") from None
        raise ContentStoreError("storage target already exists")

    def _cleanup_failed_write(
        self, temporary: Path, target: Path, temporary_identity: _FileIdentity | None
    ) -> bool:
        temporary_cleaned = self._cleanup_partial(temporary)
        if temporary_identity is None:
            return temporary_cleaned
        try:
            details = target.lstat()
        except FileNotFoundError:
            return temporary_cleaned
        except OSError:
            return False
        if self._identity(details) != temporary_identity:
            return temporary_cleaned
        try:
            self._verify_existing_target(target, temporary_identity)
        except ContentStoreError:
            return False
        return temporary_cleaned and self._cleanup_partial(target)

    def _cleanup_partial(self, path: Path) -> bool:
        try:
            self._verify_root()
            try:
                details = path.lstat()
            except FileNotFoundError:
                return True
            if (
                path.parent != self._root
                or self._is_reparse_point(path)
                or not stat.S_ISREG(details.st_mode)
            ):
                return False
            self._verify_root()
            path.unlink()
            self._verify_root()
            return True
        except (ContentStoreError, OSError):
            return False

    @classmethod
    def _assert_existing_ancestors_safe(cls, path: Path) -> None:
        current = Path(path.anchor)
        try:
            if current.anchor:
                current.lstat()
                if cls._is_reparse_point(current):
                    raise ContentStoreError("reparse points are not allowed in content storage")
            for part in path.parts[1:]:
                current /= part
                try:
                    current.lstat()
                except FileNotFoundError:
                    return
                if cls._is_reparse_point(current):
                    raise ContentStoreError("reparse points are not allowed in content storage")
        except ContentStoreError:
            raise
        except OSError:
            raise ContentStoreError("content path is unavailable") from None

    def _checkpoint(self, phase: str) -> None:
        self._security_hook(phase)

    @staticmethod
    def _identity(details: os.stat_result) -> _FileIdentity:
        return details.st_dev, details.st_ino

    @staticmethod
    def _is_reparse_point(path: Path) -> bool:
        try:
            details = path.lstat()
        except OSError:
            return True
        attributes = getattr(details, "st_file_attributes", 0)
        return path.is_symlink() or bool(attributes & _REPARSE_POINT)
