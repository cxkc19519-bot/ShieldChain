from typing import Protocol, runtime_checkable


@runtime_checkable
class ProviderSigner(Protocol):
    def public_key_bytes(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


__all__ = ("ProviderSigner",)
