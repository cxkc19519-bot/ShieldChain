from typing import Protocol, runtime_checkable

from saga.domain.users import UserId


@runtime_checkable
class IdentityVerifier(Protocol):
    def verify(self, user_id: UserId) -> bool: ...


__all__ = ("IdentityVerifier",)
