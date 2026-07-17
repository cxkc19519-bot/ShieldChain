from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class RandomSource(Protocol):
    def bytes(self, length: int) -> bytes: ...


__all__ = ("RandomSource",)
