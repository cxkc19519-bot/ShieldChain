from __future__ import annotations

import asyncio
from uuid import UUID

from shieldchain.main import _periodic_safety_recovery


class RecordingSafetyRecovery:
    def __init__(self) -> None:
        self.calls = 0

    def recover_safety_loops(self, **_values) -> int:
        self.calls += 1
        return 0


def test_periodic_safety_recovery_repeats_until_shutdown() -> None:
    async def exercise() -> int:
        service = RecordingSafetyRecovery()
        stop = asyncio.Event()
        task = asyncio.create_task(
            _periodic_safety_recovery(
                service,
                tenant_id=UUID(int=1),
                stop=stop,
                interval_seconds=0.01,
            )
        )
        async with asyncio.timeout(1):
            while service.calls < 2:
                await asyncio.sleep(0.005)
        stop.set()
        await task
        return service.calls

    assert asyncio.run(exercise()) >= 2
