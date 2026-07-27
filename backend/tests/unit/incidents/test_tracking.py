from uuid import UUID

from shieldchain.incidents.tracking import run_tracking_id


def test_run_tracking_id_is_compact_and_stable() -> None:
    run_id = UUID("12345678-1234-4234-8234-123456789abc")

    assert run_tracking_id(run_id) == "RUN-12345678"
