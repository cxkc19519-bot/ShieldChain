"""Human-readable tracking identifiers for simulation projections."""

from __future__ import annotations

from uuid import UUID


def run_tracking_id(run_id: UUID | str) -> str:
    """Return a compact, stable label while UUID remains the internal primary key."""
    token = str(run_id).split("-", maxsplit=1)[0].upper()
    return f"RUN-{token}"
