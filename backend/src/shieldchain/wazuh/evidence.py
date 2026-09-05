from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from shieldchain.incidents.persistence import EvidenceRecordRow
from shieldchain.wazuh.persistence import WazuhCaseEvidenceRow

EvidenceRow = EvidenceRecordRow | WazuhCaseEvidenceRow


def confirmed_evidence(
    session: Session, *, run_id: UUID | str, evidence_id: UUID | str
) -> EvidenceRow | None:
    """Resolve confirmed evidence across legacy investigations and live Wazuh runs."""

    legacy = session.scalar(
        select(EvidenceRecordRow).where(
            EvidenceRecordRow.id == str(evidence_id),
            EvidenceRecordRow.run_id == str(run_id),
            EvidenceRecordRow.confirmed.is_(True),
        )
    )
    if legacy is not None:
        return legacy
    return session.scalar(
        select(WazuhCaseEvidenceRow).where(
            WazuhCaseEvidenceRow.id == str(evidence_id),
            WazuhCaseEvidenceRow.run_id == str(run_id),
            WazuhCaseEvidenceRow.confirmed.is_(True),
        )
    )

