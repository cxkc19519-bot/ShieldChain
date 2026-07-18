from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from shieldchain.incidents.domain import Evidence


def _normalized_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("observed_at must be an aware UTC datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def canonical_evidence_digest(
    *,
    evidence_type: str,
    source: str,
    observed_at: datetime,
    summary: str,
    raw_reference: str,
    confidence: float,
    confirmed: bool,
    payload: Mapping[str, Any],
) -> str:
    canonical = json.dumps(
        {
            "evidence_type": evidence_type,
            "source": source,
            "observed_at": _normalized_utc(observed_at),
            "summary": summary,
            "raw_reference": raw_reference,
            "confidence": confidence,
            "confirmed": confirmed,
            "payload": dict(payload),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evidence_id_from_digest(digest: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"shieldchain-evidence:{digest}")


def create_evidence(
    *,
    evidence_type: str,
    source: str,
    observed_at: datetime,
    summary: str,
    raw_reference: str,
    confidence: float,
    confirmed: bool,
    payload: Mapping[str, Any],
) -> Evidence:
    digest = canonical_evidence_digest(
        evidence_type=evidence_type,
        source=source,
        observed_at=observed_at,
        summary=summary,
        raw_reference=raw_reference,
        confidence=confidence,
        confirmed=confirmed,
        payload=payload,
    )
    return Evidence(
        id=evidence_id_from_digest(digest),
        evidence_type=evidence_type,
        source=source,
        observed_at=observed_at.astimezone(UTC),
        summary=summary,
        raw_reference=raw_reference,
        integrity_sha256=digest,
        confidence=confidence,
        confirmed=confirmed,
        payload=payload,
    )


def verify_evidence_integrity(evidence: Evidence) -> bool:
    expected_digest = canonical_evidence_digest(
        evidence_type=evidence.evidence_type,
        source=evidence.source,
        observed_at=evidence.observed_at,
        summary=evidence.summary,
        raw_reference=evidence.raw_reference,
        confidence=evidence.confidence,
        confirmed=evidence.confirmed,
        payload=evidence.payload,
    )
    digest_matches = hmac.compare_digest(evidence.integrity_sha256, expected_digest)
    id_matches = hmac.compare_digest(
        str(evidence.id), str(evidence_id_from_digest(expected_digest))
    )
    return digest_matches and id_matches
