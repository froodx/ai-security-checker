"""Canonical finding and coverage records."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


SEVERITIES = {"critical", "high", "medium", "low", "informational", "unknown"}
STATUSES = {"confirmed", "suspected", "unverified", "mitigated"}
COVERAGE_STATUSES = {
    "passed",
    "finding",
    "not_checked",
    "unknown",
    "error",
    "cancelled",
    "not_applicable",
}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def normalise_severity(value: str | None) -> str:
    severity = (value or "unknown").strip().lower()
    aliases = {"info": "informational", "undefined": "unknown", "warning": "medium"}
    severity = aliases.get(severity, severity)
    return severity if severity in SEVERITIES else "unknown"


def stable_finding_id(fingerprint: str) -> str:
    digest = hashlib.sha256(fingerprint.encode("utf-8", errors="replace")).hexdigest()
    return f"SEC-{digest[:8].upper()}"


@dataclass
class Finding:
    layer: int
    severity: str
    status: str
    asset: str
    title: str
    description: str
    evidence: list[str]
    source: str
    confidence: str
    recommendation: str
    verification: str
    risk_if_accepted: str
    fingerprint: str
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)
    upstream_severity: str | None = None
    wrapper_reclassification: str | None = None
    id: str = ""

    def __post_init__(self) -> None:
        if self.layer not in range(1, 6):
            raise ValueError("A finding layer must be between 1 and 5.")
        self.severity = normalise_severity(self.severity)
        if self.status not in STATUSES:
            raise ValueError(f"Unsupported finding status: {self.status}")
        if self.confidence not in {"high", "medium", "low"}:
            raise ValueError(f"Unsupported confidence: {self.confidence}")
        if not self.id:
            self.id = stable_finding_id(self.fingerprint)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("fingerprint", None)
        if data.get("upstream_severity") is None:
            data.pop("upstream_severity", None)
        if data.get("wrapper_reclassification") is None:
            data.pop("wrapper_reclassification", None)
        return data


@dataclass
class Coverage:
    layer: int
    name: str
    status: str
    reason: str
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.layer not in range(1, 6):
            raise ValueError("A coverage layer must be between 1 and 5.")
        if self.status not in COVERAGE_STATUSES:
            raise ValueError(f"Unsupported coverage status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge duplicate IDs while retaining evidence from every source."""

    merged: dict[str, Finding] = {}
    severity_rank = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
        "unknown": 0,
    }
    for finding in findings:
        previous = merged.get(finding.id)
        if previous is None:
            merged[finding.id] = finding
            continue
        previous.evidence = list(dict.fromkeys(previous.evidence + finding.evidence))
        if severity_rank[finding.severity] > severity_rank[previous.severity]:
            previous.severity = finding.severity
        previous.last_seen = max(previous.last_seen, finding.last_seen)
        previous.first_seen = min(previous.first_seen, finding.first_seen)
    return sorted(
        merged.values(),
        key=lambda item: (-severity_rank[item.severity], item.layer, item.id),
    )
