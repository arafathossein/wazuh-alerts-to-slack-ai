"""Normalised alert and triage result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_level(cls, level: int) -> "Severity":
        """Wazuh rule levels 0–15, banded the way the Wazuh dashboard bands them."""
        if level >= 15:
            return cls.CRITICAL
        if level >= 12:
            return cls.HIGH
        if level >= 7:
            return cls.MEDIUM
        return cls.LOW


class Alert(BaseModel):
    """The fields of a Wazuh alert that triage needs, after redaction."""

    id: str
    timestamp: datetime | None = None
    rule_id: str
    rule_level: int
    rule_description: str
    groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    agent_name: str | None = None
    agent_ip: str | None = None
    src_ip: str | None = None
    src_user: str | None = None
    dst_user: str | None = None
    file_path: str | None = None
    full_log: str | None = None
    location: str | None = None
    firedtimes: int | None = None

    @property
    def severity(self) -> Severity:
        return Severity.from_level(self.rule_level)


class Summary(BaseModel):
    headline: str
    what_happened: str
    why_it_matters: str
    actions: list[str]
    false_positive_hints: list[str] = Field(default_factory=list)


class Triage(BaseModel):
    alert: Alert
    severity: Severity
    summary: Summary
    summarizer: str
    suppressed_since_last: int = 0
    decision: str  # "notify" | "suppress" | "below_threshold"
    redactions: int = 0
