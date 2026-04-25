"""Pydantic v2 data models for ossvet."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(s: Severity) -> int:
    return _SEVERITY_RANK[s]


class Verdict(str, Enum):
    LOW_RISK = "LOW RISK"
    REVIEW = "REVIEW REQUIRED"
    BLOCK = "BLOCK / DO NOT RUN LOCALLY"


class Finding(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    scanner: str
    category: str
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    rule_id: str | None = None
    score_contribution: int = 0


class ScannerResult(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    scanner_name: str
    status: Literal["ok", "skipped", "error"]
    tool_available: bool
    error_message: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    raw_output_path: str | None = None
    duration_seconds: float = 0.0


class ScanResult(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    repo_url: HttpUrl
    commit_sha: str
    timestamp: datetime
    duration_seconds: float
    scanner_results: list[ScannerResult]
    all_findings: list[Finding]
    risk_score: int = Field(ge=0, le=100)
    verdict: Verdict
    summary: list[str]
