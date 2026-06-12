"""Data models for the IDOR scanner (stdlib dataclasses, no heavy deps)."""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class IdentifierKind(str, enum.Enum):
    NUMERIC = "numeric"
    UUID = "uuid"
    HASH = "hash"
    SEQUENTIAL = "sequential"
    OPAQUE = "opaque"
    UNKNOWN = "unknown"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    BLOCKED = "blocked"


class ScanMode(str, enum.Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


@dataclass
class ScanBudget:
    """Crawl/test limits per scan mode."""

    max_pages: int
    max_depth: int
    max_objects: int
    max_enum: int
    rps: float
    per_context_crawl: bool
    use_ai: bool

    @classmethod
    def for_mode(cls, mode: "ScanMode") -> "ScanBudget":
        if mode == ScanMode.QUICK:
            return cls(25, 2, 15, 8, 4.0, False, False)
        if mode == ScanMode.DEEP:
            return cls(200, 5, 80, 25, 4.0, True, True)
        return cls(80, 3, 40, 15, 4.0, True, False)  # STANDARD


@dataclass
class RequestRecord:
    """A request observed by the browser (page load, XHR, fetch, etc.)."""

    method: str
    url: str
    resource_type: str = ""          # document | xhr | fetch | script | ...
    post_data: str = ""
    is_api: bool = False


@dataclass
class ApiEndpoint:
    method: str
    url_template: str
    source: str = ""                 # network | swagger | js | sitemap


@dataclass
class Candidate:
    """A ranked IDOR candidate produced by the analysis layer."""

    endpoint: str
    parameter: str
    object_id: str
    kind: str                        # IdentifierKind value
    sensitive_param: bool
    probability: float               # 0..1 heuristic/AI likelihood
    rationale: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "Probability": round(self.probability, 2),
            "Endpoint": self.endpoint,
            "Parameter": self.parameter,
            "Object ID": self.object_id,
            "ID Type": self.kind,
            "Auth-sensitive": "yes" if self.sensitive_param else "no",
        }


class AccessExpectation(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "review"


class AccessOutcome(str, enum.Enum):
    GRANTED = "granted"
    DENIED = "denied"
    NOT_FOUND = "not_found"
    ERROR = "error"


@dataclass
class ObjectReference:
    raw_value: str
    kind: IdentifierKind
    location: str
    source_url: str


@dataclass
class Evidence:
    principal: str
    role: str
    request_method: str
    request_url: str
    status_code: int = 0
    response_length: int = 0
    similarity_to_owner: float = 0.0
    body_snippet: str = ""
    elapsed_ms: float = 0.0
    captured_at: float = field(default_factory=time.time)


@dataclass
class Finding:
    endpoint: str
    parameter: str
    object_id: str
    role_tested: str
    test_case: str
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.LOW
    description: str = ""
    recommendation: str = ""
    owasp: str = "A01:2021 Broken Access Control"
    cwe: str = "CWE-639"
    evidence: list[Evidence] = field(default_factory=list)
    finding_id: str = field(default_factory=lambda: f"IDOR-{uuid.uuid4().hex[:8]}")

    def to_row(self) -> dict[str, Any]:
        return {
            "ID": self.finding_id,
            "Severity": self.severity.value,
            "Confidence": self.confidence.value,
            "Endpoint": self.endpoint,
            "Parameter": self.parameter,
            "Object ID": self.object_id,
            "Role Tested": self.role_tested,
            "Test Case": self.test_case,
        }


@dataclass
class MatrixCell:
    principal: str
    role: str
    object_label: str
    object_id: str
    expected: AccessExpectation
    actual: AccessOutcome
    status_code: int = 0

    @property
    def result(self) -> str:
        if self.actual == AccessOutcome.ERROR:
            return "inconclusive"
        granted = self.actual == AccessOutcome.GRANTED
        if self.expected == AccessExpectation.ALLOW:
            return "pass" if granted else "blocked"
        if self.expected == AccessExpectation.DENY:
            return "potential-idor" if granted else "pass"
        return "review-granted" if granted else "review-denied"


@dataclass
class ScanResult:
    target: str
    status: ScanStatus = ScanStatus.QUEUED
    scan_mode: str = "standard"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    progress: int = 0
    message: str = ""
    endpoints: int = 0
    parameters: int = 0
    objects: int = 0
    api_endpoints: int = 0
    requests_observed: int = 0
    contexts_tested: list[str] = field(default_factory=list)
    candidates: list["Candidate"] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    matrix: list[MatrixCell] = field(default_factory=list)
    log: list[str] = field(default_factory=list)

    @property
    def risk_rating(self) -> str:
        if not self.findings:
            return "info"
        top = max(self.findings, key=lambda f: SEVERITY_RANK[f.severity])
        return top.severity.value

    def severity_counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk_rating"] = self.risk_rating
        d["severity_counts"] = self.severity_counts()
        d["status"] = self.status.value
        return d
