from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim white",
        }[self]

    @property
    def icon(self) -> str:
        return {
            Severity.CRITICAL: "[!]",
            Severity.HIGH: "[H]",
            Severity.MEDIUM: "[M]",
            Severity.LOW: "[L]",
            Severity.INFO: "[i]",
        }[self]


class VulnCategory(str, Enum):
    A01_ACCESS_CONTROL = "A01:2021"
    A02_CRYPTO = "A02:2021"
    A03_INJECTION = "A03:2021"
    A04_INSECURE_DESIGN = "A04:2021"
    A05_MISCONFIG = "A05:2021"
    A06_VULNERABLE_COMPONENTS = "A06:2021"
    A07_AUTH_FAILURES = "A07:2021"
    A08_INTEGRITY = "A08:2021"
    A09_LOGGING = "A09:2021"
    A10_SSRF = "A10:2021"

    @property
    def label(self) -> str:
        return {
            VulnCategory.A01_ACCESS_CONTROL: "Broken Access Control",
            VulnCategory.A02_CRYPTO: "Cryptographic Failures",
            VulnCategory.A03_INJECTION: "Injection",
            VulnCategory.A04_INSECURE_DESIGN: "Insecure Design",
            VulnCategory.A05_MISCONFIG: "Security Misconfiguration",
            VulnCategory.A06_VULNERABLE_COMPONENTS: "Vulnerable and Outdated Components",
            VulnCategory.A07_AUTH_FAILURES: "Identification and Authentication Failures",
            VulnCategory.A08_INTEGRITY: "Software and Data Integrity Failures",
            VulnCategory.A09_LOGGING: "Security Logging and Monitoring Failures",
            VulnCategory.A10_SSRF: "Server-Side Request Forgery",
        }[self]


@dataclass
class Vulnerability:
    checker: str
    category: VulnCategory
    title: str
    description: str
    severity: Severity
    evidence: str
    remediation: str
    request: str | None = None
    response_snippet: str | None = None
    cvss_score: float | None = None
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "checker": self.checker,
            "category": self.category.value,
            "category_label": self.category.label,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "request": self.request,
            "response_snippet": self.response_snippet,
            "cvss_score": self.cvss_score,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    target_url: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    vulns: list[Vulnerability] = field(default_factory=list)
    error_count: int = 0
    ai_analysis: str | None = None

    def add(self, vuln: Vulnerability) -> None:
        self.vulns.append(vuln)
        if vuln.severity == Severity.INFO and "error" in vuln.title.lower():
            self.error_count += 1

    def by_severity(self, severity: Severity) -> list[Vulnerability]:
        return [v for v in self.vulns if v.severity == severity]

    def by_category(self, category: VulnCategory) -> list[Vulnerability]:
        return [v for v in self.vulns if v.category == category]

    @property
    def sorted_vulns(self) -> list[Vulnerability]:
        order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        return sorted(self.vulns, key=lambda v: order.index(v.severity))

    @property
    def critical_count(self) -> int:
        return len(self.by_severity(Severity.CRITICAL))

    @property
    def high_count(self) -> int:
        return len(self.by_severity(Severity.HIGH))

    @property
    def medium_count(self) -> int:
        return len(self.by_severity(Severity.MEDIUM))

    @property
    def low_count(self) -> int:
        return len(self.by_severity(Severity.LOW))

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total": len(self.vulns),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": len(self.by_severity(Severity.INFO)),
                "errors": self.error_count,
            },
            "ai_analysis": self.ai_analysis,
            "vulnerabilities": [v.to_dict() for v in self.sorted_vulns],
        }
