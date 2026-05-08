from __future__ import annotations

import asyncio
import re
import secrets

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity, VulnCategory, Vulnerability

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebHunter/1.0)"}

_SQLI_PAYLOADS: list[tuple[str, str]] = [
    ("id", "1'"),
    ("id", '1"'),
    ("search", "test'--"),
    ("q", "1 OR 1=1--"),
]

_SQL_ERRORS: list[str] = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "supplied argument is not a valid mysql",
    "ora-01756",
    "sqlstate",
    "syntax error",
    "[microsoft][odbc",
    "invalid query",
    "sql server",
]


class InjectionChecker(BaseChecker):
    name = "injection"
    category = VulnCategory.A03_INJECTION
    description = "SQL injection error detection, XSS reflection probe"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(
            verify=False,
            timeout=10,
            follow_redirects=True,
            headers=_HEADERS,
        ) as client:
            await asyncio.gather(
                self._check_sqli(client, target, result),
                self._check_xss(client, target, result),
            )

    async def _check_sqli(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        all_failed = True
        for param, payload in _SQLI_PAYLOADS:
            url = f"{target.base_url}?{param}={payload}"
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                continue

            all_failed = False
            body_lower = resp.text.lower()

            for error_sig in _SQL_ERRORS:
                idx = body_lower.find(error_sig)
                if idx == -1:
                    continue

                start = max(0, idx - 50)
                end = min(len(resp.text), idx + 50)
                evidence = resp.text[start:end].strip()

                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"SQL injection error — {param}",
                        description=(
                            f"The parameter '{param}' with payload {payload!r} "
                            "triggered a SQL error message in the response."
                        ),
                        severity=Severity.HIGH,
                        evidence=evidence[:100],
                        request=url,
                        response_snippet=resp.text[:200],
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never interpolate user input into SQL."
                        ),
                        cvss_score=8.6,
                    )
                )
                return

        if all_failed:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Checker error: injection (SQLi probes)",
                    description="All SQLi probe requests failed with HTTP errors.",
                    severity=Severity.INFO,
                    evidence="All httpx requests raised HTTPError",
                    remediation="Internal checker error — review checker implementation.",
                )
            )

    async def _check_xss(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        tag = secrets.token_hex(4)
        probe = f"<wh-xss-probe-{tag}>"
        url = f"{target.base_url}?q={probe}&search={probe}"

        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Checker error: injection (XSS probe)",
                    description="XSS probe request failed with an HTTP error.",
                    severity=Severity.INFO,
                    evidence="httpx raised HTTPError on XSS probe",
                    remediation="Internal checker error — review checker implementation.",
                )
            )
            return

        content_type = resp.headers.get("content-type", "")
        if probe in resp.text and "text/html" in content_type:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Reflected XSS candidate — probe echoed in HTML response",
                    description=(
                        f"The XSS probe {probe!r} was reflected verbatim in the HTML "
                        "response. This indicates unsanitized output that may be exploitable."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=probe,
                    request=url,
                    response_snippet=resp.text[:200],
                    remediation=(
                        "Encode all user-controlled output. "
                        "Implement Content-Security-Policy."
                    ),
                    cvss_score=6.1,
                )
            )
