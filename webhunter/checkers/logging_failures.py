from __future__ import annotations

import asyncio

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity, VulnCategory, Vulnerability

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebHunter/1.0)"}

_LOG_PATHS = (
    "/logs/",
    "/log/",
    "/logs/app.log",
    "/logs/error.log",
    "/logs/access.log",
    "/application.log",
    "/error.log",
    "/debug.log",
    "/laravel.log",
    "/storage/logs/laravel.log",
    "/var/log/apache2/access.log",
    "/wp-content/debug.log",
)

_LOG_CONTENT_PATTERNS = (
    "[ERROR]",
    "[WARNING]",
    "[WARN]",
    "Stack trace",
    "stack trace",
    "Traceback",
    "Exception",
    "SQLSTATE",
)

_TIMESTAMP_PATTERNS = (
    "2024-",
    "2025-",
    "2023-",
    "[2024",
    "[2025",
    "[2023",
)

_MONITORING_PATHS_HIGH = (
    "/metrics",
    "/prometheus",
    "/grafana",
    "/kibana",
    "/elastic",
    "/elasticsearch",
)

_MONITORING_PATHS_MEDIUM = (
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/status",
    "/ping",
)

_PROMETHEUS_PATTERNS = ("# HELP", "# TYPE")

_HEALTH_JSON_PATTERNS = ("version", "uptime", "database", "redis", "hostname", "environment")

_INTERNAL_PATH_PATTERNS = ("/var/", "/home/", "/usr/", "/etc/", "C:\\", "C:/", "D:\\")


class LoggingFailuresChecker(BaseChecker):
    name = "logging_failures"
    category = VulnCategory.A09_LOGGING
    description = "Exposed log files, debug endpoints, monitoring interfaces"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(
            verify=False,
            timeout=10,
            follow_redirects=True,
            headers=_HEADERS,
        ) as client:
            await asyncio.gather(
                self._check_log_files(client, target, result),
                self._check_monitoring(client, target, result),
                self._check_error_paths(client, target, result),
            )

    def _looks_like_log(self, body: str) -> bool:
        has_log_pattern = any(p in body for p in _LOG_CONTENT_PATTERNS)
        has_timestamp = any(p in body for p in _TIMESTAMP_PATTERNS)
        return has_log_pattern or has_timestamp

    async def _probe_log_path(
        self,
        client: httpx.AsyncClient,
        target: TargetURL,
        result: ScanResult,
        path: str,
    ) -> None:
        url = target.url(path)
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return

        if resp.status_code != 200:
            return

        body = resp.text[:4000]
        is_log = self._looks_like_log(body)

        if is_log:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Log file exposed — {path}",
                    description=(
                        f"The path {path!r} returned HTTP 200 with content that "
                        "matches log file patterns. Exposed logs may reveal internal "
                        "paths, credentials, stack traces, or sensitive application data."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"HTTP 200 on {path}, log-like content detected",
                    request=f"GET {url}",
                    response_snippet=body[:200],
                    remediation=(
                        "Move log files outside the web root. "
                        "Restrict access via web server configuration. "
                        "Never store sensitive data in log files."
                    ),
                )
            )
        else:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Potential log file exposed — {path}",
                    description=(
                        f"The path {path!r} returned HTTP 200 but content did not "
                        "clearly match log patterns. Manual review recommended."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"HTTP 200 on {path}, content-length={len(resp.content)}",
                    request=f"GET {url}",
                    response_snippet=body[:200],
                    remediation=(
                        "Verify whether this path exposes sensitive information "
                        "and restrict access if so."
                    ),
                )
            )

    async def _check_log_files(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        await asyncio.gather(
            *[self._probe_log_path(client, target, result, p) for p in _LOG_PATHS]
        )

    async def _probe_monitoring_path(
        self,
        client: httpx.AsyncClient,
        target: TargetURL,
        result: ScanResult,
        path: str,
        is_high_tier: bool,
    ) -> None:
        url = target.url(path)
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return

        if resp.status_code != 200:
            return

        body = resp.text[:4000]

        if is_high_tier:
            if any(p in body for p in _PROMETHEUS_PATTERNS):
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Prometheus metrics exposed — {path}",
                        description=(
                            f"The path {path!r} exposes Prometheus metrics with "
                            "'# HELP' / '# TYPE' lines. This leaks internal service "
                            "topology, resource usage, and application internals."
                        ),
                        severity=Severity.HIGH,
                        evidence=f"HTTP 200 on {path} with Prometheus metric lines",
                        request=f"GET {url}",
                        response_snippet=body[:200],
                        remediation=(
                            "Restrict metrics endpoints to internal networks or "
                            "authenticated scrapers only. Never expose /metrics publicly."
                        ),
                    )
                )
            else:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Monitoring interface exposed — {path}",
                        description=(
                            f"The monitoring path {path!r} returned HTTP 200. "
                            "This may expose internal observability data."
                        ),
                        severity=Severity.HIGH,
                        evidence=f"HTTP 200 on {path}, content-length={len(resp.content)}",
                        request=f"GET {url}",
                        response_snippet=body[:200],
                        remediation=(
                            "Restrict access to monitoring interfaces. "
                            "Apply authentication and IP allowlisting."
                        ),
                    )
                )
        else:
            internal_info = any(p in body for p in _HEALTH_JSON_PATTERNS)
            if internal_info:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Health endpoint exposes internal info — {path}",
                        description=(
                            f"The health endpoint {path!r} returned JSON containing "
                            "internal application details such as version, hostname, "
                            "or dependency status."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=f"HTTP 200 on {path} with internal data fields",
                        request=f"GET {url}",
                        response_snippet=body[:200],
                        remediation=(
                            "Return minimal health responses in production (e.g. "
                            "{\"status\": \"ok\"}). Move detailed health data behind auth."
                        ),
                    )
                )

    async def _check_monitoring(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        tasks = [
            self._probe_monitoring_path(client, target, result, p, True)
            for p in _MONITORING_PATHS_HIGH
        ] + [
            self._probe_monitoring_path(client, target, result, p, False)
            for p in _MONITORING_PATHS_MEDIUM
        ]
        await asyncio.gather(*tasks)

    async def _check_error_paths(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        url = target.base_url
        probe_headers = {
            **_HEADERS,
            "Content-Type": "application/x-webhunter-probe",
        }
        try:
            resp = await client.post(
                url,
                content=b'{"__probe__": null}',
                headers=probe_headers,
            )
        except httpx.HTTPError:
            return

        body = resp.text[:3000]
        found_paths = [p for p in _INTERNAL_PATH_PATTERNS if p in body]
        if found_paths:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Internal paths in error response",
                    description=(
                        "A malformed POST request triggered an error response that "
                        "contains internal filesystem paths, revealing server layout."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Paths found in response: {', '.join(found_paths)}",
                    request=f"POST {url} (Content-Type: application/x-webhunter-probe)",
                    response_snippet=body[:200],
                    remediation=(
                        "Configure generic error pages that do not expose "
                        "filesystem paths or internal stack traces."
                    ),
                )
            )
