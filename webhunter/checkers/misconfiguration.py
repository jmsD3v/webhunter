from __future__ import annotations

import asyncio
import re

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity, VulnCategory, Vulnerability

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebHunter/1.0)"}

_DEBUG_PATHS_HIGH: frozenset[str] = frozenset({
    "/actuator/env",
    "/actuator/mappings",
    "/_debugbar",
    "/telescope/requests",
})

_DEBUG_PATHS_MEDIUM: frozenset[str] = frozenset({
    "/actuator",
    "/actuator/health",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api-docs",
    "/v2/api-docs",
    "/graphql",
    "/graphiql",
    "/debug",
    "/debug/vars",
    "/__debug__/",
    "/silk/",
    "/rails/info/properties",
    "/rails/info/routes",
})

_ALL_DEBUG_PATHS: list[str] = list(_DEBUG_PATHS_HIGH) + list(_DEBUG_PATHS_MEDIUM)

_STACK_TRACE_PATTERNS: list[str] = [
    "Traceback",
    "at java.",
    "Exception in thread",
    "Caused by:",
    "NullPointerException",
]

_FRAMEWORK_SIGNATURES: list[str] = [
    "Django",
    "Laravel",
    "Rails",
    "Express",
]

_VERSION_RE = re.compile(r"\d")


class MisconfigChecker(BaseChecker):
    name = "misconfiguration"
    category = VulnCategory.A05_MISCONFIG
    description = "Security headers, debug endpoints, default pages, error verbosity"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(
            verify=False,
            timeout=10,
            follow_redirects=True,
            headers=_HEADERS,
        ) as client:
            await asyncio.gather(
                self._check_security_headers(client, target, result),
                self._check_debug_endpoints(client, target, result),
                self._check_error_verbosity(client, target, result),
            )

    async def _check_security_headers(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        try:
            resp = await client.get(target.base_url + "/")
        except httpx.HTTPError:
            return

        headers = resp.headers

        if target.scheme == "https" and "strict-transport-security" not in headers:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Missing Strict-Transport-Security header",
                    description=(
                        "The HTTPS response does not include a Strict-Transport-Security "
                        "header, leaving users vulnerable to protocol downgrade attacks."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="Header 'Strict-Transport-Security' absent from response",
                    request=f"GET {target.base_url}/",
                    remediation=(
                        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                        "to all HTTPS responses."
                    ),
                )
            )

        if "x-frame-options" not in headers:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Missing X-Frame-Options header",
                    description=(
                        "The response lacks an X-Frame-Options header, "
                        "potentially allowing clickjacking attacks."
                    ),
                    severity=Severity.LOW,
                    evidence="Header 'X-Frame-Options' absent from response",
                    request=f"GET {target.base_url}/",
                    remediation="Set 'X-Frame-Options: DENY' or use CSP frame-ancestors directive.",
                )
            )

        if "x-content-type-options" not in headers:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Missing X-Content-Type-Options header",
                    description=(
                        "The response lacks 'X-Content-Type-Options: nosniff', "
                        "allowing browsers to MIME-sniff content types."
                    ),
                    severity=Severity.LOW,
                    evidence="Header 'X-Content-Type-Options' absent from response",
                    request=f"GET {target.base_url}/",
                    remediation="Set 'X-Content-Type-Options: nosniff' on all responses.",
                )
            )

        if "content-security-policy" not in headers:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Missing Content-Security-Policy header",
                    description=(
                        "No Content-Security-Policy header is present, "
                        "reducing protection against XSS and data injection attacks."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="Header 'Content-Security-Policy' absent from response",
                    request=f"GET {target.base_url}/",
                    remediation=(
                        "Define a restrictive Content-Security-Policy "
                        "that whitelists trusted content sources."
                    ),
                )
            )

        if "referrer-policy" not in headers:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Missing Referrer-Policy header",
                    description=(
                        "No Referrer-Policy header found. "
                        "Sensitive URL fragments may leak to third parties via the Referer header."
                    ),
                    severity=Severity.INFO,
                    evidence="Header 'Referrer-Policy' absent from response",
                    request=f"GET {target.base_url}/",
                    remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
                )
            )

        if "permissions-policy" not in headers:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Missing Permissions-Policy header",
                    description=(
                        "No Permissions-Policy header found. "
                        "Browser features (camera, geolocation, etc.) are not explicitly restricted."
                    ),
                    severity=Severity.INFO,
                    evidence="Header 'Permissions-Policy' absent from response",
                    request=f"GET {target.base_url}/",
                    remediation=(
                        "Set a Permissions-Policy header to restrict "
                        "unneeded browser feature access."
                    ),
                )
            )

        powered_by = headers.get("x-powered-by")
        if powered_by:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Server tech disclosed — {powered_by}",
                    description=(
                        f"The 'X-Powered-By: {powered_by}' header discloses the "
                        "backend technology stack to potential attackers."
                    ),
                    severity=Severity.LOW,
                    evidence=f"X-Powered-By: {powered_by}",
                    request=f"GET {target.base_url}/",
                    remediation="Remove the X-Powered-By header from all responses.",
                )
            )

        server = headers.get("server", "")
        if server and _VERSION_RE.search(server):
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Server version disclosed — {server}",
                    description=(
                        f"The 'Server: {server}' header reveals the exact server version, "
                        "aiding version-specific exploit targeting."
                    ),
                    severity=Severity.LOW,
                    evidence=f"Server: {server}",
                    request=f"GET {target.base_url}/",
                    remediation=(
                        "Configure the web server to suppress or genericize "
                        "the Server header."
                    ),
                )
            )

    async def _probe_debug_path(
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

        if path in _DEBUG_PATHS_HIGH:
            severity = Severity.HIGH
            title = f"Debug interface exposed — {path}"
        else:
            severity = Severity.MEDIUM
            title = f"Framework endpoint exposed — {path}"

        result.add(
            Vulnerability(
                checker=self.name,
                category=self.category,
                title=title,
                description=(
                    f"The path {path!r} returned HTTP 200. "
                    "This endpoint may expose sensitive application internals."
                ),
                severity=severity,
                evidence=f"HTTP 200 on {path}, content-length={len(resp.content)}",
                request=f"GET {url}",
                response_snippet=resp.text[:200],
                remediation=(
                    "Disable or restrict debug/framework diagnostic endpoints "
                    "in production. Apply IP allowlisting if the endpoint is needed."
                ),
            )
        )

    async def _check_debug_endpoints(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        await asyncio.gather(
            *[
                self._probe_debug_path(client, target, result, path)
                for path in _ALL_DEBUG_PATHS
            ]
        )

    async def _check_error_verbosity(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        url = target.url("/nonexistent_webhunter_probe_path")
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return

        if resp.status_code != 404:
            return

        body = resp.text

        for pattern in _STACK_TRACE_PATTERNS:
            if pattern in body:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title="Verbose error messages — stack trace in 404",
                        description=(
                            "The 404 error page leaks a stack trace, revealing internal "
                            "file paths, framework details, or exception types."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=f"Pattern {pattern!r} found in 404 response body",
                        request=f"GET {url}",
                        response_snippet=body[:200],
                        remediation=(
                            "Configure custom error pages that do not expose "
                            "internal stack traces or framework internals."
                        ),
                    )
                )
                return

        for sig in _FRAMEWORK_SIGNATURES:
            if sig in body:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title="Framework version disclosed in error page",
                        description=(
                            f"The 404 error page contains the framework name '{sig}', "
                            "disclosing technology stack information."
                        ),
                        severity=Severity.LOW,
                        evidence=f"Framework signature '{sig}' found in 404 response body",
                        request=f"GET {url}",
                        response_snippet=body[:200],
                        remediation=(
                            "Use generic custom error pages that do not reveal "
                            "framework names or version numbers."
                        ),
                    )
                )
                return
