from __future__ import annotations

import asyncio

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity, VulnCategory, Vulnerability

_SENSITIVE_PATHS: list[str] = [
    "/admin",
    "/admin/",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/manager",
    "/console",
    "/dashboard",
    "/panel",
    "/backend",
    "/cms",
    "/.git/HEAD",
    "/.env",
    "/.htaccess",
    "/config.php",
    "/web.config",
    "/backup",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/api/v1/users",
    "/api/users",
    "/api/admin",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
]

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebHunter/1.0)"}
_BATCH_SIZE = 10


class AccessControlChecker(BaseChecker):
    name = "access_control"
    category = VulnCategory.A01_ACCESS_CONTROL
    description = "Directory traversal, admin path exposure, sensitive file access"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(
            verify=False,
            timeout=10,
            follow_redirects=True,
            headers=_HEADERS,
        ) as client:
            await asyncio.gather(
                self._probe_paths(client, target, result),
                self._check_http_methods(client, target, result),
            )

    async def _probe_paths(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        batches = [
            _SENSITIVE_PATHS[i : i + _BATCH_SIZE]
            for i in range(0, len(_SENSITIVE_PATHS), _BATCH_SIZE)
        ]
        for batch in batches:
            await asyncio.gather(
                *[self._probe_single(client, target, result, path) for path in batch]
            )

    async def _probe_single(
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

        if resp.status_code == 200:
            body = resp.text
            directory_listing = "<title>Index of" in body or "Directory listing" in body

            if directory_listing:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Directory listing enabled — {path}",
                        description=(
                            f"The server returns a browsable directory listing at {path}."
                        ),
                        severity=Severity.HIGH,
                        evidence=f"HTTP 200, body contains directory listing marker",
                        request=f"GET {url}",
                        response_snippet=body[:300],
                        remediation="Disable directory listing in web server configuration.",
                    )
                )
            else:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Exposed path — {path}",
                        description=(
                            f"Sensitive path {path} returned HTTP 200 without authentication."
                        ),
                        severity=Severity.HIGH,
                        evidence=f"HTTP 200, content-length={len(resp.content)}",
                        request=f"GET {url}",
                        response_snippet=body[:300],
                        remediation=(
                            "Restrict access with authentication. "
                            "Review web server configuration."
                        ),
                    )
                )

        elif resp.status_code in (401, 403):
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Auth-protected path exists — {path}",
                    description=(
                        f"Path {path} exists and is protected (HTTP {resp.status_code}). "
                        "Authentication bypass may be possible."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"HTTP {resp.status_code}",
                    request=f"GET {url}",
                    remediation=(
                        "Investigate if authentication bypass is possible."
                    ),
                )
            )

    async def _check_http_methods(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        url = target.base_url + "/"
        try:
            resp = await client.options(url)
        except httpx.HTTPError:
            return

        allow_header = resp.headers.get("Allow", "")
        if not allow_header:
            return

        allowed_methods = [m.strip().upper() for m in allow_header.split(",")]

        dangerous = [m for m in allowed_methods if m in ("TRACE", "DELETE")]
        if dangerous:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Dangerous HTTP methods allowed — {', '.join(dangerous)}",
                    description=(
                        f"The server advertises dangerous HTTP methods via OPTIONS: "
                        f"{', '.join(dangerous)}."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Allow: {allow_header}",
                    request=f"OPTIONS {url}",
                    response_snippet=None,
                    remediation=(
                        "Disable TRACE (XST attack vector) and unnecessary HTTP methods."
                    ),
                )
            )
