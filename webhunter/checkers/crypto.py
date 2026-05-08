from __future__ import annotations

import re

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity, VulnCategory, Vulnerability

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebHunter/1.0)"}

_CC_PATTERN = re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")
_APIKEY_PATTERN = re.compile(
    r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*['\"]?[\w\-]{20,}"
)


class CryptoChecker(BaseChecker):
    name = "crypto"
    category = VulnCategory.A02_CRYPTO
    description = "TLS/SSL config, HTTP->HTTPS redirect, insecure cookies"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(
            verify=False,
            timeout=10,
            follow_redirects=True,
            headers=_HEADERS,
        ) as client:
            resp = await self._fetch_base(client, target, result)
            if resp is not None:
                if target.scheme == "http":
                    await self._check_https_redirect(client, target, result, resp)
                self._check_cookie_flags(target, result, resp)
                self._check_sensitive_data(target, result, resp)

    async def _fetch_base(
        self,
        client: httpx.AsyncClient,
        target: TargetURL,
        result: ScanResult,
    ) -> httpx.Response | None:
        try:
            return await client.get(target.base_url + "/")
        except httpx.HTTPError as exc:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Checker error: {self.name}",
                    description=f"Failed to connect to target: {exc}",
                    severity=Severity.INFO,
                    evidence=str(exc),
                    remediation="Internal checker error — review checker implementation.",
                )
            )
            return None

    async def _check_https_redirect(
        self,
        client: httpx.AsyncClient,
        target: TargetURL,
        result: ScanResult,
        resp: httpx.Response,
    ) -> None:
        final_url = str(resp.url)
        if not final_url.startswith("https://"):
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="HTTP served without HTTPS redirect",
                    description=(
                        "The server does not redirect HTTP traffic to HTTPS. "
                        "Data transmitted over HTTP is unencrypted."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Final URL after redirects: {final_url}",
                    request=f"GET {target.base_url}/",
                    response_snippet=None,
                    remediation=(
                        "Configure the server to redirect all HTTP requests to HTTPS "
                        "using a 301 permanent redirect."
                    ),
                )
            )

        https_url = "https://" + target.host + (
            f":{target.port}" if target.port and target.port not in (80, 443) else ""
        ) + "/"
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=10,
                follow_redirects=False,
                headers=_HEADERS,
            ) as tls_client:
                await tls_client.get(https_url)
        except (httpx.ConnectError, httpx.ConnectTimeout, TimeoutError):
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"HTTPS not available on {target.host}",
                    description=(
                        f"HTTP is served on {target.host} but the HTTPS endpoint is "
                        "unreachable (connection refused or timed out)."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Connection to {https_url} failed",
                    request=f"GET {https_url}",
                    response_snippet=None,
                    remediation=(
                        "Obtain a TLS certificate and configure the server to serve "
                        "HTTPS on port 443."
                    ),
                )
            )
        except httpx.HTTPError:
            pass

    def _check_cookie_flags(
        self, target: TargetURL, result: ScanResult, resp: httpx.Response
    ) -> None:
        set_cookie_headers = resp.headers.get_list("set-cookie")
        for raw_cookie in set_cookie_headers:
            name = raw_cookie.split("=")[0].strip()
            parts_lower = raw_cookie.lower()

            if "secure" not in parts_lower:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Cookie missing Secure flag — {name}",
                        description=(
                            f"Cookie '{name}' is set without the Secure flag, "
                            "allowing transmission over plain HTTP."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=raw_cookie[:200],
                        request=f"GET {target.base_url}/",
                        response_snippet=None,
                        remediation=(
                            "Add the Secure attribute to all cookies to prevent "
                            "transmission over unencrypted connections."
                        ),
                    )
                )

            if "httponly" not in parts_lower:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Cookie missing HttpOnly flag — {name}",
                        description=(
                            f"Cookie '{name}' is set without the HttpOnly flag, "
                            "making it accessible via JavaScript."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=raw_cookie[:200],
                        request=f"GET {target.base_url}/",
                        response_snippet=None,
                        remediation=(
                            "Add the HttpOnly attribute to prevent JavaScript access "
                            "and reduce XSS impact."
                        ),
                    )
                )

            if "samesite" not in parts_lower:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Cookie missing SameSite — {name}",
                        description=(
                            f"Cookie '{name}' has no SameSite attribute, "
                            "potentially exposing it to CSRF attacks."
                        ),
                        severity=Severity.LOW,
                        evidence=raw_cookie[:200],
                        request=f"GET {target.base_url}/",
                        response_snippet=None,
                        remediation=(
                            "Set SameSite=Strict or SameSite=Lax to mitigate "
                            "cross-site request forgery."
                        ),
                    )
                )

    def _check_sensitive_data(
        self, target: TargetURL, result: ScanResult, resp: httpx.Response
    ) -> None:
        body = resp.text[:5000]

        cc_match = _CC_PATTERN.search(body)
        if cc_match:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Possible credit card number in response",
                    description=(
                        "A pattern matching a credit card number was found in the "
                        "response body."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=cc_match.group(0)[:50],
                    request=f"GET {target.base_url}/",
                    response_snippet=body[:300],
                    remediation=(
                        "Remove sensitive financial data from HTTP responses. "
                        "Ensure PCI-DSS compliance."
                    ),
                )
            )

        key_match = _APIKEY_PATTERN.search(body)
        if key_match:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="Possible API key / secret in response",
                    description=(
                        "A pattern matching an API key or secret token was found in "
                        "the response body."
                    ),
                    severity=Severity.HIGH,
                    evidence=key_match.group(0)[:50],
                    request=f"GET {target.base_url}/",
                    response_snippet=body[:300],
                    remediation=(
                        "Remove secrets from HTTP responses. Rotate any exposed "
                        "credentials immediately."
                    ),
                )
            )
