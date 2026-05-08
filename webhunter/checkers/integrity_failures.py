"""A08:2021 - Software and Data Integrity Failures: unsigned redirects, SRI missing, JWT alg:none."""
from __future__ import annotations

import base64
import json
import re

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import Severity, VulnCategory, Vulnerability, ScanResult

_CDN_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']https?://[^"\']+["\']', re.IGNORECASE)
_CDN_LINK_RE = re.compile(r'<link[^>]+href=["\']https?://[^"\']+["\']', re.IGNORECASE)
_SRI_RE = re.compile(r'integrity=["\'][^"\']+["\']', re.IGNORECASE)
_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
_SERIALIZED_RE = re.compile(r'O:\d+:"[A-Za-z]|rO0AB|ACED0005', re.IGNORECASE)


def _decode_jwt_header(token: str) -> dict | None:
    try:
        header_b64 = token.split(".")[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


class IntegrityFailuresChecker(BaseChecker):
    name = "integrity_failures"
    category = VulnCategory.A08_INTEGRITY
    description = "Missing SRI on CDN resources, JWT alg:none, insecure deserialization patterns"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                resp = await client.get(target.base_url)
                html = resp.text

                await self._check_sri(html, result)
                await self._check_jwt_in_response(resp, html, result)
                await self._check_deserialization(html, result)
                await self._check_update_endpoints(client, target, result)
        except httpx.HTTPError as exc:
            result.add(Vulnerability(
                checker=self.name, category=self.category,
                title="Checker error: integrity_failures",
                description=str(exc), severity=Severity.INFO,
                evidence="HTTP request failed", remediation="",
            ))

    async def _check_sri(self, html: str, result: ScanResult) -> None:
        external_scripts = _CDN_SCRIPT_RE.findall(html)
        external_links = _CDN_LINK_RE.findall(html)
        missing = []
        for tag in external_scripts + external_links:
            if not _SRI_RE.search(tag):
                # extract src/href URL
                m = re.search(r'(?:src|href)=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                if m:
                    missing.append(m.group(1))

        if missing:
            result.add(Vulnerability(
                checker=self.name,
                category=self.category,
                title=f"Missing Subresource Integrity (SRI) on {len(missing)} external resource(s)",
                description="External scripts/stylesheets loaded without integrity hashes. A compromised CDN can inject malicious code.",
                severity=Severity.MEDIUM,
                evidence="\n".join(missing[:5]),
                remediation="Add integrity='sha384-...' and crossorigin='anonymous' to all external <script> and <link> tags.",
            ))

    async def _check_jwt_in_response(self, resp: httpx.Response, html: str, result: ScanResult) -> None:
        # Check cookies for JWT
        for cookie_name, cookie_val in resp.cookies.items():
            if _JWT_RE.match(cookie_val):
                header = _decode_jwt_header(cookie_val)
                if header and header.get("alg", "").lower() in ("none", ""):
                    result.add(Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title="JWT with alg:none in Cookie",
                        description=f"Cookie '{cookie_name}' contains a JWT using alg:none. Signature verification is bypassed — any payload is accepted.",
                        severity=Severity.CRITICAL,
                        evidence=f"Cookie: {cookie_name}, JWT header: {json.dumps(header)}",
                        remediation="Reject JWTs with alg:none. Enforce a specific algorithm (RS256/ES256) server-side.",
                    ))
                elif header and header.get("alg", "").upper() in ("HS256", "HS384", "HS512"):
                    result.add(Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"JWT using symmetric HMAC ({header['alg']}) in Cookie",
                        description="HMAC-signed JWTs can be brute-forced if the secret is weak. Prefer asymmetric algorithms.",
                        severity=Severity.LOW,
                        evidence=f"Cookie: {cookie_name}, alg: {header.get('alg')}",
                        remediation="Use RS256 or ES256. Ensure HMAC secrets are cryptographically random and at least 256 bits.",
                    ))

        # Check page HTML for exposed JWTs
        tokens = _JWT_RE.findall(html)
        for token in tokens[:3]:
            header = _decode_jwt_header(token)
            if header and header.get("alg", "").lower() in ("none", ""):
                result.add(Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="JWT with alg:none exposed in HTML",
                    description="JWT with no signature algorithm found in page source. Signature verification is bypassed.",
                    severity=Severity.CRITICAL,
                    evidence=f"JWT header: {json.dumps(header)}, token prefix: {token[:40]}...",
                    remediation="Never expose JWTs in HTML. Enforce algorithm validation server-side.",
                ))

    async def _check_deserialization(self, html: str, result: ScanResult) -> None:
        m = _SERIALIZED_RE.search(html)
        if m:
            result.add(Vulnerability(
                checker=self.name,
                category=self.category,
                title="Possible Serialized Object in Page Source",
                description="Pattern matching PHP/Java serialized objects found in HTML. May indicate unsafe deserialization.",
                severity=Severity.MEDIUM,
                evidence=f"Pattern found: {m.group(0)[:60]}",
                remediation="Avoid deserializing untrusted data. Use integrity checks (HMAC) on serialized objects.",
            ))

    async def _check_update_endpoints(self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult) -> None:
        paths = ["/update", "/upgrade", "/deploy", "/install", "/setup", "/admin/update"]
        for path in paths:
            try:
                resp = await client.get(f"{target.base_url.rstrip('/')}{path}")
                if resp.status_code not in (404, 410):
                    result.add(Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Potentially Exposed Update Endpoint: {path}",
                        description="Update/deploy endpoints accessible without authentication may allow unauthorized code deployment.",
                        severity=Severity.MEDIUM,
                        evidence=f"GET {path} -> HTTP {resp.status_code}",
                        remediation="Restrict update/deploy endpoints to authenticated admin users only. Add IP allowlisting.",
                    ))
                    break
            except httpx.HTTPError:
                pass
