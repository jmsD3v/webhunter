"""A10:2021 - SSRF: Server-Side Request Forgery detection via URL parameters and common endpoints."""
from __future__ import annotations

import re

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import Severity, VulnCategory, Vulnerability, ScanResult

# Parameters commonly used to pass URLs server-side
_URL_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination", "target",
    "path", "proxy", "fetch", "load", "img", "image", "document", "file",
    "page", "feed", "host", "endpoint", "callback", "webhook", "resource",
]

# SSRF payloads targeting internal services
_SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDSv1
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",  # DigitalOcean
    "http://0.0.0.0/",
    "http://[::1]/",
]

# Strings that indicate a hit (internal service response leaked)
_SSRF_SIGNATURES = [
    "ami-id", "instance-id", "local-hostname", "security-credentials",  # AWS
    "computeMetadata", "serviceAccounts",  # GCP
    "droplet_id", "interfaces",  # DO
    "root:x:", "localhost",
]

# Common endpoints that accept a URL parameter
_PROXY_ENDPOINTS = [
    "/proxy", "/fetch", "/redirect", "/load", "/api/proxy",
    "/api/fetch", "/api/load", "/image", "/images/proxy",
    "/preview", "/thumbnail", "/screenshot",
]

_IMG_URL_RE = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_LINK_URL_RE = re.compile(r'(?:url|uri|src|href)=["\']?(https?://[^"\'&\s]+)', re.IGNORECASE)


class SSRFChecker(BaseChecker):
    name = "ssrf"
    category = VulnCategory.A10_SSRF
    description = "SSRF via URL parameters, proxy endpoints, and internal metadata service probes"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as client:
            await self._probe_url_params(client, target, result)
            await self._probe_proxy_endpoints(client, target, result)
            await self._check_response_for_url_params(client, target, result)

    async def _probe_url_params(self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult) -> None:
        for payload in _SSRF_PAYLOADS[:3]:  # limit to avoid too many requests
            for param in _URL_PARAMS[:8]:
                url = f"{target.base_url}?{param}={payload}"
                try:
                    resp = await client.get(url, timeout=5)
                    text = resp.text[:3000]
                    hit = next((s for s in _SSRF_SIGNATURES if s in text), None)
                    if hit:
                        result.add(Vulnerability(
                            checker=self.name,
                            category=self.category,
                            title=f"SSRF via ?{param}= (Internal Response Leaked)",
                            description=(
                                f"Parameter '{param}' caused the server to fetch an internal URL ({payload}). "
                                f"Response contains internal service content. Full SSRF confirmed."
                            ),
                            severity=Severity.CRITICAL,
                            evidence=f"GET {url} -> signature '{hit}' found in response",
                            remediation=(
                                "Validate and allowlist URLs before server-side fetching. "
                                "Block requests to RFC1918 ranges and cloud metadata IPs. "
                                "Use a dedicated egress proxy with strict controls."
                            ),
                            request=f"GET {url}",
                            response_snippet=text[:500],
                        ))
                        return
                except httpx.HTTPError:
                    pass

    async def _probe_proxy_endpoints(self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult) -> None:
        for endpoint in _PROXY_ENDPOINTS:
            full = f"{target.base_url.rstrip('/')}{endpoint}"
            for payload in ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"]:
                url = f"{full}?url={payload}"
                try:
                    resp = await client.get(url, timeout=5)
                    text = resp.text[:2000]
                    hit = next((s for s in _SSRF_SIGNATURES if s in text), None)
                    if hit:
                        result.add(Vulnerability(
                            checker=self.name,
                            category=self.category,
                            title=f"SSRF via Proxy Endpoint {endpoint}",
                            description=f"Proxy endpoint '{endpoint}' fetched internal URL '{payload}'. Internal content visible in response.",
                            severity=Severity.CRITICAL,
                            evidence=f"GET {url} -> signature '{hit}' in response",
                            remediation="Remove or restrict proxy endpoints. Validate all fetched URLs against an allowlist.",
                            request=f"GET {url}",
                        ))
                        return
                    if resp.status_code == 200 and len(resp.content) > 0 and endpoint in ("/proxy", "/fetch", "/api/proxy", "/api/fetch"):
                        result.add(Vulnerability(
                            checker=self.name,
                            category=self.category,
                            title=f"Potential SSRF: Open Proxy Endpoint {endpoint}",
                            description=f"Endpoint '{endpoint}' returned HTTP 200 for internal URL request. Manual verification needed.",
                            severity=Severity.HIGH,
                            evidence=f"GET {url} -> HTTP {resp.status_code}, {len(resp.content)} bytes",
                            remediation="Validate and restrict URLs fetched by proxy endpoints. Block internal ranges.",
                            request=f"GET {url}",
                        ))
                        return
                except httpx.HTTPError:
                    pass

    async def _check_response_for_url_params(self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult) -> None:
        """Check if the homepage contains forms/params that accept URLs (passive detection)."""
        try:
            resp = await client.get(target.base_url)
            html = resp.text
            # Look for input fields named with URL-like names
            url_inputs = re.findall(
                r'<input[^>]+name=["\'](' + '|'.join(_URL_PARAMS) + r')["\']',
                html, re.IGNORECASE
            )
            if url_inputs:
                result.add(Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Potential SSRF Attack Surface: URL Input Fields ({', '.join(set(url_inputs)[:3])})",
                    description="Input fields with URL-accepting names found. These may be vulnerable to SSRF if processed server-side without validation.",
                    severity=Severity.LOW,
                    evidence=f"Fields: {', '.join(set(url_inputs))}",
                    remediation="Audit all URL-accepting parameters. Validate against an allowlist and block requests to internal ranges.",
                ))
        except httpx.HTTPError:
            pass
