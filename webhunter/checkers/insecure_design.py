"""A04:2021 - Insecure Design: CORS misconfig, open redirects, path traversal in params."""
from __future__ import annotations

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import Severity, VulnCategory, Vulnerability, ScanResult

_TRAVERSAL_PARAMS = ["file", "path", "page", "include", "doc", "template", "folder", "dir", "load", "read"]
_TRAVERSAL_PAYLOADS = ["../etc/passwd", "../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd"]
_OPEN_REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "redirect_uri", "goto", "dest", "destination", "target"]
_REDIRECT_PAYLOAD = "https://evil.com"
_TRAVERSAL_SIGS = ["root:x:", "daemon:", "bin/bash", "bin/sh", "[extensions]", "for 16-bit app support"]


class InsecureDesignChecker(BaseChecker):
    name = "insecure_design"
    category = VulnCategory.A04_INSECURE_DESIGN
    description = "CORS misconfiguration, open redirects, path traversal in parameters"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8) as client:
            await self._check_cors(client, target, result)
            await self._check_open_redirect(client, target, result)
            await self._check_path_traversal(client, target, result)

    async def _check_cors(self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult) -> None:
        try:
            resp = await client.options(
                target.base_url,
                headers={"Origin": "https://evil.attacker.com", "Access-Control-Request-Method": "GET"},
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                result.add(Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="CORS: Wildcard Origin Allowed",
                    description="Access-Control-Allow-Origin: * allows any origin to read responses. Sensitive APIs should restrict origins.",
                    severity=Severity.MEDIUM,
                    evidence=f"ACAO: {acao}",
                    remediation="Restrict CORS to specific trusted origins. Never use wildcard on authenticated endpoints.",
                ))
            elif "evil.attacker.com" in acao:
                sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                result.add(Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title="CORS: Arbitrary Origin Reflected" + (" with Credentials" if acac.lower() == "true" else ""),
                    description="Server reflects the attacker-controlled Origin header. Combined with credentials=true this allows cross-origin data theft.",
                    severity=sev,
                    evidence=f"ACAO: {acao} | ACAC: {acac or 'not set'}",
                    remediation="Validate Origin against an explicit allowlist. Never combine arbitrary origin reflection with Allow-Credentials: true.",
                ))
        except httpx.HTTPError:
            pass

    async def _check_open_redirect(self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult) -> None:
        for param in _OPEN_REDIRECT_PARAMS:
            url = f"{target.base_url}?{param}={_REDIRECT_PAYLOAD}"
            try:
                resp = await client.get(url)
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                    result.add(Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Open Redirect via ?{param}=",
                        description=f"Parameter '{param}' controls redirect destination without validation. Attackers can craft phishing URLs under a trusted domain.",
                        severity=Severity.MEDIUM,
                        evidence=f"GET {url} -> {resp.status_code} Location: {location}",
                        remediation="Validate redirect destinations against an allowlist. Never redirect to user-supplied external URLs.",
                        request=f"GET {url}",
                    ))
                    return
            except httpx.HTTPError:
                pass

    async def _check_path_traversal(self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult) -> None:
        for param in _TRAVERSAL_PARAMS:
            for payload in _TRAVERSAL_PAYLOADS:
                url = f"{target.base_url}?{param}={payload}"
                try:
                    resp = await client.get(url)
                    text = resp.text[:2000]
                    if any(sig in text for sig in _TRAVERSAL_SIGS):
                        result.add(Vulnerability(
                            checker=self.name,
                            category=self.category,
                            title=f"Path Traversal via ?{param}=",
                            description=f"Parameter '{param}' allows directory traversal. Filesystem contents leaked in response.",
                            severity=Severity.HIGH,
                            evidence=f"GET {url} -> {resp.status_code}, response contains traversal content",
                            remediation="Canonicalize paths and validate against a safe base directory. Reject paths containing '../'.",
                            request=f"GET {url}",
                            response_snippet=text[:500],
                        ))
                        return
                except httpx.HTTPError:
                    pass
