from __future__ import annotations

import asyncio
import time

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity, VulnCategory, Vulnerability

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebHunter/1.0)"}

_LOGIN_PATHS = (
    "/login",
    "/signin",
    "/auth",
    "/account/login",
    "/user/login",
    "/wp-login.php",
    "/admin/login",
)

_LOGIN_PAYLOADS = (
    {"username": "admin", "password": "wrong_password_test"},
    {"user": "admin", "pass": "wrong_password_test"},
    {"email": "admin@admin.com", "password": "wrong_password_test"},
)

_DEFAULT_CREDS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("guest", "guest"),
)

_BRUTE_ATTEMPTS = 5
_RATE_LIMIT_THRESHOLD_S = 2.0


class AuthFailuresChecker(BaseChecker):
    name = "auth_failures"
    category = VulnCategory.A07_AUTH_FAILURES
    description = "Login form detection, lockout policy, default credentials"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(
            verify=False,
            timeout=10,
            follow_redirects=False,
            headers=_HEADERS,
        ) as client:
            login_pages = await self._detect_login_pages(client, target, result)
            if login_pages:
                await asyncio.gather(
                    self._check_brute_force_protection(client, target, result, login_pages),
                    self._check_default_credentials(client, target, result, login_pages),
                )

    async def _detect_login_pages(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> list[str]:
        found: list[str] = []

        async def probe(path: str) -> None:
            url = target.url(path)
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                return
            if resp.status_code != 200:
                return
            if '<input type="password"' not in resp.text and "<input type='password'" not in resp.text:
                return
            found.append(path)
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Login page found — {path}",
                    description=f"A login form with a password field was detected at {path!r}.",
                    severity=Severity.INFO,
                    evidence=f"HTTP 200 on {path} with <input type=\"password\">",
                    request=f"GET {url}",
                    response_snippet=resp.text[:200],
                    remediation="Ensure login pages enforce HTTPS, MFA, and brute-force protection.",
                )
            )

        await asyncio.gather(*[probe(p) for p in _LOGIN_PATHS])
        return found

    async def _check_brute_force_protection(
        self,
        client: httpx.AsyncClient,
        target: TargetURL,
        result: ScanResult,
        login_pages: list[str],
    ) -> None:
        for path in login_pages:
            url = target.url(path)
            sizes: list[int] = []
            statuses: list[int] = []
            got_429 = False
            slow_after: int | None = None

            for attempt in range(_BRUTE_ATTEMPTS):
                payload = _LOGIN_PAYLOADS[attempt % len(_LOGIN_PAYLOADS)]
                t0 = time.perf_counter()
                try:
                    resp = await client.post(url, data=payload)
                except httpx.HTTPError:
                    break

                elapsed = time.perf_counter() - t0
                statuses.append(resp.status_code)
                sizes.append(len(resp.content))

                if resp.status_code == 429:
                    got_429 = True
                    break

                if attempt >= 2 and elapsed > _RATE_LIMIT_THRESHOLD_S and slow_after is None:
                    slow_after = attempt + 1

            if got_429:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Rate limiting active (429) — {path}",
                        description=f"The login endpoint {path!r} responded with HTTP 429 after repeated attempts.",
                        severity=Severity.INFO,
                        evidence=f"HTTP 429 received on attempt during POST to {path}",
                        request=f"POST {url}",
                        remediation="Rate limiting is active. Verify lockout and CAPTCHA policies are also enforced.",
                    )
                )
                continue

            if slow_after is not None:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Possible rate limiting (slow response) — {path}",
                        description=(
                            f"Response time exceeded {_RATE_LIMIT_THRESHOLD_S}s after "
                            f"attempt {slow_after} on {path!r}, suggesting throttling."
                        ),
                        severity=Severity.INFO,
                        evidence=f"Response time > {_RATE_LIMIT_THRESHOLD_S}s detected after attempt {slow_after}",
                        request=f"POST {url}",
                        remediation="Confirm rate limiting is enforced for all login paths.",
                    )
                )
                continue

            if len(sizes) == _BRUTE_ATTEMPTS and len(set(sizes)) == 1 and len(set(statuses)) == 1:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"No brute-force protection detected — {path}",
                        description=(
                            f"{_BRUTE_ATTEMPTS} login attempts to {path!r} returned identical "
                            "responses with no rate limiting, lockout, or CAPTCHA challenge observed."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=(
                            f"{_BRUTE_ATTEMPTS} attempts, all HTTP {statuses[0]}, "
                            f"response size {sizes[0]} bytes (no variation)"
                        ),
                        request=f"POST {url}",
                        remediation=(
                            "Implement account lockout after N failed attempts, "
                            "exponential backoff, rate limiting (e.g. 429), "
                            "or CAPTCHA challenges."
                        ),
                    )
                )

    async def _check_default_credentials(
        self,
        client: httpx.AsyncClient,
        target: TargetURL,
        result: ScanResult,
        login_pages: list[str],
    ) -> None:
        if not login_pages:
            return

        path = login_pages[0]
        url = target.url(path)

        try:
            baseline = await client.get(url)
        except httpx.HTTPError:
            return
        baseline_size = len(baseline.content)

        for username, password in _DEFAULT_CREDS:
            payload = {"username": username, "password": password}
            try:
                resp = await client.post(url, data=payload)
            except httpx.HTTPError:
                continue

            accepted = False

            if resp.status_code in (301, 302, 303, 307, 308):
                accepted = True

            if not accepted and resp.status_code == 200:
                if '<input type="password"' not in resp.text and "<input type='password'" not in resp.text:
                    accepted = True

            if not accepted and resp.status_code == 200:
                size_diff = abs(len(resp.content) - baseline_size)
                if size_diff > baseline_size * 0.5 and len(resp.content) > 500:
                    accepted = True

            if accepted:
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"Default credentials accepted — {username}:{password}",
                        description=(
                            f"Login to {path!r} with default credentials "
                            f"'{username}:{password}' appears to have succeeded "
                            f"(HTTP {resp.status_code}). Human verification required."
                        ),
                        severity=Severity.HIGH,
                        evidence=(
                            f"POST {path} with {username}:{password} → "
                            f"HTTP {resp.status_code}, "
                            f"response size {len(resp.content)} bytes "
                            f"(baseline {baseline_size} bytes)"
                        ),
                        request=f"POST {url}",
                        response_snippet=resp.text[:200],
                        remediation=(
                            "Change all default credentials immediately. "
                            "Enforce a strong password policy and disable "
                            "default accounts where possible."
                        ),
                    )
                )
                return
