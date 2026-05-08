from __future__ import annotations

import asyncio
import re

import httpx

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity, VulnCategory, Vulnerability

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebHunter/1.0)"}

_VERSION_RE = re.compile(r"(\d+\.\d+[\.\d]*)")

_VERSION_HEADERS = ("server", "x-powered-by", "x-generator", "x-runtime", "x-version")

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_WP_COMMENT_RE = re.compile(r"<!--\s*WordPress\s+([\d.]+)", re.IGNORECASE)
_JOOMLA_RE = re.compile(r"Joomla!\s*([\d.]+)", re.IGNORECASE)
_DRUPAL_RE = re.compile(r"Drupal\s+([\d.]+)", re.IGNORECASE)
_TYPO3_RE = re.compile(r"TYPO3\s+([\d.]+)", re.IGNORECASE)
_JQUERY_RE = re.compile(r"[Jj]Query\s*[vV]?([\d.]+)")
_BOOTSTRAP_RE = re.compile(r"[Bb]ootstrap\s*[vV]?([\d.]+)")

_CMS_MIN_VERSIONS: dict[str, tuple[int, ...]] = {
    "wordpress": (6, 0),
    "joomla": (4, 0),
    "drupal": (10, 0),
}

_VULN_PATHS_HIGH: list[tuple[str, str]] = [
    ("/wp-content/plugins/", "WordPress plugins exposed"),
]

_VULN_PATHS_MEDIUM: list[tuple[str, str]] = [
    ("/package.json", "Dependency file exposed"),
    ("/composer.json", "Dependency file exposed"),
    ("/Gemfile", "Dependency manifest exposed"),
    ("/requirements.txt", "Dependency manifest exposed"),
]

_VULN_PATHS_LOW: list[tuple[str, str]] = [
    ("/CHANGELOG.md", "Changelog exposed (version leak)"),
    ("/CHANGELOG.txt", "Changelog exposed (version leak)"),
    ("/CHANGES", "Changelog exposed (version leak)"),
]

_DIRECTORY_LISTING_PATTERNS = ("Index of /", "<title>Index of", "Parent Directory")


def _parse_version(s: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in s.split(".") if x.isdigit())
    except Exception:
        return ()


def _is_old_cms(name: str, version_str: str) -> bool:
    minimum = _CMS_MIN_VERSIONS.get(name.lower())
    if not minimum:
        return False
    parsed = _parse_version(version_str)
    if not parsed:
        return False
    return parsed < minimum


class VulnComponentsChecker(BaseChecker):
    name = "vulnerable_components"
    category = VulnCategory.A06_VULNERABLE_COMPONENTS
    description = "Outdated software versions in headers and HTML comments"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        async with httpx.AsyncClient(
            verify=False,
            timeout=10,
            follow_redirects=True,
            headers=_HEADERS,
        ) as client:
            await asyncio.gather(
                self._check_version_headers(client, target, result),
                self._check_html_versions(client, target, result),
                self._check_vuln_paths(client, target, result),
            )

    async def _check_version_headers(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        try:
            resp = await client.get(target.base_url)
        except httpx.HTTPError:
            return

        for header in _VERSION_HEADERS:
            value = resp.headers.get(header)
            if not value:
                continue
            match = _VERSION_RE.search(value)
            if not match:
                continue
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Version disclosed — {header}: {value}",
                    description=(
                        f"The HTTP response header '{header}' discloses version "
                        f"information ({value!r}), which assists attackers in "
                        "targeting known CVEs."
                    ),
                    severity=Severity.LOW,
                    evidence=f"{header}: {value}",
                    request=f"GET {target.base_url}",
                    response_snippet=None,
                    remediation="Remove version numbers from HTTP headers.",
                )
            )

    async def _check_html_versions(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        try:
            resp = await client.get(target.base_url)
        except httpx.HTTPError:
            return

        body = resp.text[:10000]

        generator_match = _GENERATOR_RE.search(body)
        if generator_match:
            content = generator_match.group(1).strip()
            parts = content.split()
            cms = parts[0] if parts else content
            version_str = parts[1] if len(parts) > 1 else ""
            ver_match = _VERSION_RE.search(version_str) if version_str else None
            if ver_match:
                version = ver_match.group(1)
                old = _is_old_cms(cms, version)
                severity = Severity.HIGH if old else Severity.MEDIUM
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"CMS version disclosed — {cms} {version}",
                        description=(
                            f"The meta generator tag reveals {cms} version {version}. "
                            + ("This version is below the minimum recommended version and may contain known vulnerabilities." if old else "")
                        ),
                        severity=severity,
                        evidence=generator_match.group(0),
                        request=f"GET {target.base_url}",
                        remediation=f"Update {cms} to latest stable version. Remove version comments from HTML.",
                    )
                )

        wp_match = _WP_COMMENT_RE.search(body)
        if wp_match:
            version = wp_match.group(1)
            old = _is_old_cms("wordpress", version)
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"CMS version disclosed — WordPress {version}",
                    description=(
                        f"An HTML comment reveals WordPress version {version}. "
                        + ("This version is below 6.0 and likely contains known vulnerabilities." if old else "")
                    ),
                    severity=Severity.HIGH if old else Severity.MEDIUM,
                    evidence=wp_match.group(0),
                    request=f"GET {target.base_url}",
                    remediation="Update WordPress to latest stable version. Remove version comments from HTML.",
                )
            )

        for pattern_re, cms_name, min_label in (
            (_JOOMLA_RE, "Joomla", "4.0"),
            (_DRUPAL_RE, "Drupal", "10.0"),
            (_TYPO3_RE, "TYPO3", None),
        ):
            m = pattern_re.search(body)
            if m:
                version = m.group(1)
                old = _is_old_cms(cms_name, version)
                result.add(
                    Vulnerability(
                        checker=self.name,
                        category=self.category,
                        title=f"CMS version disclosed — {cms_name} {version}",
                        description=(
                            f"Page body discloses {cms_name} version {version}."
                            + (f" Version is below {min_label} and may be vulnerable." if old and min_label else "")
                        ),
                        severity=Severity.HIGH if old else Severity.MEDIUM,
                        evidence=m.group(0),
                        request=f"GET {target.base_url}",
                        remediation=f"Update {cms_name} to latest stable version. Remove version comments from HTML.",
                    )
                )

        jq_match = _JQUERY_RE.search(body)
        if jq_match:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"jQuery version disclosed — {jq_match.group(1)}",
                    description=f"Page discloses jQuery version {jq_match.group(1)} in source.",
                    severity=Severity.INFO,
                    evidence=jq_match.group(0),
                    request=f"GET {target.base_url}",
                    remediation="Avoid exposing library versions in source. Update jQuery to latest.",
                )
            )

        bs_match = _BOOTSTRAP_RE.search(body)
        if bs_match:
            result.add(
                Vulnerability(
                    checker=self.name,
                    category=self.category,
                    title=f"Bootstrap version disclosed — {bs_match.group(1)}",
                    description=f"Page discloses Bootstrap version {bs_match.group(1)} in source.",
                    severity=Severity.INFO,
                    evidence=bs_match.group(0),
                    request=f"GET {target.base_url}",
                    remediation="Avoid exposing library versions in source. Update Bootstrap to latest.",
                )
            )

    async def _probe_path(
        self,
        client: httpx.AsyncClient,
        target: TargetURL,
        result: ScanResult,
        path: str,
        title: str,
        severity: Severity,
        check_dir_listing: bool = False,
    ) -> None:
        url = target.url(path)
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return

        if resp.status_code != 200:
            return

        if check_dir_listing:
            body = resp.text[:2000]
            if not any(p in body for p in _DIRECTORY_LISTING_PATTERNS):
                return

        result.add(
            Vulnerability(
                checker=self.name,
                category=self.category,
                title=title,
                description=(
                    f"The path {path!r} returned HTTP 200 and is publicly accessible. "
                    "This may expose sensitive version or dependency information."
                ),
                severity=severity,
                evidence=f"HTTP 200 on {path}",
                request=f"GET {url}",
                response_snippet=resp.text[:200],
                remediation=(
                    "Restrict access to this path. Remove or relocate sensitive files "
                    "outside the web root."
                ),
            )
        )

    async def _check_vuln_paths(
        self, client: httpx.AsyncClient, target: TargetURL, result: ScanResult
    ) -> None:
        tasks = []
        for path, title in _VULN_PATHS_HIGH:
            tasks.append(
                self._probe_path(client, target, result, path, title, Severity.HIGH, check_dir_listing=True)
            )
        for path, title in _VULN_PATHS_MEDIUM:
            tasks.append(
                self._probe_path(client, target, result, path, title, Severity.MEDIUM)
            )
        for path, title in _VULN_PATHS_LOW:
            tasks.append(
                self._probe_path(client, target, result, path, title, Severity.LOW)
            )
        await asyncio.gather(*tasks)
