from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from webhunter.checkers.base import BaseChecker
from webhunter.core.ai_provider import NoAIProviderError, get_completion
from webhunter.core.target import TargetURL
from webhunter.types.findings import ScanResult, Severity

console = Console()

from webhunter.checkers.access_control import AccessControlChecker
from webhunter.checkers.auth_failures import AuthFailuresChecker
from webhunter.checkers.crypto import CryptoChecker
from webhunter.checkers.injection import InjectionChecker
from webhunter.checkers.insecure_design import InsecureDesignChecker
from webhunter.checkers.integrity_failures import IntegrityFailuresChecker
from webhunter.checkers.logging_failures import LoggingFailuresChecker
from webhunter.checkers.misconfiguration import MisconfigChecker
from webhunter.checkers.ssrf import SSRFChecker
from webhunter.checkers.vulnerable_components import VulnComponentsChecker

CHECKERS: list[BaseChecker] = [
    AccessControlChecker(),
    AuthFailuresChecker(),
    CryptoChecker(),
    InjectionChecker(),
    InsecureDesignChecker(),
    IntegrityFailuresChecker(),
    LoggingFailuresChecker(),
    MisconfigChecker(),
    SSRFChecker(),
    VulnComponentsChecker(),
]


async def _analyze_with_ai(result: ScanResult) -> str | None:
    try:
        vuln_summary = "\n".join(
            f"- [{v.severity.value.upper()}] {v.title} ({v.category.value}): {v.description}"
            for v in result.sorted_vulns[:20]
        )

        prompt = (
            f"You are a senior penetration tester reviewing a web security scan.\n"
            f"Target: {result.target_url}\n"
            f"Scan found {len(result.vulns)} issues:\n\n"
            f"{vuln_summary}\n\n"
            f"Provide a concise security assessment (3-5 sentences): "
            f"overall risk level, most critical issues, and top remediation priorities."
        )

        return await get_completion(prompt)

    except NoAIProviderError:
        return None
    except Exception as exc:
        console.print(f"[yellow]AI analysis skipped: {exc}[/yellow]")
        return None


async def run_scan(
    target: TargetURL,
    use_ai: bool = True,
) -> ScanResult:
    result = ScanResult(
        target_url=target.base_url,
        started_at=datetime.now(timezone.utc),
    )

    if not CHECKERS:
        console.print("[yellow]No checkers registered yet (Phase 2 pending).[/yellow]")
    else:
        console.print(
            f"[bold green]Running {len(CHECKERS)} checker(s) against {target.base_url}[/bold green]"
        )
        await asyncio.gather(*[checker.execute(target, result) for checker in CHECKERS])

    if use_ai:
        console.print("[dim]Requesting AI analysis...[/dim]")
        result.ai_analysis = await _analyze_with_ai(result)

    result.completed_at = datetime.now(timezone.utc)
    return result


def print_summary(result: ScanResult) -> None:
    duration = result.duration_seconds or 0.0

    console.print()
    console.rule("[bold]WebHunter Scan Summary[/bold]")
    console.print(f"  Target   : [bold cyan]{result.target_url}[/bold cyan]")
    console.print(f"  Duration : {duration:.1f}s")
    console.print(
        f"  Findings : "
        f"[bold red]{result.critical_count} CRITICAL[/bold red] | "
        f"[red]{result.high_count} HIGH[/red] | "
        f"[yellow]{result.medium_count} MEDIUM[/yellow] | "
        f"[cyan]{result.low_count} LOW[/cyan] | "
        f"[dim]{len(result.by_severity(Severity.INFO))} INFO[/dim]"
    )

    if not result.vulns:
        console.print("\n  [dim]No vulnerabilities found.[/dim]")
        _print_footer()
        return

    table = Table(
        "Severity",
        "OWASP",
        "Title",
        "Evidence",
        title="Vulnerabilities",
        show_lines=True,
    )

    for vuln in result.sorted_vulns:
        table.add_row(
            f"[{vuln.severity.color}]{vuln.severity.value.upper()}[/{vuln.severity.color}]",
            vuln.category.value,
            vuln.title,
            vuln.evidence[:80] + ("..." if len(vuln.evidence) > 80 else ""),
        )

    console.print()
    console.print(table)

    if result.ai_analysis:
        console.print()
        console.rule("[bold]AI Analysis[/bold]")
        console.print(result.ai_analysis)

    _print_footer()


def save_output(result: ScanResult, path: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    console.print(f"\n[green]Results saved to {output_path.resolve()}[/green]")


def _print_footer() -> None:
    console.print()
    console.print(
        "[dim]Copyright (c) 2025 Desarrollado desde Las Brenas con amor "
        "por @jmsDev All rights reserved[/dim]"
    )
