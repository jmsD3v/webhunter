from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

from webhunter.core.orchestrator import CHECKERS, print_summary, run_scan, save_output
from webhunter.core.target import ScopeError, TargetURL

app = typer.Typer(
    name="webhunter",
    help="WebHunter — OWASP Top 10 web vulnerability scanner for authorized pentesting.",
    add_completion=False,
)

console = Console()

_FOOTER = (
    "Copyright © 2025 Desarrollado desde Las Breñas con 💜 por @jmsDev All rights reserved"
)


@app.command()
def scan(
    url: Annotated[str, typer.Argument(help="Target URL to scan (e.g. http://10.10.11.21)")],
    force_scope: Annotated[
        bool,
        typer.Option(
            "--force-scope",
            help="Bypass scope check. Only use with written authorization.",
        ),
    ] = False,
    no_ai: Annotated[
        bool,
        typer.Option("--no-ai", help="Skip Gemini AI analysis."),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Save results to JSON file."),
    ] = None,
    report: Annotated[
        str | None,
        typer.Option("--report", "-r", help="Generate HTML report (Phase 3 — not yet implemented)."),
    ] = None,
) -> None:
    console.print(
        f"\n[bold cyan]WebHunter[/bold cyan] [dim]v0.1.0[/dim] — "
        "OWASP Top 10 scanner\n"
    )

    try:
        target = TargetURL.parse(url)
    except ValueError as exc:
        console.print(f"[red]Invalid URL: {exc}[/red]")
        raise typer.Exit(1) from exc

    try:
        target.validate_scope(force=force_scope)
    except ScopeError as exc:
        console.print(f"[bold red]SCOPE ERROR:[/bold red] {exc}")
        raise typer.Exit(1) from exc

    if force_scope:
        console.print(
            "[bold yellow]WARNING:[/bold yellow] Scope check bypassed. "
            "Ensure you have written authorization for this target.\n"
        )

    console.print(f"  Target  : [bold]{target.base_url}[/bold]")
    console.print(f"  AI      : {'disabled' if no_ai else 'enabled (Gemini)'}")
    console.print(f"  Checkers: {len(CHECKERS)} loaded\n")

    if report:
        console.print("[yellow]--report is not yet implemented (Phase 3).[/yellow]")

    result = asyncio.run(run_scan(target, use_ai=not no_ai))

    print_summary(result)

    if output:
        save_output(result, output)

    has_critical_or_high = result.critical_count > 0 or result.high_count > 0
    raise typer.Exit(1 if has_critical_or_high else 0)


@app.command()
def checkers() -> None:
    console.print(
        "\n[bold cyan]WebHunter[/bold cyan] — Available Checkers\n"
    )

    if not CHECKERS:
        console.print("[dim]No checkers registered yet (Phase 2 pending).[/dim]")
        console.print(
            "\nTo add a checker, implement [bold]BaseChecker[/bold] in "
            "[bold]webhunter/checkers/<name>.py[/bold] and register it in "
            "[bold]webhunter/core/orchestrator.py[/bold].\n"
        )
        console.print(f"[dim]{_FOOTER}[/dim]")
        return

    table = Table("Name", "OWASP Category", "Description", show_lines=True)
    for checker in CHECKERS:
        table.add_row(
            checker.name,
            f"{checker.category.value} — {checker.category.label}",
            checker.description,
        )

    console.print(table)
    console.print(f"\n[dim]{_FOOTER}[/dim]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
