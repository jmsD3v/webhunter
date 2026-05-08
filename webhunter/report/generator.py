from __future__ import annotations

import asyncio
from datetime import timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webhunter.types.findings import ScanResult


async def generate_report(result: ScanResult, output_path: Path, fmt: str = "pdf") -> Path:
    from jinja2 import Environment, FileSystemLoader

    template_dir = Path(__file__).parent
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    tmpl = env.get_template("template.html")

    started_at = result.started_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    duration = f"{result.duration_seconds:.1f}s" if result.duration_seconds else "—"
    info_count = len(result.by_severity(__import__("webhunter.types.findings", fromlist=["Severity"]).Severity.INFO))

    html = tmpl.render(
        result=result,
        started_at=started_at,
        duration=duration,
        info_count=info_count,
    )

    html_path = output_path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")

    if fmt == "pdf":
        try:
            from weasyprint import HTML  # type: ignore[import]
            await asyncio.get_running_loop().run_in_executor(
                None, lambda: HTML(string=html, base_url=str(template_dir)).write_pdf(str(output_path))
            )
            return output_path
        except ImportError:
            return html_path

    return html_path
