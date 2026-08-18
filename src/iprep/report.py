from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .aggregate import Verdict
from .base import SourceResult

VERDICT_STYLE = {
    "malicious": "bold red",
    "suspicious": "bold yellow",
    "clean": "bold green",
    "unknown": "dim",
}


def render(ip: str, results: list[SourceResult], verdict: Verdict, console: Console) -> None:
    style = VERDICT_STYLE.get(verdict.label, "white")
    header = (
        f"[{style}]{verdict.label.upper()}[/{style}]  "
        f"risk score: {verdict.score}/100  "
        f"({verdict.sources_ok}/{verdict.sources_total} reputation sources responded)"
    )
    console.print(Panel(header, title=f"iprep report: {ip}", expand=False))

    rep_table = Table(title="Reputation sources")
    rep_table.add_column("Source")
    rep_table.add_column("Verdict")
    rep_table.add_column("Score")
    rep_table.add_column("Summary")
    for r in sorted((x for x in results if x.category == "reputation"), key=lambda x: x.name):
        v_style = VERDICT_STYLE.get(r.verdict, "white")
        v_text = f"[{v_style}]{r.verdict}[/{v_style}]" if r.ok else "[dim]n/a[/dim]"
        score_text = f"{r.score:.0f}" if (r.ok and r.score is not None) else "-"
        summary = r.summary if r.ok else f"[dim]{r.error}: {r.summary}[/dim]"
        rep_table.add_row(r.name, v_text, score_text, summary)
    console.print(rep_table)

    ctx_table = Table(title="Context / enrichment")
    ctx_table.add_column("Source")
    ctx_table.add_column("Info")
    for r in sorted((x for x in results if x.category == "context"), key=lambda x: x.name):
        info = r.summary if r.ok else f"[dim]{r.error}[/dim]"
        ctx_table.add_row(r.name, info)
    console.print(ctx_table)

    if verdict.contributing:
        console.print(f"\n[bold]Flagged by:[/bold] {', '.join(verdict.contributing)}")
