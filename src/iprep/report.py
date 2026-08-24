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

    _render_shodan_detail(results, console)

    if verdict.contributing:
        console.print(f"\n[bold]Flagged by:[/bold] {', '.join(verdict.contributing)}")


def _render_shodan_detail(results: list[SourceResult], console: Console) -> None:
    """Shodan carries much richer per-port/per-CVE detail than fits in the
    Reputation table's Summary column - break it out separately when present."""
    r = next((x for x in results if x.name == "Shodan" and x.ok), None)
    if not r or not r.details:
        return

    d = r.details
    services = d.get("services") or []
    vuln_detail = d.get("vuln_detail") or {}
    certs = d.get("certs") or []
    if not (services or vuln_detail or certs):
        return

    header_bits = []
    if d.get("org"):
        header_bits.append(d["org"])
    if d.get("os"):
        header_bits.append(f"OS: {d['os']}")
    if d.get("city") or d.get("country"):
        header_bits.append(", ".join(filter(None, [d.get("city"), d.get("country")])))
    if d.get("last_update"):
        header_bits.append(f"last scanned: {d['last_update']}")

    console.print()
    title = "Shodan host detail"
    if header_bits:
        title += f"  ({' | '.join(header_bits)})"
    console.print(f"[bold]{title}[/bold]")

    if services:
        t = Table(show_header=True, header_style="bold")
        t.add_column("Port")
        t.add_column("Service")
        for line in services:
            port_proto, _, rest = line.partition(": ")
            t.add_row(port_proto, rest or "-")
        console.print(t)

    if vuln_detail:
        t = Table(show_header=True, header_style="bold")
        t.add_column("CVE")
        t.add_column("CVSS")
        t.add_column("Verified")
        for cve_id, info in sorted(vuln_detail.items(), key=lambda kv: -(kv[1].get("cvss") or 0)):
            cvss = info.get("cvss")
            cvss_style = "bold red" if (cvss or 0) >= 7.0 else ("yellow" if (cvss or 0) >= 4.0 else "")
            cvss_text = f"[{cvss_style}]{cvss}[/{cvss_style}]" if cvss_style else str(cvss or "-")
            t.add_row(cve_id, cvss_text, "yes" if info.get("verified") else "no")
        console.print(t)

    if certs:
        console.print("[bold]SSL certs:[/bold] " + "; ".join(certs))
