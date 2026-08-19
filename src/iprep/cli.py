from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import report
from .aggregate import Verdict, aggregate
from .base import SourceResult
from .config import CONFIG_PATH, KEY_SPECS, KNOWN_SOURCES, key_origin, load_config, mask, save_key
from .context import Context, build_context
from .sources import (
    abuseipdb,
    asn,
    blocklistde,
    cins,
    et_compromised,
    firehol,
    greynoise,
    ipsum,
    rdap,
    shodan,
    spamhaus,
    talos,
    tor,
    vpn,
)
from .sources import dns as dns_source
from .sources import virustotal

SOURCE_MODULES = {
    "virustotal": virustotal,
    "abuseipdb": abuseipdb,
    "shodan": shodan,
    "talos": talos,
    "spamhaus": spamhaus,
    "firehol": firehol,
    "cins": cins,
    "blocklistde": blocklistde,
    "ipsum": ipsum,
    "et": et_compromised,
    "rdap": rdap,
    "asn": asn,
    "dns": dns_source,
    "tor": tor,
    "vpn": vpn,
    "greynoise": greynoise,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iprep", description="Aggregate IP reputation across multiple threat-intel sources."
    )
    sub = p.add_subparsers(dest="command", required=True)

    check_p = sub.add_parser("check", help="check an IP's reputation (this is also the default when you just run `iprep <ip>`)")
    check_p.add_argument("ip", help="IPv4 (or IPv6, for supported sources) address to check")
    check_p.add_argument("--json", action="store_true", help="output machine-readable JSON instead of a formatted report")
    check_p.add_argument("--sources", help="comma-separated subset of sources to query: " + ",".join(SOURCE_MODULES))
    check_p.add_argument("--refresh-lists", action="store_true", help="force re-download of all cached blocklist/list-based feeds")
    check_p.add_argument("--timeout", type=float, default=15.0, help="per-source request timeout in seconds (default 15)")

    batch_p = sub.add_parser("batch", help="check every IP in a file and emit a summary")
    batch_p.add_argument("file", help="path to a file with one IP per line ('-' for stdin); blank lines and '#' comments are skipped, duplicates are deduped")
    fmt_group = batch_p.add_mutually_exclusive_group()
    fmt_group.add_argument("--json", action="store_true", help="emit a JSON array with full per-source detail for each IP, instead of a summary table")
    fmt_group.add_argument("--csv", action="store_true", help="emit CSV: ip,verdict,score,sources_ok,sources_total,flagged_by")
    batch_p.add_argument("--output", "-o", help="write output to this file instead of stdout")
    batch_p.add_argument("--sources", help="comma-separated subset of sources to query: " + ",".join(SOURCE_MODULES))
    batch_p.add_argument("--refresh-lists", action="store_true", help="force re-download of all cached blocklist/list-based feeds")
    batch_p.add_argument("--timeout", type=float, default=15.0, help="per-source request timeout in seconds (default 15)")
    batch_p.add_argument("--parallel", type=int, default=4, help="how many IPs to check concurrently (default 4; keep this low if you have low-quota API keys configured)")

    keys_p = sub.add_parser("keys", help="manage locally-stored API keys (never written to the repo)")
    keys_sub = keys_p.add_subparsers(dest="keys_command", required=True)

    set_p = keys_sub.add_parser("set", help="add or update an API key")
    set_p.add_argument("source", choices=KNOWN_SOURCES)
    set_p.add_argument("value", nargs="?", help="key value; omit to be prompted with hidden input instead of exposing it in shell history")

    unset_p = keys_sub.add_parser("unset", help="remove a stored API key")
    unset_p.add_argument("source", choices=KNOWN_SOURCES)

    keys_sub.add_parser("show", help="list which keys are configured (values are masked)")
    keys_sub.add_parser("path", help="print the path to the key storage file")

    return p


def _normalize_argv(argv: list[str] | None) -> list[str]:
    """Let `iprep <ip>` keep working as shorthand for `iprep check <ip>`."""
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv or argv[0] in ("check", "batch", "keys", "-h", "--help"):
        return argv
    return ["check", *argv]


def resolve_sources(sources_arg: str | None, console: Console) -> dict | None:
    if not sources_arg:
        return SOURCE_MODULES
    names = [s.strip() for s in sources_arg.split(",")]
    unknown = [n for n in names if n not in SOURCE_MODULES]
    if unknown:
        console.print(f"[bold red]error:[/bold red] unknown source(s): {', '.join(unknown)}")
        return None
    return {n: SOURCE_MODULES[n] for n in names}


def run_checks(ip: str, ctx: Context, selected: dict) -> tuple[list[SourceResult], Verdict]:
    results: list[SourceResult] = []
    with ThreadPoolExecutor(max_workers=max(len(selected), 1)) as pool:
        futures = {pool.submit(mod.check, ip, ctx): name for name, mod in selected.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(SourceResult(name=name, ok=False, error=str(e), summary="unexpected error"))
    return results, aggregate(results)


def handle_keys(args: argparse.Namespace, console: Console) -> int:
    if args.keys_command == "path":
        console.print(str(CONFIG_PATH))
        return 0

    if args.keys_command == "show":
        config = load_config()
        table = Table(title=f"iprep keys  ({CONFIG_PATH})")
        table.add_column("Source")
        table.add_column("Status")
        for source in KNOWN_SOURCES:
            field_name, _, _ = KEY_SPECS[source]
            value = getattr(config, field_name)
            if not value:
                status = "[dim]not set[/dim]"
            else:
                origin = key_origin(source) or "?"
                status = f"[green]{mask(value)}[/green] (from {origin})"
            table.add_row(source, status)
        console.print(table)
        return 0

    if args.keys_command == "set":
        value = args.value or getpass.getpass(f"Enter API key for {args.source} (input hidden, not echoed): ").strip()
        if not value:
            console.print("[bold red]error:[/bold red] empty key, nothing saved")
            return 2
        save_key(args.source, value)
        console.print(f"[green]saved[/green] {args.source} key to {CONFIG_PATH} (file permissions set to 0600, owner-only)")
        return 0

    if args.keys_command == "unset":
        save_key(args.source, None)
        console.print(f"[green]removed[/green] {args.source} key from {CONFIG_PATH}")
        return 0

    return 2


def handle_check(args: argparse.Namespace, console: Console) -> int:
    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        console.print(f"[bold red]error:[/bold red] '{args.ip}' is not a valid IP address")
        return 2

    selected = resolve_sources(args.sources, console)
    if selected is None:
        return 2

    config = load_config()
    ctx = build_context(config, force_refresh=args.refresh_lists, timeout=args.timeout)
    results, verdict = run_checks(args.ip, ctx, selected)

    if args.json:
        payload = {"ip": args.ip, "verdict": asdict(verdict), "sources": [asdict(r) for r in results]}
        print(json.dumps(payload, indent=2, default=str))
    else:
        report.render(args.ip, results, verdict, console)

    return 0


def _read_ips(path: str, err_console: Console) -> tuple[list[str], int]:
    """Parse one IP per line (blank/'#' lines skipped, duplicates deduped,
    input order preserved). Returns (ips, count_of_invalid_lines_skipped)."""
    if path == "-":
        raw_lines = sys.stdin.read().splitlines()
    else:
        try:
            raw_lines = Path(path).read_text().splitlines()
        except OSError as e:
            err_console.print(f"[bold red]error:[/bold red] could not read {path}: {e}")
            return [], 0

    seen: set[str] = set()
    ips: list[str] = []
    invalid = 0
    for raw in raw_lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            invalid += 1
            continue
        if line not in seen:
            seen.add(line)
            ips.append(line)
    return ips, invalid


def handle_batch(args: argparse.Namespace, console: Console) -> int:
    err_console = Console(stderr=True)

    ips, invalid_count = _read_ips(args.file, err_console)
    if invalid_count:
        err_console.print(f"[yellow]skipped {invalid_count} invalid/unparseable line(s)[/yellow]")
    if not ips:
        err_console.print("[bold red]error:[/bold red] no valid IP addresses found in input")
        return 2

    selected = resolve_sources(args.sources, err_console)
    if selected is None:
        return 2

    config = load_config()
    ctx = build_context(config, force_refresh=args.refresh_lists, timeout=args.timeout)

    err_console.print(f"Checking {len(ips)} IP(s) across {len(selected)} source(s), {args.parallel} at a time...")
    order = {ip: i for i, ip in enumerate(ips)}
    rows: list[tuple[str, list[SourceResult], Verdict]] = [None] * len(ips)  # type: ignore[list-item]
    completed = 0
    with ThreadPoolExecutor(max_workers=max(args.parallel, 1)) as pool:
        futures = {pool.submit(run_checks, ip, ctx, selected): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            results, verdict = fut.result()
            rows[order[ip]] = (ip, results, verdict)
            completed += 1
            style = report.VERDICT_STYLE.get(verdict.label, "white")
            err_console.print(f"  [{completed}/{len(ips)}] {ip}: [{style}]{verdict.label}[/{style}]")

    out_fh = open(args.output, "w", newline="") if args.output else sys.stdout
    try:
        if args.json:
            payload = [
                {"ip": ip, "verdict": asdict(verdict), "sources": [asdict(r) for r in results]}
                for ip, results, verdict in rows
            ]
            json.dump(payload, out_fh, indent=2, default=str)
            out_fh.write("\n")
        elif args.csv:
            writer = csv.writer(out_fh)
            writer.writerow(["ip", "verdict", "score", "sources_ok", "sources_total", "flagged_by"])
            for ip, _results, verdict in rows:
                writer.writerow([ip, verdict.label, verdict.score, verdict.sources_ok, verdict.sources_total, ";".join(verdict.contributing)])
        else:
            table = Table(title=f"iprep batch report ({len(rows)} IPs)")
            table.add_column("IP")
            table.add_column("Verdict")
            table.add_column("Score")
            table.add_column("Sources")
            table.add_column("Flagged by")
            for ip, _results, verdict in rows:
                style = report.VERDICT_STYLE.get(verdict.label, "white")
                table.add_row(ip, f"[{style}]{verdict.label}[/{style}]", f"{verdict.score:.0f}", f"{verdict.sources_ok}/{verdict.sources_total}", ", ".join(verdict.contributing) or "-")
            out = Console(file=out_fh) if args.output else console
            out.print(table)
    finally:
        if args.output:
            out_fh.close()

    counts: dict[str, int] = {}
    for _ip, _results, verdict in rows:
        counts[verdict.label] = counts.get(verdict.label, 0) + 1
    summary = ", ".join(f"{n} {label}" for label, n in counts.items())
    err_console.print(f"\nDone: {summary}")

    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(_normalize_argv(argv))
    console = Console()

    if args.command == "keys":
        return handle_keys(args, console)
    if args.command == "batch":
        return handle_batch(args, console)
    return handle_check(args, console)


if __name__ == "__main__":
    sys.exit(main())
