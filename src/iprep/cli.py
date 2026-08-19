from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from . import report
from .aggregate import aggregate
from .base import SourceResult
from .config import CONFIG_PATH, KEY_SPECS, KNOWN_SOURCES, key_origin, load_config, mask, save_key
from .context import build_context
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
    if not argv or argv[0] in ("check", "keys", "-h", "--help"):
        return argv
    return ["check", *argv]


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

    selected = SOURCE_MODULES
    if args.sources:
        names = [s.strip() for s in args.sources.split(",")]
        unknown = [n for n in names if n not in SOURCE_MODULES]
        if unknown:
            console.print(f"[bold red]error:[/bold red] unknown source(s): {', '.join(unknown)}")
            return 2
        selected = {n: SOURCE_MODULES[n] for n in names}

    config = load_config()
    ctx = build_context(config, force_refresh=args.refresh_lists, timeout=args.timeout)

    results: list[SourceResult] = []
    with ThreadPoolExecutor(max_workers=max(len(selected), 1)) as pool:
        futures = {pool.submit(mod.check, args.ip, ctx): name for name, mod in selected.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(SourceResult(name=name, ok=False, error=str(e), summary="unexpected error"))

    verdict = aggregate(results)

    if args.json:
        payload = {"ip": args.ip, "verdict": asdict(verdict), "sources": [asdict(r) for r in results]}
        print(json.dumps(payload, indent=2, default=str))
    else:
        report.render(args.ip, results, verdict, console)

    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(_normalize_argv(argv))
    console = Console()

    if args.command == "keys":
        return handle_keys(args, console)
    return handle_check(args, console)


if __name__ == "__main__":
    sys.exit(main())
