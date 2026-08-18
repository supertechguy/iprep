from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

from rich.console import Console

from . import report
from .aggregate import aggregate
from .base import SourceResult
from .config import load_config
from .context import build_context
from .sources import abuseipdb, asn, firehol, greynoise, rdap, shodan, spamhaus, talos, tor
from .sources import dns as dns_source
from .sources import virustotal

SOURCE_MODULES = {
    "vt": virustotal,
    "abuseipdb": abuseipdb,
    "shodan": shodan,
    "talos": talos,
    "spamhaus": spamhaus,
    "firehol": firehol,
    "rdap": rdap,
    "asn": asn,
    "dns": dns_source,
    "tor": tor,
    "greynoise": greynoise,
}


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="iprep", description="Aggregate IP reputation across multiple threat-intel sources."
    )
    p.add_argument("ip", help="IPv4 (or IPv6, for supported sources) address to check")
    p.add_argument("--json", action="store_true", help="output machine-readable JSON instead of a formatted report")
    p.add_argument("--sources", help="comma-separated subset of sources to query: " + ",".join(SOURCE_MODULES))
    p.add_argument("--refresh-lists", action="store_true", help="force re-download of cached blocklists (FireHOL/Talos/Tor)")
    p.add_argument("--timeout", type=float, default=15.0, help="per-source request timeout in seconds (default 15)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    console = Console()

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


if __name__ == "__main__":
    sys.exit(main())
