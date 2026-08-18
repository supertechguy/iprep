# iprep

Command-line IP reputation aggregator. Pulls signal from multiple threat-intel
sources in parallel and gives you one verdict plus the raw detail behind it,
so you can decide whether an IP has actually been used maliciously rather
than trusting a single service's opinion.

```
$ iprep 45.142.212.10
╭──────────────────── iprep report: 45.142.212.10 ────────────────────╮
│ MALICIOUS  risk score: 87.3/100  (5/7 reputation sources responded) │
╰────────────────────────────────────────────────────────────────────╯
                          Reputation sources
┏━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Source     ┃ Verdict   ┃ Score ┃ Summary                              ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ VirusTotal │ malicious │ 92    │ 12/94 engines flag malicious...      │
│ AbuseIPDB  │ malicious │ 100   │ abuse confidence 100%, 812 reports.. │
│ ...        │ ...       │ ...   │ ...                                   │
└────────────┴───────────┴───────┴───────────────────────────────────────┘
```

## Sources

| Source | What it gives you | Key required |
|---|---|---|
| **VirusTotal** | Multi-engine malicious/suspicious verdicts, reputation score, tags | Yes (free tier) |
| **AbuseIPDB** | Crowdsourced abuse confidence score, report count, ISP/usage type | Yes (free tier) |
| **Shodan** | Open ports, banners, known CVEs, risky tags (c2/honeypot/botnet) | Yes (paid-ish) |
| **Talos** | Membership on the Cisco Talos/Snort curated IP blocklist feed | No |
| **Spamhaus** | ZEN DNSBL lookup (SBL/XBL/CSS/DROP = abuse; PBL = policy-only, scored lower) | No |
| **FireHOL** | Membership on `firehol_level1/2/3` aggregate blocklists (CIDR-aware) | No |
| **GreyNoise** | Internet-scanner vs. targeted-attacker classification, RIOT (known-benign service) tagging | Optional (free tier) |
| **RDAP/Whois** | Org, network name, country, abuse contact — via `rdap.org` (structured, no legacy whois parsing) | No |
| **ASN** | Announcing AS number/name and BGP prefix, via Team Cymru's DNS service | No |
| **Reverse DNS** | PTR record + forward-confirmation | No |
| **Tor** | Whether the IP is a known Tor exit node | No |

**Why no Talos API integration?** Cisco Talos doesn't publish a public REST
API — their web reputation lookup is a JS-rendered page not meant for
scraping. Instead `iprep` uses the same curated IP blocklist feed that
Snort/Suricata deployments consume, which is Talos-maintained data without
the scraping fragility.

Reputation sources feed the aggregate score/verdict; context sources
(RDAP, ASN, reverse DNS, Tor) are shown for enrichment only and don't move
the needle — they help you interpret *why* something looks the way it does
(e.g. "malicious per AbuseIPDB, and it's a residential ISP in a country
you don't do business with" vs. "malicious per AbuseIPDB, but it's inside
a well-known cloud provider's range").

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

This installs an `iprep` command (see `pyproject.toml`'s `[project.scripts]`).

## API keys

None are required to run the tool — sources without a configured key report
`n/a` with a link to sign up, and the verdict is computed from whatever did
respond.

**Add keys with the built-in `iprep keys` command** — it writes to
`~/.config/iprep/config.toml` (owner-only permissions, `0600`), which lives
under your home directory and is never part of this git repo, so keys never
end up committed or pushed:

```bash
iprep keys set virustotal          # prompts for the key with hidden input
iprep keys set abuseipdb <key>     # or pass it directly as an argument
iprep keys show                    # list what's configured (values masked)
iprep keys unset shodan            # remove a stored key
iprep keys path                    # print the config file location
```

Sign up for keys here:

- `virustotal` — https://www.virustotal.com/gui/join-us (free, 4 req/min / 500 per day)
- `abuseipdb` — https://www.abuseipdb.com/register (free, 1000 checks/day)
- `shodan` — https://account.shodan.io/register (paid, "Freelancer" tier is ~$1/mo)
- `greynoise` — https://viz.greynoise.io/signup (free community tier, optional but recommended)
- `spamhaus_dqs` — optional, only needed if you outgrow the free public DNSBL mirror's low-volume usage policy

Environment variables (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`,
`GREYNOISE_API_KEY`, `SPAMHAUS_DQS_KEY`) still work too and take precedence
over the config file — handy for CI or if you'd rather manage secrets in a
password manager/secret store than on disk. `config.toml.example` in this
repo is just a template for reference; it holds no real keys and is safe to
commit.

## Usage

```bash
iprep 1.2.3.4                       # full report (shorthand for `iprep check 1.2.3.4`)
iprep 1.2.3.4 --json                # machine-readable output for scripting
iprep 1.2.3.4 --sources virustotal,abuseipdb,spamhaus   # only query specific sources
iprep 1.2.3.4 --refresh-lists       # force re-download of cached blocklists
iprep keys set virustotal           # add an API key (see "API keys" above)
```

FireHOL/Talos/Tor lists are cached under `~/.cache/iprep/` (TTLs: FireHOL 24h,
Talos 6h, Tor 1h) so repeated lookups don't re-download multi-MB lists every
time.

## How the verdict is computed

Each reputation source returns a 0-100 "how bad does this look" score and a
verdict (`malicious`/`suspicious`/`clean`/`unknown`). `iprep` takes a
confidence-weighted average across whatever sources actually responded
(`src/iprep/aggregate.py`), then applies one override: a single
high-confidence hit (VirusTotal, AbuseIPDB, Spamhaus abuse listing, Talos, or
a `firehol_level1` hit) is enough to call the overall verdict `malicious`
outright, even if it gets diluted in the weighted average by quieter sources.

This is a starting heuristic, not a scientifically tuned model — the weights
in `aggregate.py` are easy to adjust once you see how it behaves against IPs
you already have ground truth on.

## Suggestions / natural next additions

Roughly in order of value if you want to extend this:

1. **Historical/temporal context.** Right now every source is a point-in-time
   snapshot. AbuseIPDB and VirusTotal both include "first seen"/"last
   reported" timestamps already surfaced in `details` — worth promoting into
   the headline report (an IP maliciously active yesterday is a different
   story than one whose worst report was 3 years ago).
2. **Cloud-provider range tagging.** Cross-reference against AWS/GCP/Azure/
   Cloudflare/DigitalOcean published IP ranges. Traffic from a major cloud
   provider changes how you weigh everything else (ephemeral attacker
   infrastructure vs. a CDN edge node) and is a cheap, no-key addition.
3. **AlienVault OTX** — free API key, pulse data (which threat campaigns/IOC
   lists reference this IP), good complement to VT/AbuseIPDB.
4. **A `batch` mode** reading a file of IPs (e.g. from firewall/IDS logs) and
   emitting a CSV/JSON summary — the architecture already supports this
   cleanly since `check(ip, ctx)` is stateless per-IP; you'd just loop and
   reuse one `Context` (and therefore one warm blocklist cache) across all of
   them.
5. **CIDR/subnet rollup.** If you're investigating an incident, seeing "this
   /24 has 6 other IPs also flagged in the last 90 days" is often more
   actionable than any single-IP verdict.
6. **Local result caching with a short TTL** (minutes, not hours) so
   re-running `iprep` on the same IP a few times while investigating doesn't
   burn API quota — separate from the long-TTL blocklist cache that already
   exists.
7. **IPv6 support.** Spamhaus, ASN (Cymru), and Tor sources here are IPv4-only
   as written; VirusTotal/AbuseIPDB/Shodan/RDAP/FireHOL already handle IPv6
   fine. Worth closing that gap if you deal with v6 traffic.

## Project layout

```
src/iprep/
  base.py        SourceResult - the normalized shape every source returns
  config.py      API key loading (env vars + optional TOML config)
  cache.py       disk cache for the blocklist-style feeds
  context.py     shared HTTP session / DNS resolver / cache handed to sources
  aggregate.py   combines all SourceResults into one Verdict
  report.py      rich terminal rendering
  cli.py         argument parsing, parallel dispatch, JSON output
  sources/       one module per source, each exposing check(ip, ctx) -> SourceResult
```

Adding a new source is just: write a module with a `check(ip, ctx)` function
returning a `SourceResult`, register it in `SOURCE_MODULES` in `cli.py`, and
(if it should affect the verdict) add a weight for it in `aggregate.py`.
