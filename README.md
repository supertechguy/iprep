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

| Source | What it gives you | Key required | IPv6 |
|---|---|---|---|
| **VirusTotal** | Multi-engine malicious/suspicious verdicts, reputation score, tags | Yes (free tier) | Yes |
| **AbuseIPDB** | Crowdsourced abuse confidence score, report count, ISP/usage type | Yes (free tier) | Yes |
| **Shodan** | Open ports, banners, known CVEs, risky tags (c2/honeypot/botnet) | Yes (paid-ish) | Yes |
| **Talos** | Membership on the Cisco Talos/Snort curated IP blocklist feed | No | No (feed is IPv4-only) |
| **Spamhaus** | ZEN DNSBL lookup (SBL/XBL/CSS/DROP = abuse; PBL = policy-only, scored lower) | No | Yes* |
| **FireHOL** | Membership on `firehol_level1/2/3` aggregate blocklists (CIDR-aware) | No | No (aggregates are IPv4-only) |
| **CINS Army** | Membership on the CI Army "bad guys" list (long-established, Snort/Suricata community) | No | No (feed is IPv4-only) |
| **Blocklist.de** | Crowdsourced fail2ban-style abuse reports (SSH/mail/web bruteforce) | No | Yes |
| **ipsum** | How many distinct public blocklists (of dozens aggregated) flag this IP | No | No (feed is IPv4-only) |
| **Emerging Threats** | Membership on Proofpoint/ET's open compromised-hosts feed | No | No (feed is IPv4-only) |
| **Feodo Tracker** | Membership on abuse.ch's small, tightly-scoped active botnet C2 server list | No | No (feed is IPv4-only) |
| **Barracuda RBL** | Barracuda Reputation Block List DNSBL lookup | No | No (unconfirmed, skipped to avoid a false clean) |
| **DShield** | Whether the IP falls in SANS ISC's top ~20 currently-attacking /24 netblocks | No | No (feed is IPv4-only) |
| **Binary Defense** | Membership on Binary Defense's honeypot-derived banlist | No | No (feed is IPv4-only) |
| **AlienVault OTX** | How many threat-intel "pulses" (curated IOC collections) reference this IP, and their names | No (works unauthenticated; optional free key raises rate limit) | Yes |
| **ThreatFox** | abuse.ch malware IOC match — malware family, threat type, confidence level | Yes (free, instant signup) | Unverified |
| **CrowdSec CTI** | Crowd-sourced reputation/confidence/behaviors from CrowdSec's sensor network | Yes (free, 120 lookups/month) | Unverified |
| **GreyNoise** | Internet-scanner vs. targeted-attacker classification, RIOT (known-benign service) tagging | Optional (free tier) | Unverified |
| **RDAP/Whois** | Org, network name, country, abuse contact — via `rdap.org` (structured, no legacy whois parsing) | No | Yes |
| **ASN** | Announcing AS number/name and BGP prefix, via Team Cymru's DNS service | No | Yes |
| **Reverse DNS** | PTR record + forward-confirmation (AAAA-aware) | No | Yes |
| **Tor** | Whether the IP is a known Tor exit node | No | No (feed is IPv4-only) |
| **VPN/Proxy** | Whether the IP is a known commercial VPN exit, or broader datacenter/hosting space | No | Yes |

\* Spamhaus IPv6 ZEN lookups work (verified live) but aren't documented on
their free public-mirror FAQ the way the IPv4 syntax is — `iprep` flags this
in the summary so you can weigh it accordingly.

**Not included: SSLBL.** abuse.ch's SSL-certificate-based IP blocklist looked
like an easy companion to Feodo Tracker, but it turned out to have been
deprecated by abuse.ch on 2025-01-03 (the feed URL still returns 200 but is
empty) — not worth wiring up.

Every source that can't cover an address family reports that plainly
(`verdict: unknown`, e.g. "FireHOL level1-3 aggregates are IPv4-only")
instead of silently guessing — a source with no opinion is not the same
thing as a source that checked and found nothing.

**Why no Talos API integration?** Cisco Talos doesn't publish a public REST
API — their web reputation lookup is a JS-rendered page not meant for
scraping. Instead `iprep` uses the same curated IP blocklist feed that
Snort/Suricata deployments consume, which is Talos-maintained data without
the scraping fragility.

**Why is VPN/Proxy just informational?** Using a VPN isn't evidence of
malice by itself (same reasoning as the Tor check) — it's shown so you can
factor it into your own judgment call, but it doesn't move the aggregate
score. Detection comes from [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn),
a community-maintained, regularly-updated range list with two tiers: a
strict "vpn" list (known commercial VPN provider ranges) and a broader
"datacenter" list (also covers general hosting/cloud/proxy infrastructure —
useful for "this isn't a residential connection" but plenty of datacenter
IPs are ordinary cloud servers, not VPN exits).

Reputation sources feed the aggregate score/verdict; context sources
(RDAP, ASN, reverse DNS, Tor, VPN/Proxy) are shown for enrichment only and
don't move the needle — they help you interpret *why* something looks the
way it does (e.g. "malicious per AbuseIPDB, and it's a residential ISP in a
country you don't do business with" vs. "malicious per AbuseIPDB, but it's
inside a well-known cloud provider's range").

## Install

```bash
./install.sh
```

By default this installs `iprep` globally via [pipx](https://pipx.pypa.io/)
(isolated from your system Python, `iprep` ends up on your `PATH`), offering
to install pipx first if you don't have it. Flags:

- `./install.sh --pipx` — force the pipx path (errors if pipx isn't present)
- `./install.sh --venv` — install into a local `.venv/` in this repo instead
  (you'll `source .venv/bin/activate` before running `iprep`)
- `./install.sh --yes` — non-interactive; auto-accepts installing pipx if missing

Or do it by hand:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Either way this installs an `iprep` command (see `pyproject.toml`'s
`[project.scripts]`).

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
- `otx` — https://otx.alienvault.com/ (optional — OTX already works with no key; a free key just raises the rate limit)
- `threatfox` — https://auth.abuse.ch/ (free, instant signup via GitHub/Google/etc, no approval wait)
- `crowdsec` — https://app.crowdsec.net (free, 120 lookups/month)

If VirusTotal's free tier (500/day, 4/min) is too tight for how often you
check IPs, most of the sources above need no key at all, and OTX/ThreatFox
both have generous or nonexistent free-tier limits — `--sources` lets you
build a check that leans on those instead of the tightly-quota'd ones.

Environment variables (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`,
`GREYNOISE_API_KEY`, `SPAMHAUS_DQS_KEY`, `OTX_API_KEY`, `THREATFOX_API_KEY`,
`CROWDSEC_API_KEY`) still work too and take precedence over the config file
— handy for CI or if you'd rather manage secrets in a password
manager/secret store than on disk. `config.toml.example` in this
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

### Batch mode

Check every IP in a file (e.g. pulled from firewall/IDS logs) in one go:

```bash
iprep batch ips.txt                        # summary table, one row per IP
iprep batch ips.txt --csv -o results.csv    # ip,verdict,score,sources_ok,sources_total,flagged_by
iprep batch ips.txt --json -o results.json  # full per-source detail for every IP
grep 'DENY' firewall.log | awk '{print $5}' | iprep batch -   # pipe IPs in via stdin ("-")
```

`ips.txt` is one IP (v4 or v6) per line; blank lines and `#`-comments are
skipped, duplicates are deduped, and unparseable lines are skipped with a
warning rather than aborting the whole run. IPs are checked `--parallel`
at a time (default 4, each still fanning out across all its sources
concurrently, same as single-IP mode) and reuse one warm blocklist cache
across the whole file. Progress and the final tally print to stderr, so
stdout stays clean for `--json`/`--csv` piping.

If you have low-quota keyed sources configured (VirusTotal's free tier is
4 requests/minute), either lower `--parallel`, or restrict a large batch run
to the no-key sources with `--sources`.

All the blocklist/list-based feeds (FireHOL, Talos, CINS Army, Blocklist.de,
ipsum, Emerging Threats, Feodo Tracker, DShield, Binary Defense, Tor,
VPN/Proxy) are cached under `~/.cache/iprep/` (TTLs range from 1h to 24h
depending on how often the upstream feed updates)
so repeated lookups don't re-download multi-MB lists every time. Fetched
content is sanity-checked before being cached — if an upstream feed starts
returning an HTML error/bot-challenge page instead of its usual plaintext
list, `iprep` treats that as a failed fetch (and falls back to the last good
cached copy) rather than silently caching garbage and reporting false
"clean" verdicts.

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
2. **CIDR/subnet rollup.** If you're investigating an incident, seeing "this
   /24 has 6 other IPs also flagged in the last 90 days" is often more
   actionable than any single-IP verdict. (`iprep batch` gets you partway
   there today if you already have the candidate IP list.)
3. **Local result caching with a short TTL** (minutes, not hours) so
   re-running `iprep` on the same IP a few times while investigating doesn't
   burn API quota — separate from the long-TTL blocklist cache that already
   exists.
4. **Full IPv6 parity.** Talos, FireHOL, CINS Army, ipsum, Emerging Threats,
   and the Tor exit list are IPv4-only at the source (confirmed against the
   live feeds) — no fix on `iprep`'s end will close that, short of finding
   IPv6-native replacements for each. Spamhaus, ASN, RDAP, reverse DNS,
   Blocklist.de, and VPN/Proxy detection already fully support IPv6.

## Project layout

```
src/iprep/
  base.py        SourceResult - the normalized shape every source returns
  config.py      API key loading/storage (env vars + `iprep keys`-managed TOML config)
  cache.py       disk cache for the blocklist-style feeds, with fetch validation
  netutil.py     shared IPv4/IPv6 helpers (version detection, DNSBL query building)
  context.py     shared HTTP session / DNS resolver / cache handed to sources
  aggregate.py   combines all SourceResults into one Verdict
  report.py      rich terminal rendering
  cli.py         argument parsing, parallel dispatch, JSON output
  sources/       one module per source, each exposing check(ip, ctx) -> SourceResult
    _listutil.py   shared helper for the simple "fetch a plaintext IP list" sources
```

Adding a new source is just: write a module with a `check(ip, ctx)` function
returning a `SourceResult`, register it in `SOURCE_MODULES` in `cli.py`, and
(if it should affect the verdict) add a weight for it in `aggregate.py`.
