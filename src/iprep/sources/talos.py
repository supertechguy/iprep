from __future__ import annotations

from ..base import SourceResult
from ..context import Context
from ..netutil import ip_version
from ._listutil import fetch_ip_set

# Cisco Talos does not publish a public REST API; their web reputation lookup
# (talosintelligence.com/reputation_center) is a JS-rendered page not meant
# for scraping. Instead we use the Talos-curated Snort "Sample IP Block
# List" feed, the same data source Snort/Suricata deployments pull from.
# Confirmed IPv4-only, and (per Snort's own blog, Sept 2024) always was just
# a small sample - "less than 1% of the IP Block List maintained by the
# Talos team" - not the full thing.
#
# Since that same Sept 2024 change, the download page requires signing in
# and clicking through their terms before it'll serve the real file - an
# unauthenticated fetch gets an HTML "accept the terms" page back instead
# (caught by the cache's content validation, so it fails loudly rather than
# being mistaken for an empty/clean list). There's no API-key/oinkcode
# mechanism for this specific resource (oinkcodes are for authenticated
# rule-package downloads only) - the only way to actually fetch this
# programmatically is a browser session cookie, which you have to obtain
# and refresh yourself:
#   1. Sign in (free account) at https://snort.org and open
#      https://snort.org/downloads/ip-block-list, accepting the terms.
#   2. In your browser devtools' Network tab, find that page's request and
#      copy its full `Cookie:` header value.
#   3. `iprep keys set talos` and paste it in.
# That cookie will expire eventually (Snort doesn't publish a lifetime) -
# when it does, this source goes back to failing until you refresh it.
FEED_URL = "https://snort.org/downloads/ip-block-list"
CACHE_NAME = "talos_ip_blacklist.txt"
CACHE_TTL = 6 * 3600  # feed updates roughly hourly upstream; 6h local TTL is plenty
SETUP_HINT = (
    "Requires a snort.org account: sign in, accept the terms at "
    "https://snort.org/downloads/ip-block-list, copy that request's Cookie header "
    "from your browser devtools, then run `iprep keys set talos` (expires "
    "periodically and will need refreshing)."
)


def check(ip: str, ctx: Context) -> SourceResult:
    if ip_version(ip) == 6:
        return SourceResult(name="Talos", ok=True, verdict="unknown", score=None, summary="Talos/Snort blacklist feed is IPv4-only")

    cookie = ctx.config.talos_cookie
    headers = {"Cookie": cookie} if cookie else None

    try:
        ips = fetch_ip_set(ctx, CACHE_NAME, FEED_URL, CACHE_TTL, headers=headers)
    except Exception as e:
        summary = "could not fetch Talos/Snort blacklist feed" if cookie else SETUP_HINT
        return SourceResult(name="Talos", ok=False, error=str(e), summary=summary)

    hit = ip in ips

    return SourceResult(
        name="Talos",
        ok=True,
        verdict="malicious" if hit else "clean",
        score=100.0 if hit else 0.0,
        summary="present on Talos/Snort IP blacklist" if hit else "not on Talos/Snort IP blacklist",
        details={"list_size": len(ips), "link": "https://talosintelligence.com/reputation_center"},
    )
