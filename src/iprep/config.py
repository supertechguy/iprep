from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None

CONFIG_PATH = Path(
    os.environ.get("IPREP_CONFIG", Path.home() / ".config" / "iprep" / "config.toml")
)


@dataclass
class Config:
    vt_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    shodan_api_key: str | None = None
    greynoise_api_key: str | None = None
    spamhaus_dqs_key: str | None = None


def load_config() -> Config:
    """Env vars win; ~/.config/iprep/config.toml (a [keys] table) is the fallback."""
    file_keys: dict[str, str] = {}
    if tomllib and CONFIG_PATH.exists():
        with open(CONFIG_PATH, "rb") as f:
            data = tomllib.load(f)
        file_keys = data.get("keys", {})

    def get(env_name: str, toml_name: str) -> str | None:
        return os.environ.get(env_name) or file_keys.get(toml_name)

    return Config(
        vt_api_key=get("VT_API_KEY", "virustotal"),
        abuseipdb_api_key=get("ABUSEIPDB_API_KEY", "abuseipdb"),
        shodan_api_key=get("SHODAN_API_KEY", "shodan"),
        greynoise_api_key=get("GREYNOISE_API_KEY", "greynoise"),
        spamhaus_dqs_key=get("SPAMHAUS_DQS_KEY", "spamhaus_dqs"),
    )
