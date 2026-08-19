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

# source slug (used by `iprep keys ...`) -> (Config field name, env var name, TOML key name)
KEY_SPECS: dict[str, tuple[str, str, str]] = {
    "virustotal": ("vt_api_key", "VT_API_KEY", "virustotal"),
    "abuseipdb": ("abuseipdb_api_key", "ABUSEIPDB_API_KEY", "abuseipdb"),
    "shodan": ("shodan_api_key", "SHODAN_API_KEY", "shodan"),
    "greynoise": ("greynoise_api_key", "GREYNOISE_API_KEY", "greynoise"),
    "spamhaus_dqs": ("spamhaus_dqs_key", "SPAMHAUS_DQS_KEY", "spamhaus_dqs"),
    "otx": ("otx_api_key", "OTX_API_KEY", "otx"),
    "threatfox": ("threatfox_api_key", "THREATFOX_API_KEY", "threatfox"),
    "crowdsec": ("crowdsec_api_key", "CROWDSEC_API_KEY", "crowdsec"),
}
KNOWN_SOURCES = list(KEY_SPECS)


@dataclass
class Config:
    vt_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    shodan_api_key: str | None = None
    greynoise_api_key: str | None = None
    spamhaus_dqs_key: str | None = None
    otx_api_key: str | None = None
    threatfox_api_key: str | None = None
    crowdsec_api_key: str | None = None


def _read_toml_keys() -> dict[str, str]:
    if tomllib and CONFIG_PATH.exists():
        with open(CONFIG_PATH, "rb") as f:
            data = tomllib.load(f)
        return data.get("keys", {})
    return {}


def load_config() -> Config:
    """Env vars win; ~/.config/iprep/config.toml (managed by `iprep keys`) is the fallback.

    This file lives under the user's home directory, entirely outside any git
    repository, so keys stored there can never end up committed alongside
    the project source.
    """
    file_keys = _read_toml_keys()
    values = {}
    for field_name, env_name, toml_name in KEY_SPECS.values():
        values[field_name] = os.environ.get(env_name) or file_keys.get(toml_name) or None
    return Config(**values)


def key_origin(source: str) -> str | None:
    """Where a key's active value currently comes from: 'env', 'file', or None."""
    field_name, env_name, toml_name = KEY_SPECS[source]
    if os.environ.get(env_name):
        return "env"
    if _read_toml_keys().get(toml_name):
        return "file"
    return None


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def save_key(source: str, value: str | None) -> None:
    """Add/update (or remove, if value is None/empty) one key in
    ~/.config/iprep/config.toml, leaving any other stored keys untouched.

    Only ever writes to CONFIG_PATH - never touches anything inside the repo.
    """
    if source not in KEY_SPECS:
        raise ValueError(f"unknown source: {source}")

    file_keys = _read_toml_keys()
    _, _, toml_name = KEY_SPECS[source]
    if value:
        file_keys[toml_name] = value
    else:
        file_keys.pop(toml_name, None)

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_PATH.parent.chmod(0o700)
    except OSError:
        pass

    lines = [
        "# iprep API keys - managed via `iprep keys set` / `iprep keys unset`.",
        "# This file lives outside the git repo and is never committed.",
        "",
        "[keys]",
    ]
    for _, _, name in KEY_SPECS.values():
        v = file_keys.get(name, "")
        escaped = v.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{name} = "{escaped}"')

    CONFIG_PATH.write_text("\n".join(lines) + "\n")
    CONFIG_PATH.chmod(0o600)
