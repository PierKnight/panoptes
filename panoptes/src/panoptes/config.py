"""
Runtime configuration loader.

Priority:
1. Environment variables       (e.g.  INTELX)
2. ~/.osintapp.yml             (YAML file for defaults)
3. Hard-coded fallbacks
"""
from pathlib import Path
import os
import yaml

_DEFAULTS = {
    "base_dir": "~/osint-data",
    "api_keys": {
        "intelx": "",
        "haveibeenpwned": "",
        "c99": "",
        "virustotal": "",
        "shodan": "",
        "abuseipdb": "",
        "dnsdumpster": "",
        "mxtoolbox": "",
    },
}

def load() -> dict:
    cfg = _DEFAULTS | {}               # shallow copy
    yml_path = Path.home() / ".osintapp.yml"
    if yml_path.exists():
        cfg |= yaml.safe_load(yml_path.read_text()) or {}

    # override by env-vars
    for name in cfg["api_keys"]:
        env_val = os.getenv(name.upper())
        if env_val:
            cfg["api_keys"][name] = env_val

    cfg["base_dir"] = Path(os.path.expanduser(cfg["base_dir"]))
    cfg["base_dir"].mkdir(parents=True, exist_ok=True)

    cfg["email_without_domain_regex"] = r"[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@"
    cfg["haveibeenpwned_request_delay_in_seconds"] = 1.5
    return cfg