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
    "base_dir": "~/panoptes",
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
    "services": {
        "dns-lookup": "Gather DNS records for the domain (via DNSDumpster)",
        "spf-dmarc": "Check SPF and DMARC records (internal logic + MXToolbox)",
        "ssl-check": "Validate SSL certificate chain and info (via SSLShopper)",
        "tech-stack": "Analyze web technologies used by the domain (Wappalyzer)",
        "http-headers": "Check missing HTTP security headers (internal logic)",
        "subdomains": "Enumerate subdomains (using IntelX, VirusTotal, C99)",
        "exposed-ports-cve": "Find open ports and CVEs (Shodan + CVE database); needs subdomains",
        "compromised-hosts": "Check if hosts are blacklisted/abused (AbuseIPDB)",
        "compromised-credentials": "Find leaked credentials (IntelX + Have I Been Pwned)"
    }
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
    cfg["haveibeenpwned_request_delay_in_seconds"] = 1
    return cfg