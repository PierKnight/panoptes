from pathlib import Path
import json
import subprocess
from datetime import datetime
from importlib import metadata

PKG_VERSION = metadata.version("osint_app")

def build(workspace: Path) -> dict:
    ctx = {
        "domain": workspace.name,
        "run_datetime": datetime.now().isoformat(timespec="seconds") + "Z",
        "git_sha": subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip(),
        "header_analysis": {},      # Custom-made
        "dmarc": {},                # MXToolbox
        "spf": {},                  # MXToolbox
        "dns_records": {},          # DNSDumpster
        "ssl_check": {},            # SSLShopper
        "web_technologies": {},     # Wappalyzer
        "subdomains_ips": {},       # C99, VirusTotal, IntelX Phonebook (merged)
        "hosts": {},                # Shodan
        "providers": {},            # TODO: Check if we already have this
        "compromised_hosts": {},    # AbuseIPDB
        "leaked_credentials": {},   # IntelX
        "data_breaches": {},        # HaveIBeenPwned
    }

    for service_dir in workspace.iterdir():
        if service_dir.is_dir():
            for file in service_dir.glob("*.json"):
                if file:
                    if service_dir.name == "abuseipdb":
                        field_name = "compromised_hosts"
                    elif service_dir.name == "dnsdumpster":
                        field_name = "dns_records"
                    elif service_dir.name == "haveibeenpwned":
                        field_name = "data_breaches"
                    elif service_dir.name == "httpsecurityheaders":
                        field_name = "header_analysis"
                    elif service_dir.name == "intelx":
                        field_name = "leaked_credentials"
                    elif service_dir.name == "mxtoolbox":
                        if "dmarc" in file.name:
                            field_name = "dmarc"
                        elif "spf" in file.name:
                            field_name = "spf"
                        else:
                            continue
                    elif service_dir.name == "shodan":
                        field_name = "hosts"
                    elif service_dir.name == "sslshopper":
                        field_name = "ssl_check"
                    elif service_dir.name == "subdomains":
                        field_name = "subdomains_ips"
                    elif service_dir.name == "wappalyzer":
                        field_name = "web_technologies"

                ctx[field_name] = json.loads(file.read_text())
    return ctx