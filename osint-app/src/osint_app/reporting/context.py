from pathlib import Path
import json
import subprocess
from datetime import datetime
from importlib import metadata
from ..utils.misc import get_field_name_from_service_dir_name, image_to_base64

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
        "images": {},               # Images from service directories
    }

    for service_dir in workspace.iterdir():
        if service_dir.is_dir():
            field_name = get_field_name_from_service_dir_name(service_dir.name)
    
            # Get all JSON files in the service directory
            for file in service_dir.glob("*.json"):
                if file:
                    if field_name == "mxtoolbox":
                        # Special case for MXToolbox, which has multiple fields
                        if file.name == "dmarc.json":
                            ctx["dmarc"] = json.loads(file.read_text())
                        elif file.name == "spf.json":
                            ctx["spf"] = json.loads(file.read_text())
                        continue

                ctx[field_name] = json.loads(file.read_text())
            
            # Handle specific cases for images
            if service_dir.name == "mxtoolbox":
                for image_file in service_dir.glob("*.png"):
                    if image_file.name.startswith("dmarc"):
                        image_field_name = "dmarc"
                    elif image_file.name.startswith("spf"):
                        image_field_name = "spf"
                    #ctx["images"][image_field_name] = image_file.absolute().as_posix()
                    ctx["images"][image_field_name] = image_to_base64(str(image_file))
            elif service_dir.name == "sslshopper":
                for image_file in service_dir.glob("*.png"):
                    #ctx["images"]["ssl_check"] = image_file.absolute().as_posix()
                    ctx["images"]["ssl_check"] = image_to_base64(str(image_file))
    return ctx