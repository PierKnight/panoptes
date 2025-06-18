from pathlib import Path
import json
import subprocess
from datetime import datetime
from importlib import metadata
from ..utils.misc import get_field_name_from_service_dir_name, image_to_base64

from panoptes.utils import logging

from panoptes.ingestion.imgbb import ImgBB

log = logging.get(__name__)

PKG_VERSION = metadata.version("panoptes")

def build(workspace: Path, **kwargs) -> dict:
    # Note: if a key is changed here, it must also be changed in the get_field_name_from_service_dir_name function
    ctx = {
        "domain": workspace.name,
        "run_datetime": str(datetime.now()),
        "git_sha": subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip(),
        "header_analysis": {},      # Custom-made
        "dmarc": [],                # MXToolbox
        "spf": [],                  # MXToolbox
        "dns_records": {},          # DNSDumpster
        "ssl_check": {},            # SSLShopper
        "tech_stack": {},           # Wappalyzer
        "subdomains_ips": {},       # C99, VirusTotal, IntelX Phonebook (merged)
        "hosts": {},                # Shodan
        "compromised_ips": {},      # AbuseIPDB
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
                        if file.name.startswith("dmarc") and file.name.endswith(".json"):
                            ctx["dmarc"].append(json.loads(file.read_text()))
                        if file.name.startswith("spf") and file.name.endswith(".json"):
                            ctx["spf"].append(json.loads(file.read_text()))
                        continue

                ctx[field_name] = json.loads(file.read_text())
            
            # Handle specific cases for images
            if service_dir.name == "mxtoolbox":
                for image_file in service_dir.glob("*.png"):
                    if image_file.name.startswith("dmarc"):
                        image_field_name = "dmarc"
                    elif image_file.name.startswith("spf"):
                        image_field_name = "spf"
                    imgbb_api_key = kwargs.get("imgbb_api_key", None)
                    if not imgbb_api_key:
                        log.warning("No ImgBB API key provided, skipping image upload.")
                        continue
                    image_url = ImgBB(imgbb_api_key).upload_image(str(image_file), name=image_file.name)
                    ctx["images"][image_field_name] = image_url
            elif service_dir.name == "sslshopper":
                for image_file in service_dir.glob("*.png"):
                    ctx["images"]["ssl_check"] = image_to_base64(str(image_file))
    
    # Delete empty fields
    ctx = {k: v for k, v in ctx.items() if v not in [None, {}, ""]}

    return ctx