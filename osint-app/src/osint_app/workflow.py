"""
High-level orchestration for a single OSINT investigation.

Called by the CLI:
    $ osint collect example.com --mail-domain example.com
"""

from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List

from osint_app.persistence.paths import Workspace
from osint_app.ingestion import get_client
from osint_app.processing import grooming
from osint_app.utils import logging
from osint_app.utils.misc import *

import os

import json

import wappalyzer

import shutil

import time

log = logging.get(__name__)

DEFAULT_SERVICES = [
    "intelx",
    "shodan",
    "wappalyzer",
    "mxtoolbox",
    "dnsdumpster",
    "httpsecurityheaders",
    "sslshopper",
    "haveibeenpwned",
    "abuseipdb",
    "virustotal",
    # add/remove as you wire them
]

INTELX_BUCKETS = [
    "pastes",
    "darknet.tor",
    "darknet.i2p",
    "whois",
    "usenet",
    "leaks.private.general",
    "leaks.private.comb",
    "leaks.logs",
    "leaks.public.wikileaks",
    "leaks.public.general",
    "dumpster",
    "documents.public.scihub"
]


def run(cfg: Dict[str, Any], domain: str, mail_domain: str | None) -> None:
    """Entry point imported by cli.py.

    Args:
        cfg: Dict returned by `osint_app.config.load()`.
        domain: Web-site to analyse, e.g. "example.com".
        mail_domain: Optional e-mail domain used for credential hunting.
    """
    started = datetime.now()
    log.info("Starting investigation for %s", domain)

    # 1) set up workspace on disk
    ws = Workspace(cfg["base_dir"], domain, DEFAULT_SERVICES)

    # 2) instantiate required clients  ----------------------------
    clients = {}
    for name in DEFAULT_SERVICES:
        key = cfg["api_keys"].get(name)
        log.info("Creating client %s with key %s", name, key or "None")
        try:
            # registry returns the class, we instantiate it
            cls = get_client(name)
            clients[name] = cls(api_key=key) if key else cls()  # shodan etc.
        except Exception as exc:                               # noqa: BLE001
            log.error("Cannot create client %s: %s", name, exc)

    # 2.5) Understand which is the actual website URL
    website_url = get_website_url(domain)
    log.info("Website URL is %s", website_url)
    
    # If mail_domain is not provided, we will use the domain as the mail domain
    mail_domain = mail_domain or domain
    log.info("Mail domain is %s", mail_domain)

    # 3) run each service  ---------------------------------------
    
    # --- Wappalyzer Web App Fingerprinting ---------------------------------------------
    results = wappalyzer.analyze(
        url=website_url,
        scan_type='balanced',  # 'fast', 'balanced', or 'full'
        threads=8,
        cookie='sessionid=abc123'
    )

    ws.file("wappalyzer", "results.json").write_text(
        json.dumps(results, indent=2)
    )
    log.info("Wappalyzer results saved to %s", ws.file("wappalyzer", "results.json"))
    

    # --- MXToolbox SPF & DMARC records lookup ---------------------------------
    mxtoolbox = clients.get("mxtoolbox")
    if mxtoolbox:
        spf_info = mxtoolbox.get_action_info_from_domain(domain=domain, action="spf")
        dmarc_info = mxtoolbox.get_action_info_from_domain(domain=domain, action="dmarc")

        clean_spf_info = grooming.get_groomed_mxtoolbox_lookup(spf_info.get("spf_json", {}))
        clean_dmarc_info = grooming.get_groomed_mxtoolbox_lookup(dmarc_info.get("dmarc_json", {}))

        ws.file("mxtoolbox", "spf.json").write_text(
            json.dumps(clean_spf_info, indent=2)
        )
        log.info("DMARC info saved to %s", ws.file("mxtoolbox", "spf.json"))

        ws.file("mxtoolbox", "dmarc.json").write_text(
            json.dumps(clean_dmarc_info, indent=2)
        )
        log.info("DMARC info saved to %s", ws.file("mxtoolbox", "dmarc.json"))

        spf_img = spf_info.get("spf_image")
        if spf_img is not None:
            # Save the image
            spf_img.save(ws.file("mxtoolbox", "spf.png"))
            log.info("SPF image saved to %s", ws.file("mxtoolbox", "spf.png"))

        dmarc_img = dmarc_info.get("dmarc_image")
        if dmarc_img is not None:
            # Save the image
            dmarc_img.save(ws.file("mxtoolbox", "dmarc.png"))
            log.info("DMARC img saved to %s", ws.file("mxtoolbox", "dmarc.png"))


    # --- DNSDumpster DNS records lookup ---------------------------------
    dnsdumpster = clients.get("dnsdumpster")
    if dnsdumpster:
        raw_dns_records = dnsdumpster.get_dns_records_from_domain(domain)
        clean_dns_records = grooming.get_groomed_dnsdumpster_info(raw_dns_records)
        ws.file("dnsdumpster", "dns_records.json").write_text(
            json.dumps(clean_dns_records, indent=2)
        )
        log.info("DNSDumpster results saved to %s", ws.file("dnsdumpster", "dns_records.json"))
    

    # --- HTTP Security Headers Analysis -------------------------------
    http_security_headers = clients.get("httpsecurityheaders")
    if http_security_headers:
        missing_headers_descriptions = http_security_headers.get_missing_security_headers_with_description(website_url)
        if missing_headers_descriptions:
            ws.file("httpsecurityheaders", "missing_headers.json").write_text(
                json.dumps(missing_headers_descriptions, indent=2)
            )
            log.info("HTTP Security Headers results saved to %s", ws.file("httpsecurityheaders", "missing_headers.json"))
    

    # --- SSL Shopper Certificate Chain Analysis ----------------------
    sslshopper = clients.get("sslshopper")
    if sslshopper:
        certificate_info = sslshopper.get_ssl_certificate_info(website_url)

        if "certificate_json" and "certificate_image" in certificate_info:
            # Save the certificate image
            certificate_image = certificate_info["certificate_image"]
            certificate_image.save(ws.file("sslshopper", "certificate_chain.png"))

            # Save the certificate JSON
            ws.file("sslshopper", "certificate_info.json").write_text(
                json.dumps(certificate_info["certificate_json"], indent=2)
            )
    
    
    # --- Subdomains retrieval -----------------------------------
    subdomains = set()

    # C99
    c99 = clients.get("c99")
    if c99:
        c99_subdomains = c99.subdomain_finder(domain)
        subdomains.update(c99_subdomains)
    
    # VirusTotal
    virustotal = clients.get("virustotal")
    if virustotal:
        virustotal_subdomains = virustotal.get_subdomains_list(domain)
        subdomains.update(virustotal_subdomains)

    # IntelX
    intelx = clients.get("intelx")
    if intelx:
        phonebook_result = []
        phonebook_search_id = intelx.phonebook_search(term=domain, target=1)

        if phonebook_search_id:
            phonebook_search_result = intelx.phonebook_search_result(search_id=phonebook_search_id, limit=1000)
            if phonebook_search_result:
                if "selectors" in phonebook_search_result:
                    for entry in phonebook_search_result["selectors"]:
                        if "selectorvalue" in entry:
                            phonebook_result.append(entry["selectorvalue"])
            else:
                log.error("Phonebook search result is None")
        else:
            log.error("Phonebook search ID is None")
        
        if phonebook_result:
            subdomains.update(phonebook_result)
    subdomains = sorted(subdomains)
    log.info("All subdomains found: %s", subdomains)
    subdomains_str = "\n".join(subdomains)
    ws.file("subdomains", "subdomains_list.txt").write_text(subdomains_str)

    if len(subdomains) > 0:
        # --- AbuseIPDB abuse reports ---------------------------------
        subdomains_ips = get_ips_from_hosts(subdomains)
        ws.file("subdomains", "subdomains_ips.json").write_text(
            json.dumps(subdomains_ips, indent=2)
        )
        
        abuseipdb = clients.get("abuseipdb")

        ips = aggregate_values_from_dict_with_no_duplicates(subdomains_ips)

        if abuseipdb:
            abused_ips_reports = abuseipdb.get_abused_ips_reports(ips)
            if len(abused_ips_reports) > 0:
                ws.file("abuseipdb", "abused_ips_reports.json").write_text(
                    json.dumps(abused_ips_reports, indent=2)
                )
                log.info("AbuseIPDB reports saved to %s", ws.file("abuseipdb", "abused_ips_reports.json"))
            else:
                log.info("No abuse reports found for the given IPs in AbuseIPDB")

        # --- Shodan host lookup -------------------------------------
        shodan = clients.get("shodan")
        if shodan:
            ips_info = dict()
            for ip in ips:
                try: 
                    result = shodan.host(ip)  
                    if result != {}:      # raw dict
                        groomed = grooming.get_groomed_shodan_info(result)
                        ips_info[ip] = groomed
                except Exception as e:
                    log.error("Shodan failed for %s: %s", ip, e, exc_info=True)
            shodan_path = ws.file("shodan", "shodan_info.json")
            if ips_info:
                shodan_path.write_text(json.dumps(ips_info, indent=2))
                
    # --- IntelX Leaked Credentials Retrieval ---------------------------------------
    intelx = clients.get("intelx")
    if intelx:
        intelligent_search_id = intelx.intelligent_search(
            term=mail_domain, media=0
        )

        if intelligent_search_id:
            filetype = "zip"
            print(f"Intelligent search ID: {intelligent_search_id}")
            content = intelx.intelligent_search_export(filetype=filetype, search_id=intelligent_search_id, limit=5000)
            if content:
                if content is not None:
                    # Writes to disk the search results (as a CSV or ZIP file)
                    filename = f"intelx_search_{intelligent_search_id}.{filetype}"

                    credentials_path = ws.file("intelx", f"leaked_credentials.json")
                    intelx_breach_files = ws.file("intelx", "breach_files")
                    intelx_breach_files.mkdir(parents=True, exist_ok=True)

                    # Save the content to a file
                    with open(os.path.join(intelx_breach_files, filename), "wb") as f:
                        f.write(content)

                    if filetype == "zip":
                        filepath = os.path.join(intelx_breach_files, filename)
                        extract_zip(filepath)
                    elif filetype == "csv":
                        # Not sure if we will ever use CSV, but let's keep it here
                        pass

                    if os.path.exists(intelx_breach_files):
                        credential_regex = rf"{cfg.get("email_without_domain_regex")}{mail_domain}:\S+"
                        extracted_credentials = start_credentials_retrieving_from_folder(str(intelx_breach_files), credential_regex)
                        credentials_path.write_text(
                            json.dumps(extracted_credentials, indent=2)
                        )
                        log.info("Leaked credentials saved to %s", ws.file("intelx", "leaked_credentials.json"))

                        # Delete the breach files directory after processing (has files in it)
                        shutil.rmtree(intelx_breach_files)
                else:
                    log.error("Intelligent search export result is empty")
    
    # --- Have I Been Pwned? Breaches Retrieval ---------------------------------------
    haveibeenpwned = clients.get("haveibeenpwned")
    if haveibeenpwned:
        # Extract all the emails from the dataleaks
        if os.path.exists(credentials_path):
            breached_emails = get_breached_emails(str(credentials_path))
            breaches_path = ws.file("haveibeenpwned", f"breached_accounts_{time.time()}.json")
            emails_breaches = dict()

            for email in breached_emails:
                breaches = haveibeenpwned.get_breaches_from_account(email, False)
                emails_breaches[email] = breaches

                # Necessary since the api key we are provided with has a rate limit
                time.sleep(cfg["haveibeenpwned_request_delay_in_seconds"])
            
            ws.file("haveibeenpwned", "breaches.json").write_text(
                json.dumps(emails_breaches, indent=2)
            )
         
    # 4) post-processing / diffing / report generation ----------
    # (left as TODO – you will call your processing & report modules here)
    
    # 5) cleanup
    # Delete empty directories
    ws.cleanup_empty_dirs()

    duration = datetime.now() - started
    log.info("Investigation finished in %.1fs", duration.total_seconds())