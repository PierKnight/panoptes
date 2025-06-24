"""
High-level orchestration for a single OSINT investigation.

Called by the CLI:
    $ osint collect example.com --mail-domain example.com
"""

from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from typeguard import typechecked

from panoptes.persistence.paths import Workspace
from panoptes.ingestion import get_client
from panoptes.processing import grooming
from panoptes.utils import logging
from panoptes.utils.console import console
from panoptes.utils.misc import *
from panoptes import reporting

from rich.console import Console
from rich.progress import track, Progress

import os

import json

import wappalyzer

import shutil

import time

log = logging.get(__name__)

DEFAULT_COLLECT_SERVICES = [
    "intelx",
    "shodan",
    "mxtoolbox",
    "dnsdumpster",
    "httpsecurityheaders",
    "sslshopper",
    "haveibeenpwned",
    "abuseipdb",
    "virustotal",
    # add/remove as you wire them
]

# Unused but kept for future reference
DEFAULT_REPORT_SERVICES = [
    "imgbb"
]

WORKSPACE_ONLY_SERVICES = [
    "wappalyzer",  # Wappalyzer is not a client, but a library
]

# If you decide one day to use filtering on buckets, you can use this list.
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

SERVICE_WORKFLOW = {
    "dns-lookup": ["dnsdumpster"],
    "spf-dmarc": ["mxtoolbox"],
    "ssl-check": ["sslshopper"],
    "tech-stack": ["wappalyzer"],
    "http-headers": ["httpsecurityheaders"],
    "subdomains": ["subdomains"],
    "exposed-ports-cve": ["shodan"],
    "compromised-hosts": ["abuseipdb"],
    "compromised-credentials": ["intelx", "haveibeenpwned"]
}

@typechecked
def print_rule(message: str, style: str = "bold red") -> None:
    """
    Prints a rule with the given message to the console prepended with a newline.
    The style can be customized, default is "bold red".
    """
    console.print("\n")
    console.rule(message, style=style)

@typechecked
def get_workflow_steps(services_to_run: Optional[List[str]]) -> Set[str]:
    if services_to_run is None:
        return {s for steps in SERVICE_WORKFLOW.values() for s in steps}
    steps = set()
    for service in services_to_run:
        steps.update(SERVICE_WORKFLOW.get(service, []))
    return steps


@typechecked
def run_collect(cfg: Dict[str, Any], domains: tuple, mail_domain: Optional[str], services_to_run: Optional[Set[str]] = None, website_url: str = "") -> None:
    started = datetime.now()
    mail_domain = mail_domain or domains[0]

    ws = setup_workspace(cfg, domains[0])
    clients = instantiate_clients(cfg, DEFAULT_COLLECT_SERVICES)

    if website_url == "":
        website_url = determine_website_url(domains[0])

    print_startup(domains[0], started, ws, website_url, mail_domain)

    # Figure out which internal steps to run
    steps_to_run = get_workflow_steps(list(services_to_run) if services_to_run else None)

    # Now, for each step, check if it's requested before running its function
    if "wappalyzer" in steps_to_run:
        print_rule("[bold green]Web App Technology Fingerprinting[/bold green]")
        run_wappalyzer(ws, website_url)
    if "mxtoolbox" in steps_to_run:
        print_rule("[bold green]DMARC & SPF Records Lookup[/bold green]")
        run_mxtoolbox(ws, domains, clients.get("mxtoolbox"))
    if "dnsdumpster" in steps_to_run:
        print_rule("[bold green]DNS Records Lookup[/bold green]")
        run_dnsdumpster(ws, domains, clients.get("dnsdumpster"))
    if "httpsecurityheaders" in steps_to_run:
        print_rule("[bold green]HTTP Security Headers Analysis[/bold green]")
        run_httpsecurityheaders(ws, website_url, clients.get("httpsecurityheaders"))
    if "sslshopper" in steps_to_run:
        print_rule("[bold green]SSL Certificate Analysis[/bold green]")
        run_sslshopper(ws, website_url, clients.get("sslshopper"))

    # Subdomains block
    subdomains = []
    if "subdomains" in steps_to_run or "shodan" in steps_to_run or "abuseipdb" in steps_to_run:
        print_rule("[bold green]Subdomains and IPs Discovery[/bold green]")
        subdomains = get_subdomains(domains, clients)
        if "subdomains" in steps_to_run:
            save_subdomains(ws, subdomains)

    ## Get IPs from subdomains
    ips = []
    if subdomains:
        subdomain_ips = get_ips_from_subdomains(ws, subdomains)
        ips = aggregate_values_from_dict_with_no_duplicates(subdomain_ips)
        if "abuseipdb" in steps_to_run:
            run_abuseipdb(ws, ips, clients.get("abuseipdb"))
        if "shodan" in steps_to_run:
            run_shodan(ws, ips, clients.get("shodan"))
    
 

    # Credentials/breaches steps
    credentials_path = None
    if "intelx" in steps_to_run:
        print_rule("[bold green]Leaked Credentials Discovery[/bold green]")
        credentials_path = run_intelx(ws, cfg, mail_domain, clients.get("intelx"))
    if "haveibeenpwned" in steps_to_run and credentials_path:
        run_haveibeenpwned(ws, credentials_path, cfg, clients.get("haveibeenpwned"))

    ws.cleanup_empty_dirs()
    log.info("Investigation finished in %.1fs", (datetime.now() - started).total_seconds())

@typechecked
def run_report(cfg: Dict[str, Any], domain: str, incremental: bool, language: str, export_from_html: bool, theme: str) -> None:
    """ Generates HTML and PDF reports for the completed investigation.

    Args:
        cfg: Dict returned by `osint_app.config.load()`.
        domain: Web-site to analyse, e.g. "example.com".
    """
    ws_path = cfg["base_dir"] / domain
    
    imgbb_api_key = cfg["api_keys"].get("imgbb")

    if incremental and export_from_html:
        log.warning("Incremental mode is not compatible with HTML export. Ignoring incremental flag.")
        incremental = False
    html, pdf = reporting.generate.generate_report(ws_path, incremental, language, export_from_html, theme, imgbb_api_key=imgbb_api_key)
    log.info("HTML written to %s", html)
    log.info("PDF written to %s", pdf)


@typechecked
def setup_workspace(cfg: Dict[str, Any], domain: str) -> Workspace:
    """
    Sets up a Workspace object for filesystem organization, ensures working directory.
    """
    ws = Workspace(cfg["base_dir"], domain, DEFAULT_COLLECT_SERVICES + WORKSPACE_ONLY_SERVICES)
    console.print(f"Workspace created at [bold blue]{ws.root}[/bold blue]")
    return ws

@typechecked
def instantiate_clients(cfg: Dict[str, Any], services: list[str]) -> Dict[str, Any]:
    """
    Instantiates client objects for each enabled OSINT service using provided API keys.
    """
    clients = {}
    for name in services:
        try:
            cls = get_client(name)
            key = cfg["api_keys"].get(name)
            clients[name] = cls(api_key=key) if key else cls()
        except Exception as exc:
            log.error("Cannot create client %s: %s", name, exc)
    return clients

@typechecked
def determine_website_url(domain: str) -> str:
    """
    Derives the correct website URL to use for fingerprinting (resolves edge cases).
    """
    with console.status("[bold green]Determining website URL...[/bold green]"):
        website_url = get_website_url(domain)
        console.print(f"Website URL determined: [bold blue]{website_url}[/bold blue]")
    return website_url

@typechecked
def print_startup(domain: str, started: datetime, ws: Workspace, website_url: str, mail_domain: str) -> None:
    """
    Prints summary of investigation start and context to the CLI.
    """
    console.print(f"Starting investigation for [bold blue]{domain}[/bold blue] at [bold green]{started.strftime('%Y-%m-%d %H:%M:%S')}[/bold green]")
    log.info("Mail domain is %s", mail_domain)

@typechecked
def print_shutdown(domain: str, started: datetime) -> None:
    """
    Prints summary of investigation completion to the CLI.
    """
    duration = (datetime.now() - started).total_seconds()
    console.print(f"Investigation for [bold blue]{domain}[/bold blue] completed in [bold green]{duration:.1f} seconds[/bold green]")
    log.info("Investigation for %s completed in %.1fs", domain, duration)

@typechecked
def save_json(ws: Workspace, section: str, filename: str, data: Any) -> Path:
    """
    Utility: save a Python object as pretty-printed JSON in the workspace.
    """
    path = ws.file(section, filename)
    path.write_text(json.dumps(data, indent=2))
    return path

@typechecked
def run_wappalyzer(ws: Workspace, website_url: str) -> None:
    """
    Runs web technology fingerprinting and saves the result.
    """
    with console.status("[bold green]Running Web App Technology fingerprinting...[/bold green]"):
        raw = wappalyzer.analyze(
            url=website_url, scan_type='balanced', threads=8, cookie='sessionid=abc123'
        )
        results = grooming.get_groomed_wappalyzer_info(raw)
        path = save_json(ws, "wappalyzer", "results.json", results)
        console.print(f"Web App Technology fingerprinting results saved to [bold blue]{path}[/bold blue]")

@typechecked
def run_mxtoolbox(ws: Workspace, domains: tuple, mxtoolbox: Optional[Any]) -> None:
    """
    Looks up SPF/DMARC records using MXToolbox and saves results (with images).
    """
    if not mxtoolbox:
        return
    with console.status("[bold green]Running DMARC & SPF records lookup...[/bold green]"):
        for domain in domains:
            spf_info = mxtoolbox.get_action_info_from_domain(domain=domain, action="spf")
            dmarc_info = mxtoolbox.get_action_info_from_domain(domain=domain, action="dmarc")
            # Groom ("clean up") the results structure
            cs = grooming.get_groomed_mxtoolbox_lookup
            save_json(ws, "mxtoolbox", f"spf_{domain}.json", cs(spf_info.get("spf_json", {})))
            save_json(ws, "mxtoolbox", f"dmarc_{domain}.json", cs(dmarc_info.get("dmarc_json", {})))

            # Save images if they exist in the response
            if (spf_img := spf_info.get("spf_image")) is not None:
                spf_img.save(ws.file("mxtoolbox", f"spf_{domain}.png"))
                console.print(f"SPF image saved to [bold blue]{ws.file('mxtoolbox', f'spf_{domain}.png')}[/bold blue]")
            if (dmarc_img := dmarc_info.get("dmarc_image")) is not None:
                dmarc_img.save(ws.file("mxtoolbox", f"dmarc_{domain}.png"))
                console.print(f"DMARC image saved to [bold blue]{ws.file('mxtoolbox', f'dmarc_{domain}.png')}[/bold blue]")

@typechecked
def run_dnsdumpster(ws: Workspace, domains: tuple, dnsdumpster: Optional[Any]) -> None:
    """
    Retrieves DNS records for the domain via DNSDumpster and saves them.
    """
    if not dnsdumpster:
        return
    with console.status("[bold green]Running DNS records lookup...[/bold green]"):
        for domain in domains:
            raw = dnsdumpster.get_dns_records_from_domain(domain)
            clean = grooming.get_groomed_dnsdumpster_info(raw)
            path = save_json(ws, "dnsdumpster", f"dns_records_{domain}.json", clean)
            console.print(f"DNS records saved to [bold blue]{path}[/bold blue]")

@typechecked
def run_httpsecurityheaders(ws: Workspace, website_url: str, client: Optional[Any]) -> None:
    """
    Analyzes missing HTTP security headers on the live web app (if supported by config).
    """
    if not client:
        return
    with console.status("[bold green]Running HTTP Security Headers analysis...[/bold green]"):
        missing = client.get_missing_security_headers_with_description(website_url)
        if missing:
            path = save_json(ws, "httpsecurityheaders", "missing_headers.json", missing)
            console.print(f"HTTP Security Headers results saved to [bold blue]{path}[/bold blue]")

@typechecked
def run_sslshopper(ws: Workspace, website_url: str, sslshopper: Optional[Any]) -> None:
    """
    Performs SSL certificate chain validation and persists certificate info and image.
    """
    if not sslshopper:
        return
    with console.status("[bold green]Running SSL Certificate Chain analysis...[/bold green]"):
        info = sslshopper.get_ssl_certificate_info(website_url)
        # Only proceed if expected keys are present
        if "certificate_json" in info and "certificate_image" in info:
            info["certificate_image"].save(ws.file("sslshopper", "certificate_chain.png"))
            save_json(ws, "sslshopper", "certificate_info.json", info["certificate_json"])
            console.print(f"SSL Certificate Chain results saved to [bold blue]{ws.file('sslshopper', 'certificate_info.json')}[/bold blue]")

@typechecked
def get_subdomains(domains: tuple, clients: Dict[str, Any]) -> List[str]:
    """
    Fuses results from multiple sources (C99, VirusTotal, IntelX) to enumerate subdomains.
    """
    subdomains = set()
    for domain in domains:
        # -- C99 subdomains
        if c99 := clients.get("c99"):
            with console.status("[bold green]Running C99 subdomain finder...[/bold green]"):
                subdomains.update(c99.subdomain_finder(domain))
        # -- VirusTotal subdomains
        if vt := clients.get("virustotal"):
            with console.status("[bold green]Running VirusTotal subdomain finder...[/bold green]"):
                subdomains.update(vt.get_subdomains_list(domain))
        # -- IntelX subdomains
        if intelx := clients.get("intelx"):
            with console.status("[bold green]Running IntelX subdomain finder...[/bold green]"):
                phonebook_result = []
                phonebook_search_id = intelx.phonebook_search(term=domain, target=1)
                if phonebook_search_id:
                    res = intelx.phonebook_search_result(search_id=phonebook_search_id, limit=1000)
                    if res and "selectors" in res:
                        for entry in res["selectors"]:
                            if "selectorvalue" in entry:
                                phonebook_result.append(entry["selectorvalue"])
                subdomains.update(phonebook_result)
    # Output is alphabetically sorted for repeatability
    return sorted(subdomains)

@typechecked
def save_subdomains(ws: Workspace, subdomains: List[str]) -> None:
    """
    Stores the assembled list of discovered subdomains as a text file.
    """
    console.print(f"Subdomains found: [bold blue]{len(subdomains)}[/bold blue]")
    ws.file("subdomains", "subdomains_list.txt").write_text("\n".join(subdomains))

@typechecked
def get_ips_from_subdomains(ws: Workspace, subdomains: List[str]) -> Dict[str, List[str]]:
    """
    For each subdomain, resolves associated IP addresses and persists as JSON.
    """
    with console.status("[bold green]Running IPs retrieval from subdomains...[/bold green]"):
        subdomains_ips = get_ips_from_hosts(subdomains)
        ws.file("subdomains", "subdomains_ips.json").write_text(json.dumps(subdomains_ips, indent=2))
    return subdomains_ips

@typechecked
def run_abuseipdb(ws: Workspace, ips: List[str], abuseipdb: Optional[Any]) -> None:
    """
    Gathers AbuseIPDB reports for the set of IPs and stores the findings.
    """
    if not abuseipdb:
        return
    with console.status("[bold green]Running IPs abuse reports retrieval...[/bold green]"):
        reports = abuseipdb.get_abused_ips_reports(ips)
        if reports:
            save_json(ws, "abuseipdb", "abused_ips_reports.json", reports)
            console.print(f"AbuseIPDB reports saved to [bold blue]{ws.file('abuseipdb', 'abused_ips_reports.json')}[/bold blue]")
        else:
            log.warning("No abuse reports found for the given IPs in AbuseIPDB")


@typechecked
def run_shodan(ws: Workspace, ips: List[str], shodan: Optional[Any]) -> None:
    if not shodan:
        return
    ips_info = {}

    with Progress(console=console) as progress:
        task = progress.add_task("Retrieving hosts info...", total=len(ips))

        for ip in ips:
            try:
                result = shodan.host(ip)
                if result:
                    groomed = grooming.get_groomed_shodan_info(result)
                    ips_info[ip] = groomed
            except Exception as e:
                # Use console.log(), which *is* progress-aware
                console.log(f"[red]Shodan failed for {ip}: {e}[/]", exc_info=True)
            progress.update(task, advance=1)

    if ips_info:
        ips_info = dict(sorted(
            ips_info.items(),
            key=lambda item: item[1].get("cvss_average", 0),
            reverse=True
        ))
        save_json(ws, "shodan", "shodan_info.json", ips_info)

@typechecked
def run_intelx(ws: Workspace, cfg: Dict[str, Any], mail_domain: str, intelx: Optional[Any]) -> Optional[Path]:
    """
    Uses IntelX to search for credential leaks for a mail domain, downloading and extracting data as ZIPs.
    Results are aggregated and stored as JSON.
    """
    if not intelx:
        return None
    stop_search = False
    credentials = dict()
    credentials_path = ws.file("intelx", "leaked_credentials.json")
    # Try most relevant first, then (iff export limit is reached) less relevant (sort order impacts result relevance)
    for sort in (2, 1):
        with console.status("[bold green]Running Leaked Credentials Retrieval...[/bold green]"):
            intelligent_search_id = intelx.intelligent_search(term=mail_domain, media=0, sort=sort)
        if intelligent_search_id:
            filetype = "zip"
            intelx_breach_files = ws.file("intelx", "breach_files")
            intelx_breach_files.mkdir(parents=True, exist_ok=True)
            filename = f"intelx_search_{intelligent_search_id}_{sort}.{filetype}"
            # Wait/poll for results to be packaged
            for _ in range(10):
                time.sleep(1)
            with console.status("[bold green]Retrieving leaked data...[/bold green]"):
                content = intelx.intelligent_search_export(filetype=filetype, search_id=intelligent_search_id, limit=1000)
            if content:
                # Save result zip and extract credentials within
                with open(os.path.join(intelx_breach_files, filename), "wb") as f:
                    f.write(content)
                if filetype == "zip":
                    filepath = os.path.join(intelx_breach_files, filename)
                    extract_zip(filepath)
                # If extracted files exist: parse them with appropriate regex
                if os.path.exists(intelx_breach_files):
                    credential_regex = rf"{cfg.get('email_without_domain_regex')}{mail_domain}:\S+"
                    extracted_credentials = get_credentials_from_folder(str(intelx_breach_files), credential_regex)
                    for key, value in extracted_credentials.items():
                        if key in credentials:
                            credentials[key] |= value
                        else:
                            credentials[key] = value
                    # If the folder size is less than 2GB, we didn't hit the export limit, so we can stop searching
                    if get_folder_size(intelx_breach_files) < 2_000_000_000:
                        stop_search = True
                    shutil.rmtree(intelx_breach_files)
            else:
                log.error("Intelligent search export result is empty")
        if stop_search:
            break
        console.print(f"[bold yellow]Running IntelX's search also with ascending relevance sorting since export limit size was reached...[/bold yellow]")

    # Sorting and storing discovered credentials
    with console.status("[bold green]Sorting credentials..[/bold green]"):
        credentials = sort_credentials(credentials)
    credentials_path.write_text(json.dumps(credentials, indent=2))
    console.print(f"Leaked credentials saved to [bold blue]{credentials_path}[/bold blue]")
    return credentials_path

from rich.progress import Progress

@typechecked
def run_haveibeenpwned(ws: Workspace, credentials_path: Path, cfg: Dict[str, Any], haveibeenpwned: Optional[Any]) -> None:
    """
    Cross-checks found email addresses against the HaveIBeenPwned API to aggregate breach history.
    Observes the necessary request delay as demanded by API terms.
    """
    if (
        not haveibeenpwned
        or not credentials_path
        or not os.path.exists(credentials_path)
    ):
        return

    breached_emails = get_breached_emails(str(credentials_path))
    emails_breaches = dict()
    errors = []

    with Progress(console=console) as progress:
        task = progress.add_task("Checking breaches for emails...", total=len(breached_emails))
        for email in breached_emails:
            try:
                breaches = haveibeenpwned.get_breaches_from_account(email, False)
                emails_breaches[email] = breaches
            except Exception as e:
                # Properly logs error without breaking the progress bar
                console.log(f"[red]Error checking breaches for {email}: {e}[/]")
                errors.append((email, str(e)))
            progress.update(task, advance=1)
            # Respect rate-limiting requirements
            time.sleep(cfg["haveibeenpwned_request_delay_in_seconds"])

    save_json(ws, "haveibeenpwned", "breaches.json", emails_breaches)
    console.print(f"Data breaches saved to [bold blue]{ws.file('haveibeenpwned', 'breaches.json')}[/bold blue]")

    if errors:
        console.print("[yellow]There were errors with the following emails:[/yellow]")
        for email, err in errors:
            console.print(f"[red]- {email}: {err}[/red]")