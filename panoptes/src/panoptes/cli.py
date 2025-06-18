import click, logging
from panoptes import config, workflow, utils

from pathlib import Path
from panoptes.utils.console import console

@click.group()
@click.option("-v", "--verbose", is_flag=True)
def cli(verbose):
    print_banner()
    logging_level = "INFO" if verbose else "WARNING"
    utils.logging.init_logger(logging_level)
    

def print_banner():
    banner = \
    """
    +--------------------------------------------------------------------------------------+
    |8888888b.     d8888 888b    888  .d88888b.  8888888b. 88888888888 8888888888 .d8888b. |
    |888   Y88b   d88888 8888b   888 d88P" "Y88b 888   Y88b    888     888       d88P  Y88b|
    |888    888  d88P888 88888b  888 888     888 888    888    888     888       Y88b.     |
    |888   d88P d88P 888 888Y88b 888 888     888 888   d88P    888     8888888    "Y888b.  |
    |8888888P" d88P  888 888 Y88b888 888     888 8888888P"     888     888           "Y88b.|
    |888      d88P   888 888  Y88888 888     888 888           888     888             "888|
    |888     d8888888888 888   Y8888 Y88b. .d88P 888           888     888       Y88b  d88P|
    |888    d88P     888 888    Y888  "Y88888P"  888           888     8888888888 "Y8888P" |
    +--------------------------------------------------------------------------------------+
    |                 by Alessandro Monetti (alessandromonetti@outlook.it)                 |
    +--------------------------------------------------------------------------------------+
    """
    console.print(banner, style="bold blue", highlight=False)

@cli.command()
@click.argument(
    "domains",
    nargs=-1,
    required=True,
    type=click.STRING,
)
@click.option(
    "--filter", "-f", 
    help="Comma-separated list of services to run. If omitted, run all. To get the list of available services, run 'panoptes services'.",
)
@click.option(
    "--mail-domain", "-m",
    help="Optional mail domain to collect data for. If not specified, the domain will be used as the mail domain.",
)
@click.option(
    "--website-url", "-w",
    help="Optional website URL. If not specified, https://<domain> will be used (or https://www.{domain} if the former is not reachable).",
)
def collect(domains, filter, mail_domain, website_url):
    """
    Collect data for the specified DOMAIN(s). If multiple domains are provided, they will be processed together.
    DOMAIN can be a single domain or multiple domains separated by spaces.

    If multiple domains are provided, workspace will be created with the name of the first domain. Info deduction (mail domain, website URL) will be also based on the first domain.
    """
    cfg = config.load()
    # Parse services from option (normalize to set or None)
    services_to_run = set(filter.split(",")) if filter else None
    website_url = website_url or ""

    if len(domains) == 1:
        console.print(f"You ran the collect command for domain: [bold blue]{domains[0]}[/bold blue]")
    else:
        console.print(f"You ran the collect command for multiple domains: [bold blue]{', '.join(domains)}[/bold blue]")
        console.print("The workspace will be created with the name of the first domain.")
    console.print()
    console.print(f"You specified the following options:")
    if mail_domain:
        console.print(f" [bold italic red]- Mail Domain:[/bold italic red] {mail_domain}")
    if services_to_run:
        console.print(f" [bold italic red]- Services to run:[/bold italic red] {', '.join(services_to_run)}")
    console.print()
    workflow.run_collect(cfg, domains, mail_domain, services_to_run, website_url)


@cli.command()
@click.argument("domain")
@click.option(
    "--incremental",
    is_flag=True,
    help="Run the report in incremental mode, only processing new data since the last run.",
    default=False,
    show_default=True,
)
@click.option(
    "--language",
    help="Language for the report, If not specified, defaults to English (en). Other available language is Italian (it).",
    default="en",
    show_default=True,
    type=click.Choice(["en", "it"], case_sensitive=False),
)
@click.option(
    "--export-from-html",
    is_flag=True,
    help="Export the report to PDF from the HTML file. Useful if you want to update the HTML manually and then generate the PDF.",
    default=False,
    show_default=True,
)
def report(domain, incremental, language, export_from_html):
    """Generate a report (HTML and its PDF export) for the collected data in DOMAIN."""
    cfg = config.load()
    console.print(f"You ran the report command for domain: [bold blue]{domain}[/bold blue]")
    if incremental or export_from_html or language != "en":
        console.print("You have specified options that will affect the report generation:")
        if incremental:
            console.print(" [bold italic red]- Incremental mode:[/bold italic red] Only new data will be processed since the last run.")
        if export_from_html:
            console.print(" [bold italic red]- Export from HTML[/bold italic red]: The report will be generated from the HTML file.")
        if language != "en":
            console.print(f" [bold italic red]- Language[/bold italic red]: The report will be generated in [bold blue]{language}[/bold blue] language.")
        console.print()
    workflow.run_report(cfg, domain, incremental, language, export_from_html)
    

@cli.command()
def services():
    """List available services."""
    cfg = config.load()
    services = cfg.get("services", {})

    if not services:
        console.print("No services available.", style="bold red")
        return
    console.print("Available services:")
    for service in sorted(services.keys()):
        console.print(f"\t- [bold blue]{service}[/bold blue]: [italic]{services[service]}[/italic]")


if __name__ == "__main__":
    cli()