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
@click.argument("domain")
@click.option("--mail-domain")
@click.option(
    "--filter", "-f", 
    help="Comma-separated list of services to run. If omitted, run all. To get the list of available services, run 'panoptes services'.",
)
def collect(domain, mail_domain, filter):
    """Collect data for DOMAIN and optionally MAIL_DOMAIN."""
    cfg = config.load()
    # Parse services from option (normalize to set or None)
    services_to_run = set(filter.split(",")) if filter else None
    workflow.run_collect(cfg, domain, mail_domain, services_to_run)


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