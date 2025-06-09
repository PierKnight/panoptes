import rich_click, logging
from panoptes import config, workflow, utils

from pathlib import Path

@rich_click.group()
@rich_click.option("-v", "--verbose", is_flag=True)
def cli(verbose):
    logging_level = "DEBUG" if verbose else "CRITICAL"
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
    rich_click.echo(rich_click.style(banner, fg="blue", bold=True))

@cli.command()
@rich_click.argument("domain")
@rich_click.option("--mail-domain")
def collect(domain, mail_domain):
    """Collect data for DOMAIN and optionally MAIL_DOMAIN."""
    print_banner()
    cfg = config.load()
    workflow.run_collect(cfg, domain, mail_domain)


@cli.command()
@rich_click.argument("domain")
def report(domain):
    """Generate a report (HTML and its PDF export) for the collected data in DOMAIN."""
    print_banner()
    cfg = config.load()
    workflow.run_report(cfg, domain)
    

if __name__ == "__main__":
    cli()