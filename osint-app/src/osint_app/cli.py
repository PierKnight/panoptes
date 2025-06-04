import rich_click, logging
from osint_app import config, workflow, utils
from osint_app import reporting

from pathlib import Path

@rich_click.group()
@rich_click.option("-v", "--verbose", is_flag=True)
def cli(verbose):
    logging_level = "DEBUG" if verbose else "INFO"
    utils.logging.init_logger(logging_level)


@cli.command()
@rich_click.argument("domain")
@rich_click.option("--mail-domain")
def collect(domain, mail_domain):
    """Collect data for DOMAIN and optionally MAIL_DOMAIN."""
    cfg = config.load()
    workflow.run(cfg, domain, mail_domain)


@cli.command()
@rich_click.argument("workspace", type=rich_click.Path(exists=True, file_okay=False))
def report(workspace):
    """Generate report.json (+ prev) and a PDF for WORKSPACE."""
    html, pdf = reporting.generate.generate_report(Path(workspace))
    rich_click.echo(f"HTML written to {html}")
    rich_click.echo(f"PDF written to {pdf}")
    

if __name__ == "__main__":
    cli()