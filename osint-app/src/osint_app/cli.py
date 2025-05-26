import rich_click, logging
from osint_app import config, workflow, utils

@rich_click.group()
@rich_click.option("-v", "--verbose", is_flag=True)
def cli(verbose):
    logging_level = "DEBUG" if verbose else "INFO"
    utils.logging.init_logger(logging_level)

@cli.command()
@rich_click.argument("domain")
@rich_click.option("--mail-domain")
def collect(domain, mail_domain):
    cfg = config.load()
    workflow.run(cfg, domain, mail_domain)

if __name__ == "__main__":
    cli()