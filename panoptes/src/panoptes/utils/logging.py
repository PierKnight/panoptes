import logging
from rich.logging import RichHandler
import sys
from typeguard import typechecked
from panoptes.utils.console import console

@typechecked
def init(level: str = "INFO") -> None:
    """Initialise a root logger that prints to stdout with Rich's logging support."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)],
    )

def get(name: str | None = None) -> logging.Logger:
    """Convenience wrapper so callers can use utils.logging.get(__name__)."""
    return logging.getLogger(name)

def init_logger(level: str = "INFO") -> logging.Logger:
    """Initialise a root logger that prints to stdout with Rich's logging."""
    init(level)
    logger = get()
    logger.info("Logger initialised with level: %s", level)
    return logger