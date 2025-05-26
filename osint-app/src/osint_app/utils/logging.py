import logging
import sys
from typeguard import typechecked


@typechecked
def init(level: str = "INFO") -> None:
    """Initialise a root logger that prints to stdout."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

def get(name: str | None = None) -> logging.Logger:
    """Convenience wrapper so callers can use utils.logging.get(__name__)."""
    return logging.getLogger(name)

def init_logger(level: str = "INFO") -> None:
    """Initialise a root logger that prints to stdout."""
    init(level)
    get().info("Logger initialised with level: %s", level)
    return get()