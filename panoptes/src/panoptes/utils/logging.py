import logging
import sys
from typeguard import typechecked

# ANSI color codes
RESET = "\033[0m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
RED = "\033[31m"

class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.INFO: BLUE,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: RED
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, "")
        msg = super().format(record)
        if color:
            msg = f"{color}{msg}{RESET}"
        return msg

@typechecked
def init(level: str = "INFO") -> None:
    """Initialise a root logger that prints to stdout with color support for INFO, WARNING, ERROR."""
    # Remove all handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s"
    ))
    logging.basicConfig(
        level=level,
        handlers=[handler]
    )

def get(name: str | None = None) -> logging.Logger:
    """Convenience wrapper so callers can use utils.logging.get(__name__)."""
    return logging.getLogger(name)

def init_logger(level: str = "INFO") -> logging.Logger:
    """Initialise a root logger that prints to stdout with colors."""
    init(level)
    logger = get()
    logger.info("Logger initialised with level: %s", level)
    return logger