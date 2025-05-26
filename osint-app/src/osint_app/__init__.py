"""
Top-level package initialisation.
"""

from importlib.metadata import version as _pkg_version

from .ingestion import get_client
from .config import load as load_config

__all__ = ["get_client", "load_config", "__version__"]
__version__ = _pkg_version("osint_app")