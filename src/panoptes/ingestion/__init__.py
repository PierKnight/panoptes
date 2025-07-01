"""
Ingestion package: contains one sub-module per external data-source
(IntelX, Shodan, …) and exposes a small registry so that the rest of the
code can instantiate plug-ins by name.

Example
-------
    from osint_app.ingestion import get_client
    shodan = get_client("shodan")(api_key="…")
"""

from importlib import import_module
from typing import Dict, Type

# ------------------------------------------------------------------ #
#  Import concrete client classes here (one line per new plug-in)    #
# ------------------------------------------------------------------ #
from .intelx import IntelX          # noqa: F401
from .haveibeenpwned import HaveIBeenPwned    # noqa: F401
from .mxtoolbox import MXToolbox    # noqa: F401
from .abuseipdb import AbuseIPDB    # noqa: F401
from .virustotal import VirusTotal    # noqa: F401
from .dnsdumpster import DNSDumpster    # noqa: F401
from .httpsecurityheaders import HTTPSecurityHeaders    # noqa: F401
from .sslshopper import SSLShopper    # noqa: F401
from .c99 import C99    # noqa: F401
from .shodan import Shodan    # noqa: F401

# … add the rest of your adapters …

# ------------------------------------------------------------------ #
#  Build a registry { "service_name" : ClientClass }                 #
# ------------------------------------------------------------------ #
_REGISTRY: Dict[str, Type] = {
    "intelx": IntelX,
    "mxtoolbox": MXToolbox,
    "haveibeenpwned": HaveIBeenPwned,
    "abuseipdb": AbuseIPDB,
    "virustotal": VirusTotal,
    "dnsdumpster": DNSDumpster,
    "c99": C99,
    "httpsecurityheaders": HTTPSecurityHeaders,
    "sslshopper": SSLShopper,
    "shodan": Shodan,
    # Add more clients as needed
}

def get_client(name: str):
    """Return the client *class* registered under *name*.

    Raises:
        KeyError: If *name* is unknown.
    """
    return _REGISTRY[name]