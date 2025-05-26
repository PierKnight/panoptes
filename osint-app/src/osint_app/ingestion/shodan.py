from __future__ import annotations

import shodan
from osint_app.utils import logging
from requests.exceptions import RequestException

log = logging.get(__name__)

from typeguard import typechecked


@typechecked
class Shodan:
    """
    A wclass to interact with the Shodan API for OSINT purposes.
    
    Attributes:
        api_key (str): The API key for accessing Shodan.
        api (shodan.Shodan): An instance of the Shodan API client.
    """
    
    def __init__(self, api_key: str):
        """
        Initializes the Shodan class with the provided API key.
        
        Args:
            api_key (str): The API key for Shodan.
        """
        self.api_key = api_key
        self.api = shodan.Shodan(api_key)
    
    def host(self, ip: str) -> dict:
        """
        Retrieves information about a specific host by its IP address.
        
        Args:
            ip (str): The IP address of the host to query.
        
        Returns:
            dict: A dictionary containing information about the host.
        """
        try:
            return self.api.host(ip)
        except RequestException as e:
            log.error(f"Network error during Shodan host request: {e}")
            return {}
        except Exception as e:
            log.error(f"Unexpected error while performing Shodan host request: {e}")
            return {}