from __future__ import annotations

import json

from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging

from requests.exceptions import RequestException

log = logging.get(__name__)

from typeguard import typechecked

@typechecked
class C99(BaseHTTPClient):
    BASE_URL = "https://api.c99.nl"
    def __init__(self, api_key: str):
        self.api_key = api_key
        super().__init__(timeout=10)


    def subdomain_finder(self, domain: str) -> list[str]:
        """
        Perform a subdomain search for the given domain using C99 API.
        Args:
            domain (str): The domain to search for subdomains.
        Returns:
            list[str]: A list of subdomains found for the given domain.
        """
        subdomains = list()
        url = f"{self.BASE_URL}/subdomainfinder"

        # Here we are forced to write the params string manually since json parameter does not accept values
        params = f"key={self.api_key}&domain={domain}&json"

        try:
            result = self._get(
                url=url,
                params=params,
            )
            result.raise_for_status()                       # Raises an HTTPError for bad responses

            search_result = json.loads(result.text)

            if "success" in search_result and search_result["success"] == False:
                log.info("No subdomains found for {domain} by C99")
                return subdomains

            # Extract just the subdomains from the response
            subdomains = [subdomain["subdomain"] for subdomain in search_result["subdomains"]]

        except RequestException as e:
            log.error(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            log.error("Failed to parse search response JSON.")
        except Exception as e:
            log.error(f"Unexpected error while performing search request: {e}")
        return subdomains