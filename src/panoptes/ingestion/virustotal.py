from __future__ import annotations

import json

from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging

from requests.exceptions import RequestException

log = logging.get(__name__)

from typeguard import typechecked

@typechecked
class VirusTotal(BaseHTTPClient):
    """VirusTotal API client for retrieving subdomains of a domain."""
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        super().__init__(timeout=10)


    def get_subdomains_list(self, domain: str) -> list[str]:
        """
        Get a list of subdomains for a given domain using the VirusTotal API.
        Args:
            domain (str): The domain to search for subdomains.
        Returns:
            list[str]: A list of subdomains found for the given domain."""
        url = f"{self.BASE_URL}/domains/{domain}/subdomains"
        headers = {"x-apikey": self.api_key}
        subdomains_list = list()
        try:
            result = self._get(
                url=url,
                headers=headers
            )
            result.raise_for_status()

            result_json = result.json()
            subdomains_list.extend([entry["id"] for entry in result_json["data"]])
            return subdomains_list
        except RequestException as e:
            log.error(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            log.error("Failed to parse search response JSON.")
        except Exception as e:
            log.error(f"Unexpected error while performing search request: {e}")
        return subdomains_list