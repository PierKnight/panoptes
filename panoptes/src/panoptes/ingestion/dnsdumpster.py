from __future__ import annotations

import json

from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging

from requests.exceptions import HTTPError, RequestException

log = logging.get(__name__)

from typeguard import typechecked

@typechecked
class DNSDumpster(BaseHTTPClient):
    BASE_URL = "https://api.dnsdumpster.com"

    def __init__(self, api_key: str):
        self.api_key = api_key
        super().__init__(timeout=10)

    def get_dns_records_from_domain(self, domain: str) -> dict:
        url = f"{self.BASE_URL}/domain/{domain}"
        headers = {
            "X-API-Key": self.api_key,
        }

        dns_records = dict()

        try:
            result = self._get(
                url=url,
                headers=headers
            )
            result.raise_for_status()

            result_json = result.json()
            return result_json
        except RequestException as e:
            log.error(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            log.error("Failed to parse search response JSON.")
        except Exception as e:
            log.error(f"Unexpected error while performing search request: {e}")

        return dns_records