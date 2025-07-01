from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging
from requests.exceptions import RequestException

log = logging.get(__name__)
import json

from typeguard import typechecked

@typechecked
class HaveIBeenPwned(BaseHTTPClient):
    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: str):
        """
        Args:
            api_key: Personal Have I Been Pwned API key.
        """
        self.api_key = api_key
        super().__init__(timeout=10)

    def get_breaches_from_account(self, account: str, truncate_response: bool) -> list[dict]:
        """
        Get breaches associated with a specific account.
        Args:
            account: The account to search for breaches.
            truncate_response: If True, the response will be truncated to reduce size.
        Returns:
            A list of breaches associated with the account.
        """
        url = f"{self.BASE_URL}/breachedaccount/{account}"
        headers = {"hibp-api-key": self.api_key}

        breaches = list()

        params = {
            "truncateResponse": truncate_response
        }

        try:
            response = self._get(
                url=url,
                params=params,
                headers=headers 
            )
            response.raise_for_status()
            breaches = [breach for breach in json.loads(response.text)]

            return breaches

        except RequestException as e:      
            status_code = e.response.status_code
            if status_code == 404:
                log.info(f"{account} was not found in any breaches")
            elif status_code == 429:
                log.error("Too many requests: slow down!")
        except Exception as e:
            log.error(f"Unexpected error while performing search export request: {e}")
        return breaches 