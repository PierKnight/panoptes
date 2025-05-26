from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from osint_app.utils.http import BaseHTTPClient
from osint_app.utils import logging

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from osint_app.utils.selenium_tools import get_screenshot_and_element_by_class_name

from PIL import Image

from requests.exceptions import HTTPError, RequestException

log = logging.get(__name__)

from typeguard import typechecked

@typechecked
class MXToolbox(BaseHTTPClient):
    BASE_URL = "https://mxtoolbox.com/api/v1/lookup"

    def __init__(self, api_key: str):
        self.api_key = api_key
        super().__init__(timeout=10)

    def __use_selenium_to_retrieve_screenshot(action: str, domain: str) -> Image.Image:
        """
        This function uses Selenium to take a screenshot of the MXToolbox page for a specific action and domain.
        """
        selenium_url = f"https://mxtoolbox.com/SuperTool.aspx?action={action}%3a{domain}&run=toolpage#"
        driver = None
        try:
            driver = webdriver.Chrome(options=webdriver.ChromeOptions().add_argument("--headless"))
            driver.get(selenium_url)
            img = get_screenshot_and_element_by_class_name(driver, f"lookup-type-{action}")
            return img.get("image")
        except Exception as e:
            log.error(f"Error taking screenshot: {e}")
            return None
        finally:
            if driver:
                driver.quit()


    '''
    The following function is used to perform info retrieving for a given action.
    It takes the following parameters:
        domain: str               # The domain to check
        action: str               # The action to perform (e.g., "spf", "dmarc", etc.)
    It returns a dictionary containing the JSON response and the screenshot of the action.
    '''
    def get_action_info_from_domain(self, domain: str, action: str) -> dict:
        info = dict()
        url = f"{self.BASE_URL}/{action}/{domain}"
        headers = {
            "Authorization": self.api_key
        }

        try:
            result = self._get(
                url=url,
                headers=headers
            )
            result.raise_for_status()

            action_json = result.json()

            info[f"{action}_json"] = action_json

            # Selenium is used to retrieve the screenshot.
            try:
                img = MXToolbox.__use_selenium_to_retrieve_screenshot(action, domain)
                info[f"{action}_image"] = img
            except TimeoutException:
                log.error(f"Timeout while trying to get the {action} image")
                info[f"{action}_image"] = None

        except RequestException as e:
            log.error(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            log.error("Failed to parse search response JSON.")
        except Exception as e:
            log.error(f"Unexpected error while performing search request: {e}")
        return info