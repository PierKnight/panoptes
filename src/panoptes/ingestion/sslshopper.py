from __future__ import annotations

from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from panoptes.utils.selenium_tools import get_screenshot_and_element_by_class_name

log = logging.get(__name__)

import re

from typeguard import typechecked


@typechecked
class SSLShopper(BaseHTTPClient):
    BASE_URL = "https://www.sslshopper.com/ssl-checker.html"

    def __init__(self):
        super().__init__(timeout=10)

    @staticmethod
    def get_certificate_json_from_list(content_list: list[str]) -> dict:
        """
        Converts table content from SSLShopper html page into a JSON object.
        Args:
            content_list: List of strings representing the content of the table.
        Returns:
            A dictionary representing the SSL certificate information.
        """
        certificate_json = dict()
        for line in content_list:
            # Split the line into key and value
            # Assuming the format is "key: value"
            parts = line.split(":")
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()

                # Check if the value is a list
                if "," in value:
                    # Split the value into a list
                    value = [v.strip() for v in value.split(",")]
                # Add to the dictionary
                certificate_json[key] = value
            else:
                if line.startswith("Valid from"):
                    validity_regex = r"from (.*)? to (.*)"
                    match = re.search(validity_regex, line)
                    if match:
                        certificate_json["Valid from"] = match.group(1).strip()
                        certificate_json["Valid until"] = match.group(2).strip()
        return certificate_json
    
    def get_ssl_certificate_info(self, website_url: str) -> dict:
        # Check if the domain is reachable, if not, add www.

        url = f"{self.BASE_URL}#hostname={website_url}"

        # Set up the Selenium WebDriver
        driver = webdriver.Chrome()

        try:
            # Navigate to the page
            driver.get(url)

            try:
                result = get_screenshot_and_element_by_class_name(driver, "checker_certs")
                element = result.get("element")
                image = result.get("image")

                first_row = element.find_element(By.CSS_SELECTOR, 'tbody > tr:first-of-type')
                cert_json = SSLShopper.get_certificate_json_from_list(content_list=first_row.text.split("\n"))

                return {
                    "certificate_json": cert_json,
                    "certificate_image": image,
                }
            except TimeoutException:
                log.info("No certificate chain found, trying to get the summary instead")
                
                # Try to find the checker_messages element and take screenshot of it
                try:
                    result = get_screenshot_and_element_by_class_name(driver, "checker_messages")    
                    
                    # In this case we will not have the certificate JSON
                    element = None
                    image = result.get("image")    

                    return {
                        "certificate_json": None,
                        "certificate_image": image,
                    }   
                except Exception as inner_e:
                    log.error(f"Failed to capture 'checker_messages' element: {inner_e}")
                    return {
                        "error": "Failed to find both certificate info and error messages"
                    }

        except Exception as e:
            log.error(f"An error occurred: {e}")
            return {"error": str(e)}

        finally:
            # Close the browser
            driver.quit()
