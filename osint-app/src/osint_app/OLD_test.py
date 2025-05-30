from re import search
from enum import Enum
from typeguard import typechecked

import requests as http
import json
import os
import re
import zipfile
import csv
import time
from bs4 import BeautifulSoup
from shodan import Shodan
import wappalyzer

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from PIL import Image
import io

import sys

import socket

# Process files in parallel
import concurrent.futures
    

EMAIL_WITHOUT_DOMAIN_REGEX = r"[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@"
SERVICES_EMPLOYED = [
    "haveibeenpwned",
    "intelx",
    "abuseipdb",
    "httpsecurityheaders",
    "sslshopper",
    "shodan",
    "dnsdumpster",
    "mxtoolbox",
    "wappalyzer",
]
INTELX_BUCKETS = [
    "pastes",
    "darknet.tor",
    "darknet.i2p",
    "whois",
    "usenet",
    "leaks.private.general",
    "leaks.private.comb",
    "leaks.logs",
    "leaks.public.wikileaks",
    "leaks.public.general",
    "dumpster",
    "documents.public.scihub"
]

BASE_DIR = os.path.join(os.path.expanduser("~"), "prove")
HAVEIBEENPWNED_REQUEST_DELAY_IN_SECONDS = 1

@typechecked
def retrieve_base_urls() -> dict:
    base_urls = dict()
    config_path = os.getenv("API_BASE_URLS_PATH", "/home/kali/iei/api-base-urls.json")
    
    try:
        with open(config_path, "r") as f:
            base_urls = json.load(f)  # Corrected from json.loads(f)
    except FileNotFoundError:
        print("Error: Base URLs file not found.")
    except PermissionError:
        print("Error: Permission denied when accessing the base URLs file.")
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON from the base URLs file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    return base_urls


@typechecked
def retrieve_api_keys() -> dict:
    api_keys = dict()
    try:
        with open("/home/kali/iei/api-keys.json", "r") as f:
            api_keys = json.load(f)
        return api_keys
    
    except FileNotFoundError:
        print("Error: API keys file not found.")
    except PermissionError:
        print("Error: Permission denied when accessing the API keys file.")
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON from the API keys file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return api_keys


@typechecked
class IntelX:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://2.intelx.io"

    '''
    The following function is used to perform a search using the IntelX API.
    It takes the following parameters:
        term: str               # The search term to use (e.g., the domain)
        buckets: list[str]      # The buckets to search in
        maxresults: int         # The maximum number of results to return
        sort: int               # The sorting order (0 to 4)
        media: int              # The media type (0 to 24) 

    It returns the id to be used to retrieve the search results
    '''
    def intelligent_search(self, term: str, buckets = None, maxresults: int = 1000, sort: int = 2, media: int = 0) -> str | None:
        # TODO: Validation
        search_id = None
        if buckets is None:
            buckets = []

        url = f"{self.base_url}/intelligent/search"

        payload = {
            "term": term,
            "buckets": buckets,
            "maxresults": maxresults,
            "sort": sort,
            "media": media,
            "lookuplevel": 0,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "terminate": []
        }

        headers = {"x-key": self.api_key}

        try:
            result = http.post(
                url=url,
                headers=headers,
                json=payload,
                timeout=10
            )
            result.raise_for_status()                       # Raises an HTTPError for bad responses
            search_id = result.json().get("id")             # The search ID to retrieve results for
        except http.exceptions.RequestException as e:
            print(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            print("Failed to parse search response JSON.")
        except Exception as e:
            print(f"Unexpected error while performing search request: {e}")
        return search_id
    '''
    The following function is used to export the search results from IntelX API.
    It takes the following parameters:
        search_id: str      # The search ID to retrieve results for
        limit: int          # The number of results to retrieve
        filetype: str       # The file type to export ("csv" or "zip")
    '''
    def intelligent_search_export(self, search_id: str, filetype: str, limit: int = 1000) -> bytes | None:
        # TODO: Validation

        if filetype not in ["csv", "zip"]:
            raise ValueError("Invalid file type. Must be 'csv' or 'zip'.")

        if filetype == "csv":
            f = 0
        elif filetype == "zip":
            f = 1
        else:
            raise ValueError("Invalid file type. Must be 'csv' or 'zip'.")

        url = f"{self.base_url}/intelligent/search/export"
        
        params={
            "id": search_id,
            "f": f,
            "l": limit,
            "k": self.api_key,
        }

        try:  
            result = http.get(
                url=url,
                params=params,
                timeout=300     # Longer timeout for large files
            )
            result.raise_for_status()   

            return result.content    
                
        except http.exceptions.RequestException as e:       
            print(f"Network error during search export request: {e}")
        except http.Timeout:
            print("Request timed out. The file might be too large.")
        except Exception as e:
            print(f"Unexpected error while performing search export request: {e}")
        return None


    '''
    The following function is used to perform a search in the phonebook using the IntelX API.
    It takes the following parameters:
        term: str               # The search term to use (e.g., the domain)
        maxresults: int         # The maximum number of results to return
        media: int              # The media type (0 to 24)
        terminate: list[str]    # The list containing the previous search ids to terminate
        target: int             # The target type (e.g., 0 for all, 1 is for domains, etc.)
    It returns the id to be used to retrieve the search results
    '''
    def phonebook_search(self, term: str, maxresults: int = 1000, media: int = 0, terminate=None, target: int = 0) -> str | None:
        """Launch a *Phonebook* search on IntelX.

        Args:
            term:       Search string – typically a domain name, e-mail address,
                        IPv4/IPv6 or hash.
            maxresults: Maximum number of result records to be collected by
                        IntelX (server-side limit, default 1 000).
            media:      IntelX *media* code (0–24) that restricts the search to
                        specific data types.  The default value 0 means “all media”.
            terminate:  List of other search IDs that should be cancelled before
                        this one starts.  *None* (default) means no termination.

            target: IntelX *target* selector  
                    0 = all object types,  
                    1 = domains,  
                    2 = e-mail addresses,  
                    3 = IPv4/6, etc.

        Returns:
            The newly issued **search ID** as a string, or *None* if the HTTP
            request failed or the response could not be decoded.

        Notes:
            The returned ID is required later when you call
            `phonebook_search_result()` to pull down the actual rows.
        """
        if terminate is None:
            terminate = []

        url = f"{self.base_url}/phonebook/search"

        payload = {
            "term":term,
            "maxresults":maxresults,
            "media":media,
            "terminate":terminate,
            "target":target
        }

        headers = {"x-key": self.api_key}

        try:
            result = http.post(
                url=url,
                headers=headers,
                json=payload,
                timeout=10
            )
            result.raise_for_status()                       # Raises an HTTPError for bad responses
            search_id = result.json().get("id")             # The search ID to retrieve results for
            return search_id
        except http.exceptions.RequestException as e:
            print(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            print("Failed to parse search response JSON.")
        except Exception as e:
            print(f"Unexpected error while performing search request: {e}")
        return None


    '''
    The following function is used to retrieve the search results from the phonebook in IntelX API.
    It takes the following parameters:
        search_id: str      # The search ID to retrieve results for
        limit: int          # The number of results to retrieve

    It returns the search results as a dictionary.
    '''
    def phonebook_search_result(self, search_id: str, limit: int = 1000) -> dict:
        url = f"{self.base_url}/phonebook/search/result"
        search_result = dict()

        params = {
            "id": search_id,
            "limit": limit
        }
        headers = {"x-key": self.api_key}

        try:
            result = http.get(
                url=url,
                params=params,
                headers=headers,
                timeout=10
            )
            result.raise_for_status()                       # Raises an HTTPError for bad responses
            search_result = result.json()
        except http.exceptions.RequestException as e:
            print(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            print("Failed to parse search response JSON.")
        except Exception as e:
            print(f"Unexpected error while performing search request: {e}")
        return search_result


#################################### END CLASS INTELX ####################################

@typechecked
class HaveIBeenPwned:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://haveibeenpwned.com/api/v3"
    

    def get_breaches_from_account(self, account: str, truncate_response: bool) -> list[dict]:
        url = f"{self.base_url}/breachedaccount/{account}"
        headers = {"hibp-api-key": self.api_key}

        breaches = list()

        params = {
            "truncateResponse": truncate_response
        }

        try:
            result = http.get(
                url=url,
                params=params,
                headers=headers 
            )
            result.raise_for_status()
            breaches = [breach for breach in json.loads(result.text)]

            return breaches

        except http.exceptions.RequestException as e:      
            status_code = e.response.status_code
            if status_code == 404:
                print(f"{account} was not found in any breaches")
            elif status_code == 429:
                print("Too many requests: slow down!")
        except Exception as e:
            print(f"Unexpected error while performing search export request: {e}")
        return breaches 
        
#################################### END CLASS HAVEIBEENPWNED ####################################


class C99:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.c99.nl"

    '''
    The following function is used to perform a subdomains search.
    It takes the following parameters:
        domain: str               
        
    It returns the subdomains found for the given domain
    '''
    def subdomain_finder(self, domain: str) -> list[str]:
        subdomains = list()
        url = f"{self.base_url}/subdomainfinder"

        # Here we are forced to write the params string manually since json parameter does not accept values
        params = f"key={self.api_key}&domain={domain}&json"

        try:
            result = http.get(
                url=url,
                params=params,
                timeout=10
            )
            result.raise_for_status()                       # Raises an HTTPError for bad responses

            search_result = json.loads(result.text)

            if "success" in search_result and search_result["success"] == False:
                print(f"No subdomains found for {domain} by C99")
                return subdomains

            # Extract just the subdomains from the response
            subdomains = [subdomain["subdomain"] for subdomain in search_result["subdomains"]]

        except http.exceptions.RequestException as e:
            print(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            print("Failed to parse search response JSON.")
        except Exception as e:
            print(f"Unexpected error while performing search request: {e}")
        return subdomains


#################################### END CLASS C99 ####################################


@typechecked
class AbuseIPDB:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.__report_categories = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }

    '''
    The following function is used to check if an IP address has been reported.
    It takes the following parameters:
        ip: str               # The IP address to check
    It returns a list of reports for the given IP address.
    '''
    def check_ip(self, ip: str) -> dict:
        url = f'{self.base_url}/check'

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '365',
            'verbose': True
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        response = http.get(
            url,
            headers=headers,
            params=querystring
        )

        # Formatted output
        decoded_response = json.loads(response.text)

        return decoded_response

    '''
    The following function is used to get the reports from the check_ip function.
    It takes the following parameters:
        ip: str               # The IP address to check
    It returns a list of reports for the given IP address.
    '''
    def get_reports_from_check_ip(self, ip: str) -> list:
        decoded_response = self.check_ip(ip)

        reports = list()

        for report in decoded_response["data"]["reports"]:
            reported_at = report["reportedAt"]
            comment = report["comment"]
            # Simply convert categories numbers to labels
            categories = [self.__report_categories[category_number] for category_number in report["categories"]]

            reports.append({
                "reportedAt": reported_at,
                "comment": comment,
                "categories": categories
            })

        return reports

    '''
    The following function is used to check a list of IP addresses for reports.
    It takes the following parameters:
        ips: list[str]        # The list of IP addresses to check
    It returns a dictionary with the IP addresses as keys and the reports as values.
    Not reported IP addresses are not included in the dictionary.
    '''
    def get_abused_ips_reports(self, ips: list[str]) -> dict:
        abused_ips_reports = dict()
        for ip in ips:
            report = self.get_reports_from_check_ip(ip)
            if len(report) > 0:
                abused_ips_reports[ip] = report
        return abused_ips_reports

#################################### END CLASS ABUSEIPDB ####################################


@typechecked
class HTTPSecurityHeaders:
    def __init__(self):
        self.__security_headers_description = {
            "Content-Security-Policy": "A security standard to prevent a wide range of attacks such as XSS and data injection by specifying domains the browser should trust.",
            "Strict-Transport-Security": "Forces browsers to use HTTPS with an optional max age and preload directives, helping to prevent man-in-the-middle attacks.",
            "X-Frame-Options": "Protects against clickjacking by controlling whether a page can be embedded in a frame.",
            "X-Content-Type-Options": "Prevents MIME type sniffing thereby reducing exposure to drive-by download attacks.",
            "Referrer-Policy": "Controls the amount of referrer information in requests, enhancing user privacy and security.",
            "Permissions-Policy": "Manages access to browser features like geolocation, camera, etc., providing granular control to enhance security.",
            "Cross-Origin-Opener-Policy": "Helps prevent cross-origin attacks like Spectre, isolating resources by controlling if a window can share a browsing context.",
            "Cross-Origin-Resource-Policy": "Restricts sharing of resources across origins, mitigating risk of data exposure and cross-site attacks.",
            "Cross-Origin-Embedder-Policy": "Ensures that a document can only load resources that are securely isolated, helping to prevent spectre-like attacks.",
            "Cache-Control": "Controls the caching behavior of responses, which can mitigate leakage of sensitive data through cached content.",
            "Expect-CT": "Ensures correct certificate transparency and pinning, aiding in preventing the use of misissued certificates.",
            "Feature-Policy": "Deprecated, replaced by Permissions-Policy, used to restrict features that browser could use to enhance security.",
            "Access-Control-Allow-Origin": "Enables Cross-Origin Resource Sharing (CORS) to specify domains allowed to access resources, preventing unauthorized resource access.",
            "Public-Key-Pins": "Allows the app to pin the public key of the SSL certificate, reducing risk of man-in-the-middle attacks with misissued certificates.",
            "Content-Type": "Indicates the media type of the resource, crucial for logical handling of the content to prevent security vulnerabilities."
        }
        self.__security_headers = set(self.__security_headers_description.keys())

    '''
    The following function is used to check the security headers of a domain.
    It takes the following parameters:
        domain: str               # The domain to check
    It returns the security headers for the given domain.
    '''
    def get_missing_security_headers_with_description(self, domain: str) -> dict:
        url = f"https://{domain}"
        missing_security_headers = dict()
        try:
            result = http.get(
                url=url,
                timeout=5
            )
            result.raise_for_status
            headers = set(result.headers.keys())
            missing = self.__security_headers - headers

            for k,v in self.__security_headers_description.items():
                if k in missing:
                    missing_security_headers[k] = v

            return missing_security_headers
        except json.JSONDecodeError:
            print("Failed to parse search response JSON.")
            missing_security_headers["error"] = "Failed to parse search response JSON."
            return missing_security_headers
        except (http.Timeout, http.exceptions.RequestException) as e:
            if "www" not in domain:
                return self.get_missing_security_headers_with_description(domain=f"www.{domain}")
            else:
                missing_security_headers["error"] = "Timeout" if isinstance(e, http.Timeout) else "RequestException"
                return missing_security_headers
            

######################################## END CLASS HTTPSecurityHeaders ####################################

@typechecked
class SSLShopper:
    def __init__(self):
        self.base_url = "https://www.sslshopper.com/ssl-checker.html"

    @staticmethod
    def get_certificate_json_from_list(content_list: list[str]) -> dict:
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
        return certificate_json

    '''
    The following function is used to check the SSL certificate of a domain.
    Selenium is used to retrieve the necessary information.
    It takes the following parameters:
        domain: str               # The domain to check
    It returns a dict containing the screenshot of the SSL Certificate Chain and
    the JSON representation of the server certificate (if present).
    '''
    def get_ssl_certificate_info(self, domain: str) -> dict:
        # Check if the domain is reachable, if not, add www.
        try:
            http.get(
                url = f"https://{domain}",
                timeout=5
            )
        except http.Timeout as e:
            domain = f"www.{domain}"
        
        url = f"{self.base_url}#hostname={domain}"

        # Set up the Selenium WebDriver
        driver = webdriver.Chrome()

        try:
            # Navigate to the page
            driver.get(url)

            try:
                result = get_screenshot_and_element_with_selenium_by_class_name(driver, "checker_certs")
                element = result.get("element")
                image = result.get("image")

                first_row = element.find_element(By.CSS_SELECTOR, 'tbody > tr:first-of-type')
                cert_json = SSLShopper.get_certificate_json_from_list(content_list=first_row.text.split("\n"))

                return {
                    "certificate_json": cert_json,
                    "certificate_image": image,
                }
            except TimeoutException:
                print("No certificate chain found, trying to get the summary instead")
                
                # Try to find the checker_messages element and take screenshot of it
                try:
                    result = get_screenshot_and_element_with_selenium_by_class_name(driver, "checker_messages")    
                    
                    # In this case we will not have the certificate JSON
                    element = None
                    image = result.get("image")    

                    return {
                        "certificate_json": None,
                        "certificate_image": image,
                    }   
                except Exception as inner_e:
                    print(f"Failed to capture 'checker_messages' element: {inner_e}")
                    return {
                        "error": "Failed to find both certificate info and error messages"
                    }

        except Exception as e:
            print(f"An error occurred: {e}")
            return {"error": str(e)}

        finally:
            # Close the browser
            driver.quit()
######################################## END CLASS SSLShopper ####################################

@typechecked
class VirusTotal:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    '''
    The following function is used to retrieve the subdomains of a domain.
    It takes the following parameters:
        
        domain: str               # The domain to check
    It returns a list of subdomains for the given domain.
    '''
    def get_subdomains_list(self, domain: str) -> list[str]:
        url = f"{self.base_url}/domains/{domain}/subdomains"
        headers = {"x-apikey": self.api_key}
        subdomains_list = list()
        try:
            result = http.get(
                url=url,
                headers=headers
            )
            result.raise_for_status()

            result_json = result.json()
            subdomains_list.extend([entry["id"] for entry in result_json["data"]])
            return subdomains_list
        except http.exceptions.RequestException as e:
            print(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            print("Failed to parse search response JSON.")
        except Exception as e:
            print(f"Unexpected error while performing search request: {e}")
######################################## END CLASS VirusTotal ####################################


@typechecked
class MXToolbox:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://mxtoolbox.com/api/v1/lookup"

    '''
    This function is used to retrieve the screenshot of the MXToolbox page.
    It takes the following parameters:
        action: str               # The action to perform (e.g., "spf", "dns", etc.)
    It returns the URL of the screenshot.
    '''

    def __use_selenium_to_retrieve_screenshot(action: str, domain: str) -> Image.Image:
        selenium_url = f"https://mxtoolbox.com/SuperTool.aspx?action={action}%3a{domain}&run=toolpage#"
        driver = None
        try:
            driver = webdriver.Chrome(options=webdriver.ChromeOptions().add_argument("--headless"))
            driver.get(selenium_url)
            img = get_screenshot_and_element_with_selenium_by_class_name(driver, f"lookup-type-{action}")
            return img.get("image")
        except Exception as e:
            print(f"Error taking screenshot: {e}")
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
        url = f"{self.base_url}/{action}/{domain}"
        headers = {
            "Authorization": self.api_key
        }

        try:
            result = http.get(
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
                print(f"Timeout while trying to get the {action} image")
                info[f"{action}_image"] = None

        except http.exceptions.RequestException as e:
            print(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            print("Failed to parse search response JSON.")
        except Exception as e:
            print(f"Unexpected error while performing search request: {e}")
        return info


######################################## END CLASS MXToolbox ####################################


class DNSDumpster:
    def __init__(self, api_key: str):
        self.base_url = "https://api.dnsdumpster.com"
        self.api_key = api_key

    def get_dns_records_from_domain(self, domain: str) -> dict:
        url = f"{self.base_url}/domain/{domain}"
        headers = {
            "X-API-Key": self.api_key,
        }

        dns_records = dict()

        try:
            result = http.get(
                url=url,
                headers=headers
            )
            result.raise_for_status()

            result_json = result.json()
            return result_json
        except http.exceptions.RequestException as e:
            print(f"Network error during search request: {e}")
        except json.JSONDecodeError:
            print("Failed to parse search response JSON.")
        except Exception as e:
            print(f"Unexpected error while performing search request: {e}")
        return dns_records
    
######################################## END CLASS DNSDumpster ####################################


'''
The following function is used to retrieve the credentials from a file.
It takes the following parameters:
    file_path: str               # The path to the file
    credential_regex: str        # The regex to use to extract the credentials
    
It returns a dict with the email addresses as keys and the credentials as values.
'''
@typechecked
def get_credentials_from_file(file_path: str, credential_regex: str) -> dict[str, set[str]]:
    email_credentials = dict()

    # This is done to avoid regex injection
    if len(credential_regex) > 500:
        print("Error: Credential regex is too long.")
        return email_credentials

    try:
        with open(file_path, "r") as f:
            for line in f:
                matches = re.findall(credential_regex, line)
                if matches:
                    for match in matches:
                        email, password = match.split(":")[:2]
                        
                        # Create a new list for the email if it doesn't exist
                        if email not in email_credentials:
                            email_credentials[email] = set()
                        
                        # If credentials appear in a record with a URL, we want to add the URL to the credentials
                        if "http" in line:
                            email_credentials[email].add(line.strip())
                        else:
                            # We want to add the email and password as a single string
                            credentials = f"{email}:{password}"

                            # We want to add the email and password as a single string
                            email_credentials[email].add(credentials)
                        
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except PermissionError:
        print(f"Error: Permission denied when accessing the file {file_path}.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return email_credentials


'''
The following function is used to retrieve the system IDs and names association from the Info.csv file.
It takes the following parameters:
    folder_path: str           # The path to the folder containing the Info.csv file
It returns a dictionary with the system IDs as keys and the names as values.
'''
@typechecked
def get_system_ids_names_association(folder_path: str) -> dict | None:
    system_ids_names = dict()

    try:
        print(folder_path)
        with open(os.path.join(folder_path, "Info.csv"), "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 2:
                    print("Error: Info.csv file does not contain enough columns.")
                    return None
                # We want to merge different parts of the same name
                name = row[0].split("[Part")[0].strip()

                system_id = row[-1]
                if name and system_id:
                    system_ids_names[system_id] = name
    except FileNotFoundError:
        print("Error: Info.csv file not found.")
    except PermissionError:
        print("Error: Permission denied when accessing the Info.csv file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return system_ids_names


'''
The following function is used to start the credentials retrieving process from a folder.
It takes the following parameters:
    folder_path: str           # The path to the folder containing the files
    credential_regex: str      # The regex to use to extract the credentials
It returns a dictionary with the system IDs as keys and the credentials as values.
'''
@typechecked
def OLD_start_credentials_retrieving_from_folder(folder_path: str, credential_regex: str):
    # System ID (str) to breach file name (str) association
    system_ids_names = get_system_ids_names_association(folder_path)

    # Breach file name (str) to credentials (list[str]) association
    credentials = {name: [] for name in system_ids_names.values()}

    if system_ids_names is None:
        print("Error: System IDs and names association could not be retrieved.")
        return None

    for file in os.listdir(folder_path):
        if file == "Info.csv" or file.lower().split(".")[-1] not in ["txt","csv"]:
            continue
        print(f"Processing file: {file}")
        
        # The file name without extension is used to match the system ID
        file_without_extension = file.split(".")[0]
        breach_file = system_ids_names.get(file_without_extension)

        # If there's a file which does not appear in the Info.csv file, we want to add it to the credentials dictionary
        if not breach_file:
            credentials[file] = list()
            breach_file = file
        
        credential_retrieved_from_file = get_credentials_from_file(os.path.join(BASE_DIR, folder_path, file), credential_regex)
    
        credentials[breach_file].extend(credential_retrieved_from_file)

    # Remove files with no interesting credentials
    keys = list(credentials.keys())
    for key in keys:
        if not credentials[key]:
            del credentials[key]

    return credentials


'''
The following function is used to start the credentials retrieving process from a folder.
It uses multiprocessing to speed up the process.
It takes the following parameters:
    folder_path: str           # The path to the folder containing the files
    credential_regex: str      # The regex to use to extract the credentials
It returns a dictionary with the email addresses as keys and the credentials as values.
'''
@typechecked
def start_credentials_retrieving_from_folder(folder_path: str, credential_regex: str):
    # Breach file name (str) to credentials (list[str]) association
    credentials = {}
    
    # Get list of files to process
    files_to_process = [
        file for file in os.listdir(folder_path) 
        if file != "Info.csv" and file.lower().split(".")[-1] in ["txt", "csv"]
    ]
    
    with concurrent.futures.ProcessPoolExecutor() as executor:
        # Create a dictionary to track futures
        future_to_file = {
            executor.submit(
                get_credentials_from_file, 
                os.path.join(BASE_DIR, folder_path, file), 
                credential_regex
            ): file for file in files_to_process
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_file):
            file = future_to_file[future]
            print(f"Processing file: {file}")
            try:
                file_credentials = future.result()
                # Merge the results
                for email, credentials_set in file_credentials.items():
                    if email not in credentials:
                        credentials[email] = set()
                    credentials[email] = credentials[email].union(credentials_set)
            except Exception as e:
                print(f"Error processing {file}: {e}")

        # Sort the credentials dictionary by email
        credentials = dict(sorted(credentials.items(), key=lambda item: item[0]))

        # Sort the credentials for each email (it also converts the set to a list, which is necessary for JSON serialization)
        for email in credentials:
            credentials[email] = sorted(credentials[email])
    return credentials


'''
The following function is used to take a screenshot of an element with Selenium.
It takes the following parameters:
    driver: webdriver.Chrome   # The Selenium WebDriver
    class_name: str            # The class name of the element to take a screenshot of
It returns a dictionary with the element and the image.

'''
@typechecked
def get_screenshot_and_element_with_selenium_by_class_name(driver: webdriver.Chrome, class_name: str) -> dict:
    WebDriverWait(driver, 30).until(
        EC.visibility_of_element_located((By.CLASS_NAME, class_name))
    )

    # Remove advertisement elements
    driver.execute_script("""
        var ele = document.getElementsByClassName('bsaStickyLeaderboard')[0];
        if (ele) { ele.parentNode.removeChild(ele); }
        var ele = document.getElementById('promo-outer');
        if (ele) { ele.parentNode.removeChild(ele); }
    """)

    # Wait for the page to load completely
    time.sleep(0.5)
    # Find the element containing the certificate chain information
    element = driver.find_element(By.CLASS_NAME, class_name)

    # Get the size of the element
    element_height = element.size['height']
    element_width = element.size['width']

    # Set window size to accommodate the element
    driver.set_window_size(max(1024, element_width + 100), max(768, element_height + 200))

    # Make sure element is in view
    driver.execute_script("arguments[0].scrollIntoView(true);", element)

    image_binary = element.screenshot_as_png
    img = Image.open(io.BytesIO(image_binary))

    return {
        "element": element,
        "image": img,
    }


''' 
The following function is used to save a dictionary to a JSON file.
It takes the following parameters:
    dictionary: dict          # The dictionary to save
    file_path: str            # The path to the file
'''
@typechecked
def save_dict_to_json_file(dictionary: dict, file_path: str):
    try:
        with open(file_path, "w") as f:
            json.dump(dictionary, f, indent=4)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except PermissionError:
        print(f"Error: Permission denied when accessing the file {file_path}.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


'''
The following function is used to create the working directories for the domain and the services.
It takes the following parameters:
    domain: str               # The domain to create the directories for
    services: list[str]       # The list of services to create the directories for
It creates a directory for the domain and a subdirectory for each service.
'''
@typechecked
def create_working_directories(domain: str, services: list[str]):
    # Create a directory for the domain if it doesn't exist
    if not os.path.exists(os.path.join(BASE_DIR, domain)):
        os.makedirs(os.path.join(BASE_DIR, domain))
        print(f"Created directory: {os.path.join(BASE_DIR, domain)}")

    for service in services:
        dir_path = os.path.join(BASE_DIR, domain, service)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)


'''
The following function is used to retrieve the breached emails from the credentials file.
It takes the following parameters:
    credentials_path: str     # The path to the credentials file
It returns a set of breached emails.
'''
@typechecked
def OLD_get_breached_emails(credentials_path: str) -> set[str]:
    # If the credential.json file exists
    if os.path.exists(credentials_path):
        try:
            with open(credentials_path, "r") as f:
                credentials = json.load(f)
            breached_emails = set()
            for _, creds in credentials.items():
                # Separate the email from the password
                leaked_in_this_file = set([creds.split(":")[0] for creds in creds if ":" in creds])
                breached_emails = breached_emails.union(leaked_in_this_file)
            return breached_emails
        except FileNotFoundError:
            print(f"Error: File {credentials_path} not found.")
        except PermissionError:
            print(f"Error: Permission denied when accessing the file {credentials_path}.")
        except json.JSONDecodeError:
            print(f"Error: Failed to decode JSON from the file {credentials_path}.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        
    return set()

'''
The following function is used to retrieve the breached emails from the credentials file.
It takes the following parameters:
    credentials_path: str     # The path to the credentials file
It returns a set of breached emails.
'''
@typechecked
def get_breached_emails(credentials_path: str) -> set[str]:
    # If the credential.json file exists
    if os.path.exists(credentials_path):
        try:
            with open(credentials_path, "r") as f:
                credentials = json.load(f)         
            return set(credentials.keys())
        except FileNotFoundError:
            print(f"Error: File {credentials_path} not found.")
        except PermissionError:
            print(f"Error: Permission denied when accessing the file {credentials_path}.")
        except json.JSONDecodeError:
            print(f"Error: Failed to decode JSON from the file {credentials_path}.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        
    return set()


@typechecked
def get_all_ips_from_host(host: str) -> list[str]:
    """Retrieve all IP addresses associated with a hostname.
    
    Args:
        host (str): The hostname to resolve.
        
    Returns:
        list[str]: List of IP addresses associated with the hostname.
        
    Raises:
        socket.gaierror: If the hostname cannot be resolved.
    """
    try:
        _, _, ip_addresses = socket.gethostbyname_ex(host)
        return ip_addresses
    except socket.gaierror as e:
        print(f"Unable to resolve host {host}: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error while resolving host {host}: {e}")
        return []

@typechecked
def get_ips_from_hosts(hosts: list[str], max_workers: int = 20, timeout: int = 10) -> dict[str, list[str]]:
    """Resolve multiple hostnames to their IP addresses in parallel.
    
    Uses a thread pool to perform DNS resolution in parallel, significantly
    improving performance when processing many hostnames.
    
    Args:
        hosts (list[str]): List of hostnames to resolve.
        max_workers (int, optional): Maximum number of parallel workers. Defaults to 20.
        timeout (int, optional): Maximum time in seconds to wait for resolution. Defaults to 10.
        
    Returns:
        dict[str, list[str]]: Dictionary mapping hostnames to lists of IP addresses.
    """
    ip_addresses = {}
    
    # Define a helper function to process each host
    def process_host(host):
        try:
            ips = get_all_ips_from_host(host)
            return host, ips
        except Exception as e:
            print(f"Error processing {host}: {e}")
            return host, []
    
    # Use ThreadPoolExecutor for parallel DNS resolution
    # (ThreadPoolExecutor is better than ProcessPoolExecutor for I/O-bound tasks)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Start the operations and mark each future with its hostname
        future_to_host = {executor.submit(process_host, host): host for host in hosts}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_host, timeout=timeout):
            try:
                host, ips = future.result()
                if ips:  # Only add hosts that resolved successfully
                    ip_addresses[host] = ips
            except concurrent.futures.TimeoutError:
                host = future_to_host[future]
                print(f"DNS resolution timed out for {host}")
            except Exception as e:
                host = future_to_host[future]
                print(f"Exception while processing {host}: {e}")
    
    return ip_addresses

'''
The following function is used to groom the Shodan information.
It takes the following parameters:
    host_info: dict          # The host information to groom
It returns a dictionary with the groomed information.
'''
@typechecked
def get_groomed_shodan_info(host_info: dict):
    groomed_info = dict()
    # Exposed ports
    groomed_info["asn"] = host_info["asn"]
    groomed_info["isp"] = host_info["isp"]

    old_data = host_info["data"]
    new_data = list()
    exposed_service_as_is = ["os", "port", "product", "transport", "version"]

    # Services section
    for exposed_service in old_data:
        to_add = dict()
        for field in exposed_service_as_is:
            if field in exposed_service:
                to_add[field] = exposed_service[field]

        port = transport = product = version = ""


        if "port" in to_add:
            port = to_add["port"]
        if "transport" in to_add:
            transport = to_add["transport"]
        if "product" in to_add:
            product = to_add["product"]
        if "version" in to_add:
            version = to_add["version"]

        name = f"{port}/{transport}/{product}/{version}"
        re.sub("/{2,}", "/", name)          # Remove multiple slashes caused by empty fields
        name = re.sub(r"^/|/$", "", name)   # Remove leading and trailing slashes

        to_add["name"] = name
        
        new_data.append(to_add)

    groomed_info["data"] = new_data
    
    # CVEs section
    new_vulns = list()

    if "vulns" not in host_info:
        print("No CVEs found in the host information.")
        return groomed_info
    
    vulns = host_info["vulns"]

    for cve in vulns:
        to_add = dict()
        try:
            result = http.get(f"https://cvedb.shodan.io/cve/{cve}")

            result.raise_for_status()

            result_json = result.json()

            to_add["cve_id"] = result_json["cve_id"]
            to_add["summary"] = result_json["summary"]
            to_add["cvss"] = result_json["cvss"]

            new_vulns.append(to_add)
        except http.exceptions.RequestException as e:
            print(f"Network error during CVE request: {e}")
        except json.JSONDecodeError:
            print("Failed to parse CVE response JSON.")
        except Exception as e:
            print(f"Unexpected error while performing CVE request: {e}")

    groomed_info["vulns"] = new_vulns

    return groomed_info

'''
The following function is used to groom the DNSDumpster information.
It takes the following parameters:
    dns_records: dict        # The DNS records to groom
It returns a dictionary with the groomed information.
'''
@typechecked
def get_groomed_dnsdumpster_info(dns_records: dict) -> dict:
    groomed_info = dict()

    for record_type, records in dns_records.items():
        # For example for the "total_a_recs", which is an int
        if type(records) is not list:
            continue

        # For TXT records, we want to keep the record as is
        if record_type == "txt":
            groomed_info[record_type] = records
        # We filter out some data we don't need
        else:
            groomed_info[record_type] = list()
            for record in records:
                new_record = dict()
                try:
                    if "host" in record:
                        new_record["host"] = record["host"]
                    if "ips" in record:
                        new_record["ips"] = list()
                        for ip in record["ips"]:
                            to_add = dict()
                            if "asn" in ip:
                                to_add["asn"] = ip["asn"]
                            if "asn_name" in ip:
                                to_add["asn_name"] = ip["asn_name"]
                            if "ip" in ip:
                                to_add["ip"] = ip["ip"]
                            new_record["ips"].append(to_add)               
                except KeyError as e:
                    print(f"KeyError: {e} in record {record}")
                groomed_info[record_type].append(new_record)
    return groomed_info
    

def get_name_and_info_from_dicts_in_list(entries: list[dict]) -> list:
    return [
        {
            "Name": entry["Name"],
            "Info": entry["Info"],
        } for entry in entries
    ]

@typechecked
def get_groomed_mxtoolbox_lookup(info: dict) -> dict:
    groomed_info = dict()

    # Get the command argument (in this case the domain)
    groomed_info["CommandArgument"] = info.get("CommandArgument", "")
    groomed_info["TimeRecorded"] = info.get("TimeRecorded", "")
    groomed_info["Command"] = info.get("Command", "")
    groomed_info["Records"] = info.get("Records", [])
    
    if "Failed" in info:
        # Get Name and Info from each failed entry
        groomed_info["Failed"] = get_name_and_info_from_dicts_in_list(info["Failed"])
    if "Warnings" in info:
        # Get Name and Info from each warnings entry
        groomed_info["Warnings"] = get_name_and_info_from_dicts_in_list(info["Warnings"])
    if "Passed" in info:
        # Get Name and Info from each passed entry
        groomed_info["Passed"] = get_name_and_info_from_dicts_in_list(info["Passed"])
    return groomed_info


'''
The following function is used to aggregate the values from a dictionary without duplicates.
It takes the following parameters:
    dictionary: dict         # The dictionary to aggregate
It returns a list of unique values from the dictionary.
'''
@typechecked
def aggregate_values_from_dict_with_no_duplicates(dictionary: dict) -> list[str]:
    ips = [ip for ip_list in dictionary.values() for ip in ip_list]
    ips = list(set(ips))
    return ips

def main():
    api_keys = retrieve_api_keys()

    #web_domain = "internet-idee.net"
    #mail_domain = "internet-idee.net"
    web_domain = "mediocrati.it"
    mail_domain = "mediocrati.bcc.it"
    domain = web_domain if web_domain else mail_domain
    # Create a directory for the domain if it doesn't exist
    create_working_directories(domain, SERVICES_EMPLOYED)

    intelx = IntelX(api_key=os.getenv("INTELX"))
    haveibeenpwned = HaveIBeenPwned(api_key=os.getenv("HAVEIBEENPWNED"))
    c99 = C99(api_key=os.getenv("C99"))
    abuseipdb = AbuseIPDB(api_key=  os.getenv("ABUSEIPDB"))
    httpsecurityheaders = HTTPSecurityHeaders()
    sslshopper = SSLShopper()
    shodan = Shodan(key=os.getenv("SHODAN"))
    virustotal = VirusTotal(api_key=os.getenv("VIRUSTOTAL"))
    dnsdumpster = DNSDumpster(api_key=os.getenv("DNSDUMPSTER"))
    mxtoolbox = MXToolbox(api_key=os.getenv("MXTOOLBOX"))
     
    credential_regex = rf"{EMAIL_WITHOUT_DOMAIN_REGEX}{mail_domain}:\S+"
    website_url = f"https://{web_domain}"

    try:
        result = http.get(
            url=website_url,
            timeout=3
        )
    except http.Timeout as e:
        website_url = f"https://www.{web_domain}"


    ##### Web app fingerprinting
    # Wappalyzer
    
    # With options
    results = wappalyzer.analyze(
        url=website_url,
        scan_type='balanced',  # 'fast', 'balanced', or 'full'
        threads=8,
        cookie='sessionid=abc123'
    )

    save_dict_to_json_file(
        dictionary=results,
        file_path=os.path.join(BASE_DIR, domain, "wappalyzer", "wappalyzer_info.json")
    )

    
    ##### SPF and DMARC record lookup
    ### MXToolbox
    spf_info = mxtoolbox.get_action_info_from_domain(domain=web_domain, action="spf")
    dmarc_info = mxtoolbox.get_action_info_from_domain(domain=web_domain, action="dmarc")

    save_dict_to_json_file(
        dictionary=get_groomed_mxtoolbox_lookup(info=spf_info.get("spf_json")),
        file_path=os.path.join(BASE_DIR, domain, "mxtoolbox", "spf_info.json")
    )

    save_dict_to_json_file(
        dictionary=get_groomed_mxtoolbox_lookup(info=dmarc_info.get("dmarc_json")),
        file_path=os.path.join(BASE_DIR, domain, "mxtoolbox", "dmarc_info.json")
    )


    spf_img = spf_info.get("spf_image")
    if spf_img is not None:
        # Save the image
        spf_img.save(os.path.join(BASE_DIR, domain, "mxtoolbox", "spf_record.png"))

    dmarc_img = dmarc_info.get("dmarc_image")
    if dmarc_img is not None:
        # Save the image
        dmarc_img.save(os.path.join(BASE_DIR, domain, "mxtoolbox", "dmarc_record.png"))
    # Screenshot of DMARC and SPF info

    
    ##### DNS Analysis
    ### DNSDumpster
    print("DNSDumpster")
    dns_records = get_groomed_dnsdumpster_info(dnsdumpster.get_dns_records_from_domain(domain))
    save_dict_to_json_file(
        dictionary=dns_records,
        file_path=os.path.join(BASE_DIR, domain, "dnsdumpster", "dns_records.json")
    )

    ##### HTTP Security Headers Check
    ### HTTP Security Headers
    print("HTTP Security Headers")
    missing_headers_descriptions = httpsecurityheaders.get_missing_security_headers_with_description(web_domain)
    if missing_headers_descriptions:
        save_dict_to_json_file(
            dictionary=missing_headers_descriptions,
            file_path=os.path.join(BASE_DIR, domain, "httpsecurityheaders", "missing_security_headers.json")
        )

    ###### SSL Certificate Chain + Data
    ### SSLShopper
    print("SSLShopper")
    certificate_info = sslshopper.get_ssl_certificate_info(web_domain)

    if "certificate_json" and "certificate_image" in certificate_info:
        # Save the certificate image
        certificate_image = certificate_info["certificate_image"]
        certificate_image.save(os.path.join(BASE_DIR, domain, "sslshopper", "certificate_chain.png"))

        # Save the certificate JSON
        save_dict_to_json_file(
            dictionary=certificate_info["certificate_json"],
            file_path=os.path.join(BASE_DIR, domain, "sslshopper", "certificate_data.json")
        )

    ##### Subdomains retrieving
    subdomains = set()

    ### VirusTotal
    virustotal_subdomains = virustotal.get_subdomains_list(web_domain)

    ### C99
    print("C99")
    subdomain_result = c99.subdomain_finder(web_domain)

    ### IntelX
    phonebook_search_id = intelx.phonebook_search(term=web_domain, target=1)

    if phonebook_search_id is not None:
        phonebook_search_result = intelx.phonebook_search_result(search_id=phonebook_search_id, limit=1000)
        if phonebook_search_result is not None:
            phonebook_result = list()
            if "selectors" in phonebook_search_result:
                for entry in phonebook_search_result["selectors"]:
                    if "selectorvalue" in entry:
                        phonebook_result.append(entry["selectorvalue"])

        else:
            print("Error: Phonebook search result is None")
    else:
        print("Error: Phonebook search ID is None")
    
    # Merge the subdomains from C99, IntelX, and VirusTotal into a sorted (list)
    subdomains = sorted(set(subdomain_result).union(set(phonebook_result)).union(set(virustotal_subdomains)))
    print(f"Subdomains found: {subdomains}")

    if len(subdomains) > 0:
        # Save the subdomains to a TXT file
        with open(os.path.join(BASE_DIR, domain, "subdomains.txt"), "w") as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        
        ### AbuseIPDB
        print("AbuseIPDB")
        hosts_ips = get_ips_from_hosts(subdomains)
        print(f"Hosts IPs: {hosts_ips}")

        ips = aggregate_values_from_dict_with_no_duplicates(hosts_ips)

        save_dict_to_json_file(
            dictionary=abuseipdb.get_abused_ips_reports(ips=ips),
            file_path=os.path.join(BASE_DIR, domain, "abuseipdb", "abused_ips.json")
        )
    
        ### Shodan
        print("Shodan")
        for ip in ips:
            # Get the host information from Shodan
            try:
                host_info = shodan.host(ip)
            except Exception as e:
                print(f"Error retrieving host information for {ip}: {e}")
                host_info = None

            if host_info:
                os.makedirs(os.path.join(BASE_DIR, domain, "shodan", ip), exist_ok=True)

                groomed_json = get_groomed_shodan_info(host_info)

                save_dict_to_json_file(
                    dictionary=groomed_json,
                    file_path=os.path.join(BASE_DIR, domain, "shodan", ip, "shodan_info.json")
                )
    
    
    ##### Leaked Credentials
    ### IntelX
    intelligent_search_id = intelx.intelligent_search(term=mail_domain, media=0, buckets=INTELX_BUCKETS, maxresults=5000)

    intelx_breach_files = os.path.join(BASE_DIR, domain, "intelx", "breach_files")
    credentials_path = os.path.join(BASE_DIR, domain, "intelx", "credentials.json")
    
    if intelligent_search_id is not None:
        filetype = "zip"  # or "csv"

        content = intelx.intelligent_search_export(search_id=intelligent_search_id, limit=5000, filetype=filetype)

        if content is not None:
            # Writes to disk the search results (as a CSV or ZIP file)
            filename = f"intelx_search_{intelligent_search_id}.{filetype}"
            with open(filename, "wb") as f:
                f.write(content)
                print(f"Search results exported successfully to {filename}")

            if filetype == "zip":
                try:
                    with zipfile.ZipFile(filename, "r") as zip_file:
                        zip_file.extractall(os.path.join(BASE_DIR, domain, "intelx", "breach_files"))
                    os.remove(filename)
                except zipfile.BadZipFile:
                    print(f"Error: {filename} is not a valid zip file.")
                except FileNotFoundError:
                    print(f"Error: {filename} not found.")
                except PermissionError:
                    print(f"Error: Permission denied when accessing {filename}.")
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")
            elif filetype == "csv":
                pass

            if os.path.exists(intelx_breach_files):
                extracted_credentials = start_credentials_retrieving_from_folder(intelx_breach_files, credential_regex)

                save_dict_to_json_file(
                    dictionary=extracted_credentials,
                    file_path=credentials_path
                )
        else:
            print("Error: Intelligent search export result is empty")
    

    # Extract all the emails from the dataleaks
    if os.path.exists(credentials_path):
        breached_emails = get_breached_emails(credentials_path)
        breaches_path = os.path.join(BASE_DIR, domain, "haveibeenpwned", "breached_accounts.json")
        emails_breaches = dict()

        for email in breached_emails:
            breaches = haveibeenpwned.get_breaches_from_account(email, False)
            emails_breaches[email] = breaches

            # Necessary since the api key we are provided with has a rate limit
            time.sleep(HAVEIBEENPWNED_REQUEST_DELAY_IN_SECONDS)
        
        save_dict_to_json_file(
            dictionary=emails_breaches,
            file_path=breaches_path
        )
    

if __name__ == "__main__":
    main()

