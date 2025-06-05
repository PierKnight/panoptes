"""
Functions that normalise / simplify raw API payloads so that the report
generator can work with a stable internal schema.
"""
from typing import Any
import re
import requests as http
import json

from osint_app.utils import logging

log = logging.get(__name__)

from typeguard import typechecked

@typechecked
def get_groomed_shodan_info(raw: dict):
    """
    Extract just the bits we need from the big Shodan response.

    Args:
        raw (dict): The raw Shodan host information.
    
    Returns:
        dict: A dictionary containing groomed Shodan host information.
    
    Raises:
        KeyError: If the expected keys are not found in the raw data.
        requests.RequestException: If there is a network error during the CVE request.
        json.JSONDecodeError: If the CVE response cannot be parsed as JSON.
        Exception: For any other unexpected errors during the CVE request.
    """
    groomed_info = dict()
    # Exposed ports
    general_info_as_is = ["asn", "isp", "city", "country_name"]
    for field in general_info_as_is:
        if field in raw:
            groomed_info[field] = raw[field]

    old_data = raw.get("data", [])
    new_data = list()
    exposed_service_as_is = ["os", "port", "product", "transport", "version"]

    # Services section
    for exposed_service in old_data:
        to_add = dict()
        for field in exposed_service_as_is:
            if field in exposed_service:
                to_add[field] = exposed_service[field]
        port = exposed_service.get("port", "")
        transport = exposed_service.get("transport", "")
        product = exposed_service.get("product", "")
        version = exposed_service.get("version", "")

        name = f"{port}/{transport}/{product}/{version}"
        re.sub("/{2,}", "/", name)          # Remove multiple slashes caused by empty fields
        while name.startswith("/") or name.endswith("/"):
            name = re.sub(r"^/|/$", "", name)   # Remove leading and trailing slashes

        to_add["name"] = name
        
        new_data.append(to_add)

    groomed_info["data"] = new_data
    
    # CVEs section
    new_vulns = list()

    if "vulns" not in raw:
        log.info("No CVEs found in the host information.")
        return groomed_info
    
    vulns = raw["vulns"]

    for cve in vulns:
        to_add = dict()
        try:
            response = http.get(f"https://cvedb.shodan.io/cve/{cve}")
            response.raise_for_status()

            result_json = response.json()

            to_add["cve_id"] = result_json.get("cve_id", cve)  # Use the provided CVE ID if not found in response
            to_add["summary"] = result_json.get("summary", "")
            to_add["cvss"] = result_json.get("cvss", "")

            new_vulns.append(to_add)
        except http.exceptions.RequestException as e:
            log.error(f"Network error during CVE request: {e}")
        except json.JSONDecodeError:
            log.error("Failed to parse CVE response JSON.")
        except Exception as e:
            log.error(f"Unexpected error while performing CVE request: {e}")

    groomed_info["vulns"] = new_vulns

    return groomed_info


@typechecked
def get_groomed_dnsdumpster_info(dns_records: dict) -> dict:
    """
    Extracts and grooms DNS records from the raw DNSDumpster API response.

    Args:
        dns_records (dict): The raw DNS records from DNSDumpster API.
    Returns:
        dict: A dictionary containing groomed DNS records.
    Raises:
        KeyError: If the expected keys are not found in the raw data.
            """
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
                            to_add = {key: ip[key] for key in ip if key in ["ip", "asn", "asn_name"]}
                            new_record["ips"].append(to_add)               
                except KeyError as e:
                    log.error(f"KeyError: {e} in record {record}")
                groomed_info[record_type].append(new_record)
    return groomed_info


@typechecked
def get_groomed_mxtoolbox_lookup(info: dict) -> dict:
    """
    Extracts and grooms MXToolbox lookup information from the raw response.
    Args:
        info (dict): The raw MXToolbox lookup information.
    Returns:
        dict: A dictionary containing groomed MXToolbox lookup information.
    Raises:
        KeyError: If the expected keys are not found in the raw data.
    """
    groomed_info = dict()

    # Get the command argument (in this case the domain)
    groomed_info["CommandArgument"] = info.get("CommandArgument", "")
    groomed_info["TimeRecorded"] = info.get("TimeRecorded", "")
    groomed_info["Command"] = info.get("Command", "")
    groomed_info["Records"] = info.get("Records", [])
    
    if "Failed" in info:
        # Get Name and Info from each failed entry
        groomed_info["Failed"] = [{"Name": entry.get("Name"), "Info": entry.get("Info")} for entry in info["Failed"]]
    if "Warnings" in info:
        # Get Name and Info from each warnings entry
        groomed_info["Warnings"] = [{"Name": entry.get("Name"), "Info": entry.get("Info")} for entry in info["Warnings"]]
    if "Passed" in info:
        # Get Name and Info from each passed entry
        groomed_info["Passed"] = [{"Name": entry.get("Name"), "Info": entry.get("Info")} for entry in info["Passed"]]
    return groomed_info


@typechecked
def get_groomed_wappalyzer_info(raw_data: dict) -> dict:
    """
    Grooms the raw Wappalyzer technology information by grouping technologies by their categories
    and formatting them as "tech_name/version". If no version is available, it only includes the tech name.
    Args:
        raw_data (dict): The raw Wappalyzer technology information.
    Returns:
        dict: A dictionary containing groomed Wappalyzer technology information.
    """
    groomed_info = dict()
    
    # Get the URL and technologies
    for domain in raw_data.keys():
        for key, value in raw_data[domain].items():
            categories = value.get("categories", [])
            category = ""
            if len(categories) > 0:
                category = categories[0]
                if category != "":
                    if category not in groomed_info:
                        groomed_info[category] = []
            
                    # <tech_name>/<version>
                    tech_name = key
                    version = value.get("version", "")
                    to_add = tech_name
                    if version != "":
                        to_add += f"/{version}"
                    
                    groomed_info[category].append(to_add)
    
    return groomed_info
