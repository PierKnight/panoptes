import requests as http
import socket
import concurrent.futures
from typeguard import typechecked

import zipfile

from panoptes.utils import logging

import os
from pathlib import Path

from ..persistence.paths import Workspace

import re

import json

log = logging.get(__name__)

import base64
from pathlib import Path

from tqdm import tqdm

import click

from typing import Any


@typechecked
def image_to_base64(image_path: str) -> str:
    """
    Convert an image file to a base64 encoded data URI.
    Args:
        image_path (str): The path to the image file.
    Returns:
        str: A base64 encoded data URI representing the image.
    Raises:
        FileNotFoundError: If the image file does not exist.
        ValueError: If the file is not a valid image type.
    """

    with open(image_path, "rb") as image_file:
        # Convert the image file to base64
        encoded = base64.b64encode(image_file.read()).decode('utf-8')
    
    # Determine the MIME type based on the file extension
    suffix = Path(image_path).suffix.lower()
    mime_types = {
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.webp': 'image/webp',
        '.svg': 'image/svg+xml'
    }
    mime_type = mime_types.get(suffix, 'image/png')
    
    # Return the base64 encoded data URI
    return f"data:{mime_type};base64,{encoded}"


@typechecked
def get_field_name_from_service_dir_name(service_dir_name: str) -> str:
    """
    Get the field name for a given service directory.
    Args:
        service_dir_name (str): The name of the service directory (e.g., "abuseipdb", "dnsdumpster").
    Returns:
        str: The field name corresponding to the service directory.
    """
    service_dir_name = service_dir_name.lower()
    if service_dir_name == "abuseipdb":
        field_name = "compromised_ips"
    elif service_dir_name == "dnsdumpster":
        field_name = "dns_records"
    elif service_dir_name == "haveibeenpwned":
        field_name = "data_breaches"
    elif service_dir_name == "httpsecurityheaders":
        field_name = "header_analysis"
    elif service_dir_name == "intelx":
        field_name = "leaked_credentials"
    elif service_dir_name == "mxtoolbox":
        return "mxtoolbox"  # Special case, as it can contain multiple fields
    elif service_dir_name == "shodan":
        field_name = "hosts"
    elif service_dir_name == "sslshopper":
        field_name = "ssl_check"
    elif service_dir_name == "subdomains":
        field_name = "subdomains_ips"
    elif service_dir_name == "wappalyzer":
        field_name = "tech_stack"
    else:
        raise ValueError(f"Unknown service directory: {service_dir_name}")
    return field_name


@typechecked
def get_website_url(domain: str) -> str:
    """
    Get the website URL for a given domain.
    If the domain does not respond to a HEAD request, it will try with "www." prepended.
    Args:
        domain (str): The domain to check.
    Returns:
        str: The website URL, either with or without "www." based on the response.
    """
    website_url = f"https://{domain.strip()}"
    try:
        response = http.head(
            url=website_url,
            timeout=3
        )
    except http.Timeout as e:
        website_url = f"https://www.{domain.strip()}"
    return website_url

@typechecked
def get_name_and_info_from_dicts_in_list(entries: list[dict]) -> list:
    """
    Extracts "Name" and "Info" from a list of dictionaries.
    Args:
        entries (list[dict]): List of dictionaries containing "Name" and "Info" keys.
    Returns:
        list[dict]: List of dictionaries with "Name" and "Info" keys.
    """
    return [
        {
            "Name": entry["Name"],
            "Info": entry["Info"],
        } for entry in entries
    ]

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
        log.error(f"Unable to resolve host {host}: {e}")
        return []
    except Exception as e:
        log.error(f"Unexpected error while resolving host {host}: {e}")
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
            log.error(f"Error processing {host}: {e}")
            return host, []
    
    # Use ThreadPoolExecutor for parallel DNS resolution
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
                log.error(f"DNS resolution timed out for {host}")
            except Exception as e:
                host = future_to_host[future]
                log.error(f"Exception while processing {host}: {e}")
    
    return ip_addresses

@typechecked
def aggregate_values_from_dict_with_no_duplicates(dictionary: dict) -> list:
    """
    Aggregate all values from a dictionary into a list without duplicates.
    Args:
        dictionary (dict): A dictionary where values are lists of IP addresses.
    Returns:
        list[str]: A list of unique IP addresses aggregated from the dictionary values.
    """
    ips = [ip for ip_list in dictionary.values() for ip in ip_list]

    # Remove duplicates by converting to a set and back to a list
    ips = list(set(ips))

    return ips

def extract_zip(filepath: str) -> None:
    """
    Extracts a zip file to a specific directory and removes the zip file after extraction.
    Args:
        filepath (str): The path to the zip file to be extracted.
    """
    try:
        with zipfile.ZipFile(filepath, "r") as zip_file:
            zip_file.extractall(Path(filepath).parent)
        log.info(f"Extracted {filepath} successfully.")
        os.remove(filepath)
    except zipfile.BadZipFile:
        log.error(f"{filepath} is not a valid zip file.")
    except FileNotFoundError:
        log.error(f"{filepath} not found.")
    except PermissionError:
        log.error(f"Permission denied when accessing {filepath}.")
    except Exception as e:
        log.error(f"An unexpected error occurred: {e}")


@typechecked
def get_credentials_from_file(file_path: str, credential_regex: str) -> dict[str, set[str]]:
    email_credentials = dict()

    # This is done to avoid regex injection
    if len(credential_regex) > 500:
        log.error("Credential regex is too long, it might be a security risk.")
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
        log.error(f"File {file_path} not found.")
    except PermissionError:
        log.error(f"Permission denied when accessing the file {file_path}.")
    except Exception as e:
        log.error(f"An unexpected error occurred: {e}")

    return email_credentials

def sort_credentials(credentials: dict[str, set[str]]) -> dict[str, list[str]]:
    """
    Sorts the credentials dictionary by email and converts sets to sorted lists.
    Args:
        credentials (dict[str, set[str]]): A dictionary where keys are emails and values are sets of credentials.
    Returns:
        dict[str, list[str]]: A sorted dictionary where each email maps to a sorted list of credentials.
    """
    sorted_credentials = {}
    for email in sorted(credentials.keys()):
        sorted_credentials[email] = sorted(credentials[email])
    return sorted_credentials

@typechecked
def get_credentials_from_folder(folder_path: str, credential_regex: str):
    # Breach file name (str) to credentials (list[str]) association
    credentials = {}
    
    # Get list of files to process
    files_to_process = [
        file for file in os.listdir(folder_path) 
        if file != "Info.csv" and file.lower().split(".")[-1] in ["txt", "csv"]
    ]

    # TQDM progress bar
    # Leave=False disables lingering bar after done, dynamic_ncols for nice fit, and use click's stdout
    with tqdm(total=len(files_to_process), desc="Processing files", leave=False, dynamic_ncols=True, file=click.get_text_stream('stdout')) as pbar:
        with concurrent.futures.ProcessPoolExecutor() as executor:
            future_to_file = {
                executor.submit(
                    get_credentials_from_file, 
                    os.path.join(folder_path, file),
                    credential_regex
                ): file for file in files_to_process
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    file_credentials = future.result()
                    for email, credentials_set in file_credentials.items():
                        if email not in credentials:
                            credentials[email] = set()
                        credentials[email] = credentials[email].union(credentials_set)
                except Exception as e:
                    # Use tqdm.write so it doesn't mess up the progress bar
                    tqdm.write(f"Error processing {file}: {e}")
                finally:
                    pbar.update(1)  # update progress bar

    return credentials


@typechecked
def get_breached_emails(credentials_path: str) -> set[str]:
    """
    Retrieves a set of breached emails from a credentials file.
    Args:
        credentials_path (str): The path to the credentials file (JSON format).
    Returns:
        set[str]: A set of breached emails.
    """
    # If the credential.json file exists
    if os.path.exists(credentials_path):
        try:
            with open(credentials_path, "r") as f:
                credentials = json.load(f)         
            return set(credentials.keys())
        except FileNotFoundError:
            log.error(f"File {credentials_path} not found.")
        except PermissionError:
            log.error(f"Permission denied when accessing the file {credentials_path}.")
        except json.JSONDecodeError:
            log.error(f"Failed to decode JSON from the file {credentials_path}.")
        except Exception as e:
            log.error(f"An unexpected error occurred: {e}")
        
    return set()


def get_folder_size(folder_path: str) -> int:
    """
    Calculate the total size of a folder in bytes.
    
    Args:
        folder_path (str): The path to the folder.
        
    Returns:
        int: Total size of the folder in bytes.
    """
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # Skip if it's a symlink
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size


@typechecked
def get_diff_json(new: Any, old: Any, *, always_add: list[str]) -> dict | None:
    # If new and old are both dicts, descend
    if isinstance(new, dict) and isinstance(old, dict):
        out = {}
        # Always add keys from always_add (from the top-level new)
        for to_add in always_add:
            if to_add in new:
                out[to_add] = new[to_add]
        # For all keys in new, compare or recurse
        for k, v in new.items():
            if k in old:
                diff = get_diff_json(v, old[k], always_add=[])  # only always_add at top-level
                if diff not in [None, {}, [], ""]:
                    out[k] = diff
            else:
                out[k] = v  # Key only in new
        return out or None
    # If both are lists, compare by value
    elif isinstance(new, list) and isinstance(old, list):
        if new != old:
            return new
        else:
            return None
    # Any other types: only return if different
    else:
        if new != old:
            return new
        else:
            return None