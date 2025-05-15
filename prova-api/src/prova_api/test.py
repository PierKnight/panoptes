from re import search
from enum import Enum
from typeguard import typechecked

import requests as http
import json
import os
import re
import zipfile
import csv

import socket


EMAIL_WITHOUT_DOMAIN_REGEX = r"[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@"
SERVICES_EMPLOYED = [
    "haveibeenpwned",
    "intelx",
    "c99",
    "abuseipdb"
]
BASE_DIR = os.path.join(os.path.expanduser("~"), "prove")
HAVEIBEENPWNED_REQUEST_DELAY_IN_SECONDS = 1

@typechecked
def retrieve_base_urls() -> dict:
    base_urls = dict()

    try:
        with open("/home/kali/iei/api-base-urls.json", "r") as f:
            base_urls = json.loads(f)
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
    def intelligent_search(self, term: str, buckets = None, maxresults: int = 1000, sort: int = 2, media: int = 0) -> str:
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

        result = http.get(url)
        headers = set(result.headers.keys())
        missing = self.__security_headers - headers

        missing_security_headers = dict()

        for k,v in self.__security_headers_description.items():
            if k in missing:
                missing_security_headers[k] = v

        return missing_security_headers
######################################## END CLASS HTTPSecurityHeaders ####################################


'''
The following function is used to retrieve the credentials from a file.
It takes the following parameters:
    file_path: str               # The path to the file
    credential_regex: str        # The regex to use to extract the credentials
    
It returns a list of credentials found in the file.
'''
@typechecked
def get_credentials_from_file(file_path: str, credential_regex: str) -> list[str]:
    credentials = list()

    # This is done to avoid regex injection
    if len(credential_regex) > 500:
        print("Error: Credential regex is too long.")
        return credentials

    try:
        with open(file_path, "r") as f:
            for line in f:
                matches = re.findall(credential_regex, line)
                if matches:
                    credentials.extend(matches)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except PermissionError:
        print(f"Error: Permission denied when accessing the file {file_path}.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return credentials


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
def start_credentials_retrieving_from_folder(folder_path: str, credential_regex: str):
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
def get_breached_emails(credentials_path: str) -> set[str]:
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
The following function is used to retrieve the IP address from a host.
It takes the following parameters:
    host: str                # The host to retrieve the IP address from
It returns the IP address of the host.
'''
@typechecked
def get_ip_from_host(host: str) -> str:
    return socket.gethostbyname(host)


'''
The following function is used to retrieve the IP addresses from a list of hosts.
It takes the following parameters:
    hosts: list[str]         # The list of hosts to retrieve the IP addresses from
It returns a dictionary with the hosts as keys and the IP addresses as values.
'''
@typechecked
def get_ips_from_hosts(hosts: list[str]) -> dict[str, str]:
    ip_addresses = dict()
    for host in hosts:
        try:
            ip = get_ip_from_host(host)
            ip_addresses[host] = ip
        except socket.gaierror:
            print(f"Error: Unable to resolve host {host}.")
        except Exception as e:
            print(f"An unexpected error occurred while resolving host {host}: {e}")
    return ip_addresses


def main():
    api_keys = retrieve_api_keys()
    
    intelx = IntelX(api_key=api_keys["intelx"])
    haveibeenpwned = HaveIBeenPwned(api_key=api_keys["haveibeenpwned"])
    c99 = C99(api_key=api_keys["c99"])
    abuseipdb = AbuseIPDB(api_key=api_keys["abuseipdb"])
    httpsecurityheaders = HTTPSecurityHeaders()

    domain = "internet-idee.net"

    credential_regex = rf"{EMAIL_WITHOUT_DOMAIN_REGEX}{domain}:\S+"

    # Create a directory for the domain if it doesn't exist
    create_working_directories(domain, SERVICES_EMPLOYED)

    missing_headers_descriptions = httpsecurityheaders.get_missing_security_headers_with_description(domain)
    if missing_headers_descriptions:
        print(missing_headers_descriptions)

    subdomain_result = c99.subdomain_finder(domain)
    if len(subdomain_result) > 0:
        hosts_ips = get_ips_from_hosts(subdomain_result)

        # ["62.149.128.154", "62.149.128.155"]
        save_dict_to_json_file(
            dictionary=abuseipdb.get_abused_ips_reports(ips=[val for _, val in hosts_ips.items() if val is not None]),
            file_path=os.path.join(BASE_DIR, domain, "abuseipdb", "abused_ips.json")
        )

    phonebook_search_id = intelx.phonebook_search(term=domain, target=1)

    if phonebook_search_id is not None:
        phonebook_search_result = intelx.phonebook_search_result(search_id=phonebook_search_id, limit=1000)
        if phonebook_search_result is not None:
            save_dict_to_json_file(
                dictionary=phonebook_search_result,
                file_path="phonebook_search_result.json"
            )
        else:
            print("Error: Phonebook search result is None")
    else:
        print("Error: Phonebook search ID is None")
    
    intelligent_search_id = intelx.intelligent_search(term=domain, media=0)

    intelx_breach_files = os.path.join(BASE_DIR, domain, "intelx", "breach_files")
    credentials_path = os.path.join(BASE_DIR, domain, "intelx", "credentials.json")

    if intelligent_search_id is not None:
        filetype = "zip"  # or "csv"

        content = intelx.intelligent_search_export(search_id=intelligent_search_id, limit=2000, filetype=filetype)

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
            __import__("time").sleep(HAVEIBEENPWNED_REQUEST_DELAY_IN_SECONDS)
        
        save_dict_to_json_file(
            dictionary=emails_breaches,
            file_path=breaches_path
        )

if __name__ == "__main__":
    main()

