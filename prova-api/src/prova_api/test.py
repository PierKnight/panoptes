import requests as http
import json
import os
import re
import zipfile
import csv

EMAIL_WITHOUT_DOMAIN_REGEX = r"[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@"
SERVICES_EMPLOYED = [
    "pwned",
    "intelx",
]
BASE_DIR = os.path.join(os.path.expanduser("~"), "prove")

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
        api_key: str            # The API key to use for authentication

    It returns the id to be used to retrieve the search results
    '''
    def search(self, term: str, buckets: list[str] = None, maxresults: int = 1000, sort: int = 2, media: int = 0) -> str:
        # TODO: Validation

        if buckets is None:
            buckets = []

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

        try:
            result = http.post(
                url=f"{self.base_url}/intelligent/search",
                headers={"x-key": self.api_key},
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
        

    '''
    The following function is used to export the search results from IntelX API.
    It takes the following parameters:
        search_id: str      # The search ID to retrieve results for
        limit: int          # The number of results to retrieve
        filetype: str       # The file type to export ("csv" or "zip")
        api_key: str        # The API key to use for authentication
    '''
    def search_export(self, search_id: str, filetype: str, limit: int = 1000) -> str:
        # TODO: Validation

        if filetype not in ["csv", "zip"]:
            raise ValueError("Invalid file type. Must be 'csv' or 'zip'.")

        if filetype == "csv":
            f = 0
        elif filetype == "zip":
            f = 1           

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
                timeout=10
            )
            result.raise_for_status()   

            # Writes to disk the search results (as a CSV or ZIP file)
            filename = f"intelx_search_{search_id}.{filetype}"
            with open(filename, "wb") as f:
                f.write(result.content)
                print(f"Search results exported successfully to {filename}")   
            return filename     
                
        except http.exceptions.RequestException as e:       
            print(f"Network error during search export request: {e}")
        except Exception as e:
            print(f"Unexpected error while performing search export request: {e}")
### END CLASS INTELX ###

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

def get_system_ids_names_association(folder_path: str) -> dict:
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


def create_working_directories(domain: str):
    # Create a directory for the domain if it doesn't exist
    if not os.path.exists(os.path.join(BASE_DIR, domain)):
        os.makedirs(os.path.join(BASE_DIR, domain))
        print(f"Created directory: {os.path.join(BASE_DIR, domain)}")


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

def main():
    api_keys = retrieve_api_keys()
    
    intelx = IntelX(api_key=api_keys["intelx"])

    domain = "internet-idee.net"
    
    credential_regex = rf"{EMAIL_WITHOUT_DOMAIN_REGEX}{domain}:\S+"

    # Create a directory for the domain if it doesn't exist
    create_working_directories(domain)

    '''
    search_id = intelx.search(term=domain, media=0)

    if search_id is None:
        print("Error: Search ID is None")
        return
    
    filetype = "zip"  # or "csv"

    filename = intelx.search_export(search_id=search_id, limit=100, filetype=filetype)

    if filename is None:
        print("Error: No file name returned")
        return

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
    '''
    # Move this under the multiline comment when not using only local files
    intelx_breach_files = os.path.join(BASE_DIR, domain, "intelx", "breach_files")
    if os.path.exists(intelx_breach_files):
        extracted_credentials = start_credentials_retrieving_from_folder(intelx_breach_files, credential_regex)

        save_dict_to_json_file(
            dictionary=extracted_credentials,
            file_path=os.path.join(BASE_DIR, domain, "intelx", f"credentials.json")
        )
    

    credentials_path = os.path.join(BASE_DIR, domain, "intelx", f"credentials.json")
    # Extract all the emails from the dataleaks
    breached_emails = get_breached_emails(credentials_path)
    print(breached_emails)

if __name__ == "__main__":
    main()

