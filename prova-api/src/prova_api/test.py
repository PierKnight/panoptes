import requests as http
import json

EMAIL_REGEX = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
CREDENTIAL_REGEX = rf"{EMAIL_REGEX}:\S+"

def retrieve_base_urls():
    base_urls = dict()

    with open("/home/kali/iei/api-base-urls.json", "r") as f:
        base_urls = json.loads(f.read().strip())
    
    return base_urls

def retrieve_api_keys():
    api_keys = dict()

    with open("/home/kali/iei/api-keys.json", "r") as f:
        api_keys = json.loads(f.read().strip())
    
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
        api_key: str           # The API key to use for authentication

    It returns the id to be used to retrieve the search results
    '''
    def search(self, term: str, buckets: list[str] = list(), maxresults: int = 1000, sort: int = 2, media: int = 0):
        # TODO: Validation
    
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
            result = http.post(url=f"{self.base_url}/intelligent/search", headers={"x-key": self.api_key}, json=payload)
            search_id = json.loads(result.text)["id"]
            return search_id
        except Exception as e:
            print(f"Error while performing search request: {e}")
            return None
        

    '''
    The following function is used to export the search results from IntelX API.
    It takes the following parameters:
        search_id: str      # The search ID to retrieve results for
        limit: int          # The number of results to retrieve
        filetype: str       # The file type to export ("csv" or "zip")
        api_key: str        # The API key to use for authentication
    '''
    def search_export(self, search_id: str, filetype: str, limit: int = 1000):
        # TODO: Validation

        if filetype not in ["csv", "zip"]:
            raise ValueError("Invalid file type. Must be 'csv' or 'zip'.")

        try:  
            result = http.get(url=f"{self.base_url}/intelligent/search/export?id={search_id}&f=1&l={limit}&k={self.api_key}")
        except Exception as e:
            print(f"Error while performing search export request: {e}")
            return None
        
        if result.status_code == 200:
            with open(f"intelx_search_{search_id}.{filetype}", "wb") as f:
                f.write(result.content)
            print(f"Search results exported successfully to intelx_search_{search_id}.{filetype}")
        else:
            print(f"Error: {result.status_code} - {result.text}")
            return None
        
### END CLASS INTELX ###

def main():
    api_keys = retrieve_api_keys()
    
    intelx = IntelX(api_key=api_keys["intelx"])

    search_id = intelx.search(term="internet-idee.net")

    if search_id is None:
        print("Error: Search ID is None")
        return
    
    intelx.search_export(search_id=search_id, filetype="zip")

if __name__ == "__main__":
    main()

