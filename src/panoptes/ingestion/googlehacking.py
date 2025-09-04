import concurrent
import json
import random
import threading
from panoptes.utils import logging
import tempfile
from typeguard import typechecked

from panoptes.utils.http import BaseHTTPClient

log = logging.get(__name__)

@typechecked
class GoogleHacking():

    config_filename = "provider-config"

    def __init__(self):
        """
        Args:
            searchengine_key: Key for Google Search Engine
            programmable_searchengine_keys: Key Used to make queries, they are rotated for each search
        """

        
    def __create_google_dorker_conf(self, searchengine_key: str, searchengine_keys: list[str]):
        tmp_file = tempfile.NamedTemporaryFile(delete=False, mode="w+", suffix=".yaml")
        try:
            config = "".join(f"\n -  {key}:{searchengine_key}" for key in searchengine_keys)
            config = f"google:{config}"
            tmp_file.write(f"google:\n{config}")
        finally:
            tmp_file.close()
        
        return tmp_file
    
    def __handle_dork(self, dork: str, cx : str, keys: list[str], timeout: int, page: int = 0) -> set[str]:
        
        
        randomkey = random.choice(keys)
        httpClient = BaseHTTPClient()
        response = httpClient._get(f"https://customsearch.googleapis.com/customsearch/v1?q={dork}&cx={cx}&num=10&start={page}&key={randomkey}&alt=json")
        data = json.loads(response.text)

        items = data.get("items")
        results = set()
      
        if items:
            for item in items:
                print(item)
                url = item.get("link")
                if url:
                    results.add(url)
        
        #print(dork)
        return results
    
    def make_site_dork(self, domain, dork):
        return f"site:{domain} {dork}"

    def check_for_sensible_data(self, domains: tuple, searchengine_key: str, programmable_searchengine_keys: str, max_workers: int = 10, timeout: int = 10):
        
        """
        print(programmable_searchengine_keys)



        dorker_config = self.__create_google_dorker_conf(searchengine_key, programmable_searchengine_keys.split(";"))
        #"-cp",dorker_config.file.name        
        result = subprocess.run(
            ["dorker","-cp",dorker_config.file.name,"-o", "/tmp/test"],         
            input=f"site:{website_url} ext:pdf",
            capture_output=True,
            text=True
        )
        


        print(result.stdout)

        os.remove(dorker_config.name)
        """ 

        searchengine_keys_list = programmable_searchengine_keys.split(";")
        
        domain = domains[0]
        

        dorks = ["ext:pdf"]


        #used to avoid race condition while writing to the results list
        lock = threading.Lock()

        #dictionary which track for each dork the corresponding results
        results = dict()

         # Use ThreadPoolExecutor for parallel Query 
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Start the operations and mark each future with its dork
            future_to_dork = {executor.submit(self.__handle_dork, self.make_site_dork(domain, dork), searchengine_key, searchengine_keys_list, timeout): self.make_site_dork(domain, dork) for dork in dorks}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_dork, timeout=timeout):
                dork = future_to_dork[future]
                try:
                    paths = future.result()
                    if paths:  # Only add found paths
                        results[dork] = paths
                except concurrent.futures.TimeoutError:
                    log.error(f"Google Dork timed out for {dork}")
                except Exception as e:
                    log.error(f"Exception while processing {dork}: {e}")

        # Order by key (hostname)
        found_dorks = dict(sorted(results.items()))
        print(found_dorks)
        