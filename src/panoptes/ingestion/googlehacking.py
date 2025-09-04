import concurrent
from dataclasses import dataclass
import json
import os
from pathlib import Path
import random
from typing import Callable

import requests
from panoptes.utils import logging
import xml.etree.ElementTree as ET
from typeguard import typechecked

from panoptes.utils.http import BaseHTTPClient

log = logging.get(__name__)


EXPLOITDB = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/ghdb.xml"

#Categories defined by exploitdb
EXPLOITDB_CATEGORIES = [
    "Sensitive Directories",
    "Web Server Detection",
    "Vulnerable Servers",
    "Error Messages",
    "Files Containing Juicy Info",
    "Files Containing Passwords",
    "Sensitive Online Shopping Info",
    "Network or Vulnerability Data",
    "Pages Containing Login Portals",
    "Pages Containing Login Portals",
    "Advisories and Vulnerabilities"
]

@typechecked
@dataclass(frozen=True)
class ExploitDBDork():
    category: str
    query: str
    author: str

@typechecked
class GoogleHacking():


    def __init__(self):
        """
        Args:
            searchengine_key: Key for Google Search Engine
            programmable_searchengine_keys: Key Used to make queries, they are rotated for each search
        """

    
    def __handle_dork(self, dork: str, cx : str, keys: list[str], timeout: int, page: int = 0) -> set[str]:
        
        
        randomkey = random.choice(keys)
        httpClient = BaseHTTPClient()
        response = httpClient._get(f"https://customsearch.googleapis.com/customsearch/v1?q={dork}&cx={cx}&num=10&start={page}&key={randomkey}&alt=json")
        data = json.loads(response.text)

        items = data.get("items")
        results = set()
      
        if items:
            for item in items:
                url = item.get("link")
                if url:
                    results.add(url)
        return results
    

    def __iter_queries_from_exploitdb(self):
        """
        Stream parse GHDB XML from HTTPS and yield queries for a given category.
        """
        with requests.get(EXPLOITDB, stream=True) as r:
            r.raise_for_status()

            # iterparse over streamed XML
            context = ET.iterparse(r.raw, events=("end",))
            for event, elem in context:
                if elem.tag == "entry":
                    category = elem.findtext("category", "").strip()

                    query = elem.findtext("query")
                    author = elem.findtext("author")
                    if query:
                        query = query.strip()
                        dork = ExploitDBDork(category, query, author)
                        yield dork

                    elem.clear()  # free memory
    
    #method that collects dorks from dumped database based on configuration file
    def __collect_exploitdb_dork(self, cfg, on_dork: Callable[[str], None]):
        exploitdb_categories = cfg["googlehacking"].get("exploitdb_categories", dict())

        #end collections if not a single category is configured
        if not exploitdb_categories or len(exploitdb_categories) == 0:
            log.info(f"No ExploitDB category set")
            return
        
        #keeps track the amount of dorks found by category
        category_count = {category: 0 for category in exploitdb_categories.keys()}
        
        

        #max number of dorks per category (default 5)
        max_dorks = {category: exploitdb_categories[category].get("max_dorks", 5) for category in exploitdb_categories.keys()}
        #categories that completed their dorks
        complete_categories = 0
        for i, dork in enumerate(self.__iter_queries_from_exploitdb(), 1):
            if complete_categories >= len(category_count):
                break

            category = dork.category

            if category not in exploitdb_categories or category_count[category] >= max_dorks[category]:
                continue
            category_count[category] += 1

            if category_count[category] > max_dorks[category]:
                complete_categories += 1

            print(f"FOUND: {category}: {dork.query}")

            on_dork(dork.query)

    #collects dorks defined in files
    def __collect_file_dork(self, cfg, on_dork: Callable[[str], None]):

        dork_files = cfg["googlehacking"].get("dork_file", [])

        for path_str in dork_files: 
            file_path = Path(os.path.expanduser(path_str))
            if file_path.exists():
                with file_path.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.rstrip("\n") 
                        on_dork(line)
            else:
                log.warning(f"Dork file: {file_path} not found. Skipping it")






    #format dork to be used in specific domain
    def __make_site_dork(self, domain, dork):
        return f"site:{domain} {dork}"

    #method used to return all results agains docks
    def check_for_sensible_data(self, domains: tuple, cfg: dict[str, any]):

        
        searchengine_key: str = cfg["api_keys"]["searchengine"]
        programmable_searchengine_keys: str = cfg["api_keys"]["programmablesearchengine"]
        max_workers: int = cfg["googlehacking"]["max_workers"]
        timeout: int = cfg["googlehacking"]["timeout"]


        searchengine_keys_list = programmable_searchengine_keys.split(";")
        
        domain = domains[0]
        

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:

            future_to_dork = {}
            
            #method to add a new dork query in the thread pool
            def add_new_future(dork_query):
                site_dork = self.__make_site_dork(domain, dork_query)
                future = executor.submit(self.__handle_dork, site_dork, searchengine_key, searchengine_keys_list, timeout)
                future_to_dork[future] = site_dork

            #ladd a new thread in the pool for each file dork found
            self.__collect_file_dork(cfg, add_new_future)
            #add a new thread in the pool for each exploitdb dork found
            self.__collect_exploitdb_dork(cfg, add_new_future)


            print(future_to_dork)
            
            results = dict()

            for future in concurrent.futures.as_completed(future_to_dork, timeout=timeout):
                dork = future_to_dork[future]
                try:
                    paths = future.result()
                    if paths:  
                        results[dork] = paths
                except concurrent.futures.TimeoutError:
                    log.error(f"Google Dork timed out for {dork}")
                except Exception as e:
                    log.error(f"Exception while processing {dork}: {e}")

            found_dorks = dict(sorted(results.items()))
            return found_dorks
        #https://github.com/ChillHackLab/Google-Dorking/tree/main good place for new dorcs


        