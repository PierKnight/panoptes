from panoptes.utils import logging
import os
import subprocess
import tempfile
from typeguard import typechecked

log = logging.get(__name__)

@typechecked
class GoogleHacking:

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
        

    def check_for_sensible_data(self, website_url: str, searchengine_key: str, programmable_searchengine_keys: str):
        

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
        