import os
import subprocess
import tempfile
from typeguard import typechecked



@typechecked
class GoogleHacking:

    config_filename = "provider-config"

    def __init__(self):
        """
        Args:
            searchengine_key: Personal Have I Been Pwned API key.
            programmable_searchengine_keys: Key Used to make queries, they are rotated for each search
        """

    def __create_google_dorker_conf(self, searchengine_keys: list[str]):
        tmp_file = tempfile.NamedTemporaryFile(delete=False, mode="w+", suffix=".yaml")
        try:
            config = "".join(f"\t{key}\n" for key in searchengine_keys)
            config = f"google:\n{config}"
            tmp_file.write(f"google:\n{config}")
            print(config)
        finally:
            tmp_file.close()
        
        return tmp_file
        

    def check_for_sensible_data(self, website_url: str, searchengine_key: str, programmable_searchengine_keys: str):
        dorker_config = self.__create_google_dorker_conf(programmable_searchengine_keys.split(";"))


        
        result = subprocess.run(
            ["dorker","-cp",tmp_file.file.name],         
            input=f"site:{website_url} ext:pdf",
            capture_output=True,
            text=True
        )
        


        print(result.stdout)

        os.remove(dorker_config.name)
