from __future__ import annotations

import requests
from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging
from requests.exceptions import RequestException
from typeguard import typechecked
from pathlib import Path

log = logging.get(__name__)

@typechecked
class Thumbsnap(BaseHTTPClient):
    BASE_URL = "https://thumbsnap.com/api"

    def __init__(self, api_key: str):
        self.api_key = api_key
        super().__init__(timeout=15)
    
    def upload_image(self, image_path: str) -> str | None:
        """
        Upload an image to Thumbsnap.

        Args:
            image_path (str): The file path to the image.

        Returns:
            str: URL of the uploaded image, or None if upload failed.
        """
        try:
            file_path = Path(image_path)
            if not file_path.exists():
                log.error(f"Image file not found: {image_path}")
                return None

            payload = {
                "key": self.api_key,
            }

            files = {
                "media": file_path.open("rb")
            }

            response = self._post(
                url=f"{self.BASE_URL}/upload",
                data=payload,
                files=files,
            )
            response.raise_for_status()

            result_data = response.json()

            # Check if the response contains the expected structure
            if "data" in result_data and "media" in result_data["data"]:
                return result_data["data"]["media"]
            else:
                log.error(f"Image upload to Thumbsnap failed: {result_data}")
                return None

        except RequestException as e:
            log.error(f"Network error during image upload: {e}")
        except Exception as e:
            log.error(f"Unexpected error during image upload: {e}")

        return None
