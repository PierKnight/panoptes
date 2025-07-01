from __future__ import annotations

import json
import base64

from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging

from requests.exceptions import RequestException

log = logging.get(__name__)

from typeguard import typechecked
from pathlib import Path


@typechecked
class ImgBB(BaseHTTPClient):
    BASE_URL = "https://api.imgbb.com/1"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        super().__init__(timeout=15)

    def upload_image(self, image_path: str, name: str | None = None) -> str | None:
        """
        Upload an image to imgbb.

        Args:
            image_path (str): The file path to the image.
            name (str, optional): Optional name for the image on imgbb.

        Returns:
            dict: Parsed response from the imgbb API.
        """
        result_data = {}

        try:
            file_path = Path(image_path)
            if not file_path.exists():
                log.error(f"Image file not found: {image_path}")
                return None

            with file_path.open("rb") as image_file:
                encoded_image = base64.b64encode(image_file.read()).decode("utf-8")

            payload = {
                "key": self.api_key,
                "image": encoded_image,
            }

            if name:
                payload["name"] = name

            response = self._post(
                url=f"{self.BASE_URL}/upload",
                data=payload,
            )
            response.raise_for_status()

            result_data = response.json()

            if not result_data.get("success", False):
                log.info(f"Image upload to imgbb failed: {result_data}")
                return None

        except RequestException as e:
            log.error(f"Network error during image upload: {e}")
        except json.JSONDecodeError:
            log.error("Failed to parse imgbb response JSON.")
        except Exception as e:
            log.error(f"Unexpected error during image upload: {e}")

        # Return only the image URL if upload was successful
        if result_data.get("success") and "data" in result_data and "url" in result_data["data"]:
            return result_data["data"]["url"]
        return None
