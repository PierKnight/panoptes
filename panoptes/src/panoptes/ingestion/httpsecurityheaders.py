from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging

log = logging.get(__name__)

from typeguard import typechecked

@typechecked
class HTTPSecurityHeaders(BaseHTTPClient):
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
        super().__init__(timeout=10)


    def get_missing_security_headers_with_description(self, website_url: str) -> dict:
        """
        Get missing security headers for a given website URL with descriptions.
        Args:
            website_url: The URL of the website to check.
        Returns:
            A dictionary containing missing security headers and their descriptions.
        """
        missing_security_headers = dict()
        try:
            result = self._get(
                url=website_url,
            )
            result.raise_for_status
            headers = set(result.headers.keys())
            missing = self.__security_headers - headers

            for k,v in self.__security_headers_description.items():
                if k in missing:
                    missing_security_headers[k] = v

            return missing_security_headers
        except json.JSONDecodeError:
            log.error("Failed to parse search response JSON.")
            missing_security_headers["error"] = "Failed to parse search response JSON."
            return missing_security_headers
        except Exception as e:
            log.error(f"Unexpected error while performing search request: {e}")
            missing_security_headers["error"] = str(e)
            return missing_security_headers