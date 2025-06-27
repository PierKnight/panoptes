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
            "Content-Security-Policy": {
                "it": "Previene attacchi come XSS e injection specificando le origini fidate da cui il browser può caricare contenuti.",
                "en": "Prevents attacks like XSS and injection by specifying trusted sources the browser can load content from."
            },
            "Strict-Transport-Security": {
                "it": "Forza l'uso di HTTPS e protegge da attacchi man-in-the-middle.",
                "en": "Enforces the use of HTTPS and protects against man-in-the-middle attacks."
            },
            "X-Frame-Options": {
                "it": "Protegge contro il clickjacking impedendo l'incorporamento della pagina in frame non autorizzati.",
                "en": "Protects against clickjacking by preventing the page from being embedded in unauthorized frames."
            },
            "X-Content-Type-Options": {
                "it": "Impedisce il MIME type sniffing, riducendo il rischio di download pericolosi.",
                "en": "Prevents MIME type sniffing, reducing the risk of malicious file downloads."
            },
            "Referrer-Policy": {
                "it": "Controlla le informazioni di referrer inviate, migliorando privacy e sicurezza.",
                "en": "Controls the referrer information sent, enhancing privacy and security."
            },
            "Permissions-Policy": {
                "it": "Gestisce l'accesso a funzionalità sensibili del browser (es. fotocamera, microfono).",
                "en": "Manages access to sensitive browser features (e.g., camera, microphone)."
            },
            "Cross-Origin-Opener-Policy": {
                "it": "Isola il contesto di navigazione tra origini diverse per mitigare attacchi come Spectre.",
                "en": "Isolates browsing contexts between origins to mitigate attacks like Spectre."
            },
            "Cross-Origin-Resource-Policy": {
                "it": "Restringe la condivisione di risorse con origini diverse, proteggendo da data leaks.",
                "en": "Restricts resource sharing across origins, protecting against data leaks."
            },
            "Cross-Origin-Embedder-Policy": {
                "it": "Richiede risorse con isolamento forte, migliorando la sicurezza contro attacchi side-channel.",
                "en": "Requires strongly isolated resources, improving protection against side-channel attacks."
            },
            "Cache-Control": {
                "it": "Gestisce la cache per evitare la memorizzazione di contenuti sensibili su client intermedi.",
                "en": "Controls caching to prevent storage of sensitive content on intermediate clients."
            },
            "Expect-CT": {
                "it": "Aiuta a garantire la trasparenza dei certificati, prevenendo certificati TLS mal emessi.",
                "en": "Helps ensure certificate transparency and prevents misissued TLS certificates."
            },
            "Access-Control-Allow-Origin": {
                "it": "Definisce le origini autorizzate ad accedere alle risorse via CORS, evitando accessi non autorizzati.",
                "en": "Defines the origins allowed to access resources via CORS, preventing unauthorized access."
            }
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

            if len(missing) == 0:
                return {"safe": True}

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