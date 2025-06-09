from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from panoptes.utils.http import BaseHTTPClient
from panoptes.utils import logging

log = logging.get(__name__)

from typeguard import typechecked

@typechecked
class IntelX(BaseHTTPClient):
    """Wrapper around the IntelX v2 API."""

    BASE_URL = "https://2.intelx.io"

    def __init__(self, api_key: str) -> None:
        """
        Args:
            api_key: Personal IntelX API key.
        """
        super().__init__(timeout=10)
        self._api_key = api_key


    def intelligent_search(
        self,
        term: str,
        *,
        buckets: Optional[List[str]] = None,
        maxresults: int = 1_000,
        sort: int = 2,
        media: int = 0,
    ) -> Optional[str]:
        """Start an *Intelligent Search* and return its ID.

        Args:
            term: Search term (domain, e-mail, hash …).
            buckets: Explicit list of bucket names. ``None`` → all buckets.
            maxresults: Server-side result cap.
            sort: IntelX sort flag (0–4).
            media: IntelX media type (0–24).

        Returns:
            Search ID if the request succeeds, otherwise *None*.
        """
        url = f"{self.BASE_URL}/intelligent/search"
        payload: Dict[str, Any] = {
            "term": term,
            "buckets": buckets or [],
            "maxresults": maxresults,
            "sort": sort,
            "media": media,
            "lookuplevel": 0,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "terminate": [],
        }

        try:
            resp = self._post(url, json=payload, headers={"x-key": self._api_key})
            resp_json = resp.json()
            status = int(resp_json.get("status"))
            if status == 1:
                log.error("intelx/intelligent/search term is invalid: %s", term)
            elif status == 2:
                log.error("intelx/intelligent/search max concurrent searches per API key exceeded")
                
            return resp_json.get("id")        # type: ignore[return-value]

        except Exception as exc:                # noqa: BLE001
            log.error("intelx intelligent_search failed: %s", exc, exc_info=True)
            return None


    def intelligent_search_export(
        self,
        search_id: str,
        *,
        filetype: str = "zip",
        limit: int = 1_000,
    ) -> Optional[bytes]:
        """Download the results of an Intelligent Search.

        Args:
            search_id: Identifier returned by :py:meth:`intelligent_search`.
            filetype: ``"zip"`` or ``"csv"``.
            limit: Maximum number of rows/objects to export.

        Returns:
            Raw bytes (ZIP or CSV).  *None* on failure.
        """
        if filetype not in ("zip", "csv"):
            raise ValueError("filetype must be 'zip' or 'csv'")

        params = {
            "id": search_id,
            "f": 1 if filetype == "zip" else 0,
            "l": limit,
            "k": self._api_key,
        }
        url = f"{self.BASE_URL}/intelligent/search/export"

        try:
            resp = self._get(url, params=params, timeout=600)
            log.info("intelx /intelligent/search/export: %s", resp.status_code)
            if resp.status_code == 204:
                log.error("intelx /intelligent/search/export: no content for search with ID %s", search_id)
            return resp.content
        except Exception as exc:        # noqa: BLE001
            log.error("intelx /intelligent/search/export failed: %s", exc, exc_info=True)
            return None


    def phonebook_search(
        self,
        term: str,
        *,
        maxresults: int = 1_000,
        media: int = 0,
        terminate: Optional[List[str]] = None,
        target: int = 0,
    ) -> Optional[str]:
        """Launch a *Phonebook* search.

        Args:
            term: Any string accepted by IntelX (*domain.com*, hash, …).
            maxresults: Maximum number of hits.
            media: Media type filter (0 = all).
            terminate: Search IDs that should be cancelled before starting.
            target: Target filter (0 = all, 1 = domain, 2 = e-mail …).

        Returns:
            New search ID or *None* on error.
        """
        url = f"{self.BASE_URL}/phonebook/search"
        payload: Dict[str, Any] = {
            "term": term,
            "maxresults": maxresults,
            "media": media,
            "terminate": terminate or [],
            "target": target,
        }

        try:
            resp = self._post(url, json=payload, headers={"x-key": self._api_key})
            return resp.json().get("id")        # type: ignore[return-value]
        except Exception as exc:                # noqa: BLE001
            log.error("intelx phonebook_search failed: %s", exc, exc_info=True)
            return None


    def phonebook_search_result(
        self,
        search_id: str,
        *,
        limit: int = 1_000,
    ) -> Dict[str, Any]:
        """Retrieve rows from a Phonebook search.

        Args:
            search_id: ID obtained from :py:meth:`phonebook_search`.
            limit: Maximum number of rows to request.

        Returns:
            Parsed JSON payload (empty dict if anything goes wrong).
        """
        url = f"{self.BASE_URL}/phonebook/search/result"
        params = {"id": search_id, "limit": limit}

        try:
            resp = self._get(url, params=params, headers={"x-key": self._api_key})
            return resp.json()          # type: ignore[return-value]
        except json.JSONDecodeError:
            log.error("intelx phonebook_search_result: invalid JSON")
        except Exception as exc:        # noqa: BLE001
            log.error("intelx phonebook_search_result failed: %s", exc, exc_info=True)
        return {}
