"""Anubis-DB / JLDC API."""
from __future__ import annotations

from typing import Set

import requests

from .base import BaseSource


class AnubisSource(BaseSource):
    name = "anubis-jldc"
    timeout = 30

    def fetch(self, domain: str) -> Set[str]:
        # JLDC anubis mirror - returns JSON list
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        resp = requests.get(
            url,
            timeout=self.timeout,
            headers={"User-Agent": "DomainRadar/1.0"},
        )
        if resp.status_code != 200:
            return set()
        try:
            data = resp.json()
        except ValueError:
            return set()
        if not isinstance(data, list):
            return set()
        return {str(item).strip() for item in data if item}
