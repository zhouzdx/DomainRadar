"""AlienVault OTX passive DNS."""
from __future__ import annotations

from typing import Set

import requests

from .base import BaseSource


class AlienVaultSource(BaseSource):
    name = "alienvault-otx"
    timeout = 45

    def fetch(self, domain: str) -> Set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
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
        results: Set[str] = set()
        for item in data.get("passive_dns", []) or []:
            host = item.get("hostname")
            if host:
                results.add(host)
        return results
