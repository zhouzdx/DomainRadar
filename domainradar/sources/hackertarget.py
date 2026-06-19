"""HackerTarget hostsearch API."""
from __future__ import annotations

from typing import Set

import requests

from .base import BaseSource


class HackerTargetSource(BaseSource):
    name = "hackertarget"
    timeout = 30

    def fetch(self, domain: str) -> Set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(
            url,
            timeout=self.timeout,
            headers={"User-Agent": "DomainRadar/1.0"},
        )
        if resp.status_code != 200:
            return set()
        text = resp.text or ""
        if "error" in text.lower() and "," not in text:
            return set()
        results: Set[str] = set()
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip()
            if host:
                results.add(host)
        return results
