"""crt.sh - Certificate Transparency log search."""
from __future__ import annotations

from typing import Set

import requests

from .base import BaseSource


class CrtShSource(BaseSource):
    name = "crt.sh"
    timeout = 60

    def fetch(self, domain: str) -> Set[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
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
        for entry in data:
            name_value = entry.get("name_value", "")
            common_name = entry.get("common_name", "")
            for blob in (name_value, common_name):
                for line in str(blob).splitlines():
                    line = line.strip()
                    if line:
                        results.add(line)
        return results
