"""RapidDNS subdomain finder (HTML scrape)."""
from __future__ import annotations

import re
from typing import Set

import requests

from .base import BaseSource


_TD_RE = re.compile(r"<td>([a-zA-Z0-9\.\-\*]+)</td>")


class RapidDNSSource(BaseSource):
    name = "rapiddns"
    timeout = 30

    def fetch(self, domain: str) -> Set[str]:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        resp = requests.get(
            url,
            timeout=self.timeout,
            headers={"User-Agent": "Mozilla/5.0 DomainRadar/1.0"},
        )
        if resp.status_code != 200:
            return set()
        results: Set[str] = set()
        for match in _TD_RE.findall(resp.text):
            host = match.strip()
            if host and "." in host and not host.startswith("<"):
                results.add(host)
        return results
