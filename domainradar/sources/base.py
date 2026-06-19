"""Base class for subdomain sources."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Set


_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")


def normalize(domain: str) -> str:
    """Normalize a domain - lowercase, strip wildcards, strip whitespace."""
    d = domain.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("."):
        d = d[1:]
    return d


def is_valid_subdomain(candidate: str, root: str) -> bool:
    """Check if candidate is a valid subdomain of root."""
    if not candidate or not root:
        return False
    if not _DOMAIN_RE.match(candidate):
        return False
    return candidate == root or candidate.endswith("." + root)


class BaseSource(ABC):
    """Abstract source - one plugin per data provider."""

    name: str = "base"
    timeout: int = 30

    @abstractmethod
    def fetch(self, domain: str) -> Set[str]:
        """Return a set of subdomains discovered for ``domain``."""

    def run(self, domain: str) -> Set[str]:
        """Run safely - return empty set on failure rather than raising."""
        root = normalize(domain)
        try:
            raw = self.fetch(root)
        except Exception:
            return set()
        return {s for s in (normalize(x) for x in raw) if is_valid_subdomain(s, root)}
