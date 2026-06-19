"""DNS brute force using a wordlist."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Set

import dns.resolver

from .base import BaseSource


DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent.parent / "wordlists" / "subdomains.txt"


def _make_resolver(timeout: float = 3.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.timeout = timeout
    r.lifetime = timeout
    # Reliable public resolvers - fall back to system if these fail
    r.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "223.5.5.5"]
    return r


def _resolve(host: str, resolver: dns.resolver.Resolver) -> bool:
    """Return True if ``host`` resolves to A or AAAA."""
    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(host, rtype)
            if answers:
                return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            continue
        except Exception:
            continue
    return False


class BruteForceSource(BaseSource):
    name = "bruteforce-dns"

    def __init__(
        self,
        wordlist: str | os.PathLike[str] | None = None,
        words: Iterable[str] | None = None,
        threads: int = 50,
        resolver_timeout: float = 3.0,
    ) -> None:
        self.threads = max(1, int(threads))
        self.resolver_timeout = resolver_timeout
        if words is not None:
            self.words = [w.strip() for w in words if w and w.strip()]
        else:
            path = Path(wordlist) if wordlist else DEFAULT_WORDLIST
            if path.exists():
                self.words = [
                    line.strip()
                    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if line.strip() and not line.startswith("#")
                ]
            else:
                self.words = []

    def fetch(self, domain: str) -> Set[str]:
        if not self.words:
            return set()

        resolver = _make_resolver(self.resolver_timeout)
        candidates = [f"{w}.{domain}" for w in self.words]
        found: Set[str] = set()

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            future_map = {pool.submit(_resolve, host, resolver): host for host in candidates}
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    if future.result():
                        found.add(host)
                except Exception:
                    continue
        return found
