"""Scanner orchestrator - runs all sources in parallel and aggregates results."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from .dns_resolver import resolve_many
from .sources.base import BaseSource, normalize
from .sources.bruteforce import BruteForceSource
from .wildcard import detect_wildcard


@dataclass
class ScanResult:
    domain: str
    subdomains: Set[str] = field(default_factory=set)
    per_source: Dict[str, Set[str]] = field(default_factory=dict)
    resolved: Dict[str, List[str]] = field(default_factory=dict)
    # IPs returned by random non-existent subdomains. Non-empty means either
    # the domain has a wildcard record or the network hijacks DNS.
    wildcard_ips: Set[str] = field(default_factory=set)

    @property
    def hijacked(self) -> bool:
        return bool(self.wildcard_ips)

    @property
    def alive(self) -> Dict[str, List[str]]:
        """Return resolved subdomains whose IPs are NOT entirely fake."""
        out: Dict[str, List[str]] = {}
        for host, ips in self.resolved.items():
            if not ips:
                continue
            real_ips = [ip for ip in ips if ip not in self.wildcard_ips]
            if real_ips:
                out[host] = real_ips
        return out

    def sorted_subdomains(self) -> List[str]:
        return sorted(self.subdomains, key=lambda s: (s.count("."), s))


class Scanner:
    """Run a set of sources against a domain and (optionally) resolve hits."""

    def __init__(
        self,
        sources: Sequence[BaseSource],
        resolve: bool = True,
        resolve_threads: int = 50,
        resolve_timeout: float = 3.0,
        progress_cb=None,
    ) -> None:
        self.sources = list(sources)
        self.resolve = resolve
        self.resolve_threads = resolve_threads
        self.resolve_timeout = resolve_timeout
        # progress_cb(event_type, payload) -> None
        # event_type: "wildcard" | "source_start" | "source_done" |
        #             "resolve_start" | "resolve_done"
        self.progress_cb = progress_cb

    def _emit(self, event: str, payload) -> None:
        if self.progress_cb:
            try:
                self.progress_cb(event, payload)
            except Exception:
                pass

    def scan(self, domain: str) -> ScanResult:
        root = normalize(domain)
        result = ScanResult(domain=root)

        # 1. Wildcard / DNS-hijack baseline check. Run BEFORE bruteforce so
        # the bogus IP set can be injected into BruteForceSource instances.
        self._emit("wildcard_start", {"domain": root})
        wildcard_ips = detect_wildcard(root, samples=3, timeout=self.resolve_timeout)
        result.wildcard_ips = wildcard_ips
        for src in self.sources:
            if isinstance(src, BruteForceSource):
                src.wildcard_ips = wildcard_ips
        self._emit(
            "wildcard_done",
            {"hijacked": bool(wildcard_ips), "ips": sorted(wildcard_ips)},
        )

        # 2. Run all sources in parallel.
        with ThreadPoolExecutor(max_workers=max(1, len(self.sources))) as pool:
            future_map = {}
            for src in self.sources:
                self._emit("source_start", {"source": src.name})
                future_map[pool.submit(src.run, root)] = src

            for future in as_completed(future_map):
                src = future_map[future]
                try:
                    found = future.result()
                except Exception:
                    found = set()
                result.per_source[src.name] = found
                result.subdomains |= found
                self._emit("source_done", {"source": src.name, "count": len(found)})

        # 3. Resolve all discovered subdomains.
        if self.resolve and result.subdomains:
            self._emit("resolve_start", {"count": len(result.subdomains)})
            result.resolved = resolve_many(
                result.subdomains,
                threads=self.resolve_threads,
                timeout=self.resolve_timeout,
            )
            self._emit("resolve_done", {"alive": len(result.alive)})

        return result
