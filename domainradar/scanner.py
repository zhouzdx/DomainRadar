"""Scanner orchestrator - runs all sources in parallel and aggregates results."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from .dns_resolver import resolve_many
from .sources.base import BaseSource, normalize


@dataclass
class ScanResult:
    domain: str
    subdomains: Set[str] = field(default_factory=set)
    per_source: Dict[str, Set[str]] = field(default_factory=dict)
    resolved: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def alive(self) -> Dict[str, List[str]]:
        return {h: ips for h, ips in self.resolved.items() if ips}

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
        # event_type: "source_start" | "source_done" | "resolve_start" | "resolve_done"
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

        if self.resolve and result.subdomains:
            self._emit("resolve_start", {"count": len(result.subdomains)})
            result.resolved = resolve_many(
                result.subdomains,
                threads=self.resolve_threads,
                timeout=self.resolve_timeout,
            )
            self._emit("resolve_done", {"alive": len(result.alive)})

        return result
