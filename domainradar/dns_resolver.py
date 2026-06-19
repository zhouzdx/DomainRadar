"""DNS resolution helpers for validating discovered subdomains."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List

import dns.exception
import dns.resolver


def _make_resolver(timeout: float = 3.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.timeout = timeout
    r.lifetime = timeout
    r.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "223.5.5.5"]
    return r


def resolve_one(host: str, resolver: dns.resolver.Resolver) -> List[str]:
    """Return the list of A / AAAA records for ``host`` (empty if unresolvable)."""
    ips: List[str] = []
    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(host, rtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            continue
        except Exception:
            continue
        for rdata in answers:
            ips.append(rdata.to_text())
    return ips


def resolve_many(
    hosts: Iterable[str],
    threads: int = 50,
    timeout: float = 3.0,
) -> Dict[str, List[str]]:
    """Resolve all hosts in parallel - returns ``{host: [ips...]}``."""
    resolver = _make_resolver(timeout)
    results: Dict[str, List[str]] = {}
    hosts = list(hosts)
    if not hosts:
        return results
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        future_map = {pool.submit(resolve_one, h, resolver): h for h in hosts}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                results[host] = future.result()
            except Exception:
                results[host] = []
    return results
