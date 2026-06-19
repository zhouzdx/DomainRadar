"""DNS wildcard / hijacking detection.

Many networks (corporate proxies, hotels, captive portals, some cloud / VPN
environments, ISPs) intercept DNS queries and return synthetic answers for
non-existent domains. Some legitimate domains also configure wildcard records
(``*.example.com -> A ...``).

In both cases a brute-force enumeration over a wordlist will report ALL words
as ``alive`` with the same set of IPs, which is useless.

This module probes a domain with random labels that cannot exist. The IPs that
come back form a "bogus baseline" - any subdomain that resolves to ONLY those
IPs is treated as a false positive by downstream consumers.
"""
from __future__ import annotations

import random
import string
from typing import Set

import dns.exception
import dns.resolver

from .dns_resolver import _make_resolver


def _random_label(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def detect_wildcard(
    domain: str,
    samples: int = 3,
    label_len: int = 16,
    timeout: float = 3.0,
) -> Set[str]:
    """Return the set of IPs returned for non-existent subdomains of ``domain``.

    Empty set      -> no wildcard / no DNS hijacking detected.
    Non-empty set  -> bogus IPs, callers should treat any host whose ALL IPs
                      lie within this set as a false positive.
    """
    resolver = _make_resolver(timeout)
    bogus: Set[str] = set()

    for _ in range(max(1, samples)):
        host = f"{_random_label(label_len)}.{domain}"
        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(host, rtype)
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                continue
            except Exception:
                continue
            for rdata in answers:
                bogus.add(rdata.to_text())

    return bogus
