"""validation/oracles/dns_oracle.py — Phase 2: DNS-Oracle.

Mehrere unabhängige Resolver, Mehrheitsentscheid; Dissens -> eigener Status
'AMBIGUOUS' (VALIDATION_SPEC.md Phase 2). Nutzt 'dig' (bereits Projekt-
Abhängigkeit, siehe agentscanit/tools/passive_recon.py) gegen drei öffentliche
Resolver, die NICHT vom recon-suite-eigenen System-Resolver abhängen.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _cache import get, put  # noqa: E402

_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _dig(resolver: str, name: str, rtype: str, timeout: int = 8) -> list[str]:
    try:
        p = subprocess.run(
            ["dig", f"@{resolver}", "+short", "+time=5", "+tries=1", name, rtype],
            capture_output=True, text=True, timeout=timeout,
        )
        return sorted(l.strip().rstrip(".") for l in p.stdout.splitlines() if l.strip())
    except Exception:
        return []


def fetch(target: str, rtype: str = "A", use_cache: bool = True) -> dict:
    """Fragt A/CNAME-Records für `target` bei 3 unabhängigen Resolvern ab.

    Rückgabe: {"status": "RESOLVED"|"NXDOMAIN"|"AMBIGUOUS", "records": [...],
               "per_resolver": {...}, "resolved_ips": set-as-list}
    """
    cache_key = f"{target}|{rtype}"
    if use_cache:
        cached = get("dns", cache_key)
        if cached:
            return cached["parsed"]

    per_resolver = {r: _dig(r, target, rtype) for r in _RESOLVERS}
    non_empty = [tuple(v) for v in per_resolver.values() if v]

    if not non_empty:
        status = "NXDOMAIN"
        records: list[str] = []
    else:
        # Mehrheitsentscheid: identisches Record-Set über >=2/3 Resolver
        from collections import Counter
        counts = Counter(non_empty)
        winner, n = counts.most_common(1)[0]
        if n >= 2:
            status, records = "RESOLVED", list(winner)
        else:
            status, records = "AMBIGUOUS", sorted(set(v for vv in non_empty for v in vv))

    parsed = {"status": status, "records": records, "per_resolver": per_resolver}
    put("dns", cache_key, url=f"dig +short {target} {rtype} @{{1.1.1.1,8.8.8.8,9.9.9.9}}",
        raw_response=str(per_resolver), parsed=parsed)
    return parsed


if __name__ == "__main__":
    import sys
    print(fetch(sys.argv[1] if len(sys.argv) > 1 else "example.com"))
