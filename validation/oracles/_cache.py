"""validation/oracles/_cache.py — gemeinsamer lokaler Cache für alle Oracle-Adapter.

Phase 2 (VALIDATION_SPEC.md): 'einheitliches Interface fetch(target) -> dict und
lokalem Cache'. Einfacher JSON-Datei-Cache — kein Redis/DB nötig für 7 Targets.
Jeder Cache-Eintrag speichert auch Abrufzeit + Roh-Response (Regel 4: 'Jede
externe Referenz wird mit URL, Abrufzeit und Roh-Response gespeichert.').
"""
import hashlib
import json
import os
import time

_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_cache")
os.makedirs(_CACHE_DIR, exist_ok=True)


def _key(oracle: str, target: str) -> str:
    h = hashlib.sha256(f"{oracle}:{target}".encode()).hexdigest()[:16]
    safe_target = "".join(c if c.isalnum() else "_" for c in target)[:40]
    return f"{oracle}__{safe_target}__{h}.json"


def get(oracle: str, target: str, max_age_s: int = 86400) -> dict | None:
    path = os.path.join(_CACHE_DIR, _key(oracle, target))
    if not os.path.exists(path):
        return None
    with open(path) as f:
        entry = json.load(f)
    if time.time() - entry.get("_cached_at", 0) > max_age_s:
        return None
    return entry


def put(oracle: str, target: str, url: str, raw_response: str, parsed: dict) -> dict:
    entry = {
        "oracle": oracle,
        "target": target,
        "url": url,
        "fetched_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "_cached_at": time.time(),
        "raw_response": raw_response,
        "parsed": parsed,
    }
    path = os.path.join(_CACHE_DIR, _key(oracle, target))
    with open(path, "w") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)
    return entry
