"""Zentrale API-Key-Quelle für Team 4 (Threat Intel).

Liest Keys aus zwei Quellen, in dieser Reihenfolge:
  1. Env-Var (z.B. OTX_API_KEY) — falls gesetzt, hat immer Vorrang.
  2. threatintel_agent/api_keys.md — falls die Env-Var leer ist.

api_keys.md ist gitignored und wird nie committed (analog agentscanit/models.json).
Vorlage zum Kopieren: api_keys.md.example.

Format in api_keys.md — eine Zeile pro Key:
  OTX_API_KEY: dein-key-hier
"""

import os
import re
from functools import lru_cache
from pathlib import Path

_KEYS_FILE = Path(__file__).resolve().parent.parent / "api_keys.md"
_LINE_RE = re.compile(r"^\s*[-*]?\s*`?([A-Z][A-Z0-9_]*_API_KEY)`?\s*[:=]\s*`?([^`]*?)`?\s*$")
_PLACEHOLDER = {"", "-", "dein-key-hier", "..."}


@lru_cache(maxsize=1)
def _load_md() -> dict:
    if not _KEYS_FILE.exists():
        return {}
    keys = {}
    for line in _KEYS_FILE.read_text(encoding="utf-8").splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        value = m.group(2).strip()
        if value.lower() in _PLACEHOLDER:
            continue
        keys[m.group(1)] = value
    return keys


def get_key(env_var: str) -> str:
    """Liest einen API-Key: Env-Var hat Vorrang, sonst api_keys.md, sonst ''."""
    value = os.environ.get(env_var, "")
    if value:
        return value
    return _load_md().get(env_var, "")
