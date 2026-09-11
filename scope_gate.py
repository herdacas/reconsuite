"""
scope_gate.py — Phase 9 Safety-Gate (Exploitation & Validation)

Kein aktives Validierungs-Tool (Team 7, ab Phase 9.2) darf laufen ohne
bestandenes Scope-Gate. Dieses Modul ist bewusst der allererste Baustein
von Phase 9 (siehe roadmap.md, "9.0 — Safety-Gate") — es entscheidet,
noch bevor ein einziger Tool-Wrapper existiert, WELCHE Tiers für welches
Ziel überhaupt laufen dürfen.

Drei unabhängige Tiers (siehe roadmap.md "Tool-Auswahl — 3 Tiers"):
    Tier 1  Safe Validation      — Default AN, kein Impact
            (nuclei, nmap --script vuln,safe, testssl.sh, ffuf, searchsploit -m)
    Tier 2  Active Injection     — Opt-in via --enable-injection
            (sqlmap, dalfox, wpscan)
    Tier 3  Exploitation/Creds   — Opt-in via --enable-exploit
            (Metasploit auxiliary/scanner "check" only, hydra/medusa)

Autorisierungsregeln:
    Tier 1  Ziel in authorized_scopes.json  ODER  interaktive Bestätigung (TTY).
            Ohne beides: Tier 1 wird übersprungen — fail-safe, kein Blind-Scan.
    Tier 2  NUR Ziel in authorized_scopes.json mit "tier2" in tiers[].
            Keine interaktive Ausnahme — muss vorab signiert sein.
    Tier 3  Ziel in authorized_scopes.json mit "tier3" in tiers[]  UND
            zusätzlich eine live getippte Bestätigung PRO RUN (TTY erforderlich).
            In nicht-interaktiven Läufen (Cron/CI) ist Tier 3 IMMER blockiert.

Jede Entscheidung (erlaubt wie verweigert) wird deterministisch als JSON-Zeile
nach logs/audit_phase9.jsonl geschrieben — Wer (OS-User) / Was (Tier) / Wann /
Ziel / Ergebnis + Begründung. Das Log wird nie überschrieben, nur angehängt.

Verwendung:
    from scope_gate import check_scope
    decision = check_scope(target, enable_injection=False, enable_exploit=False, flow_id=state.id)
    if decision.tier1_allowed:
        ...  # Team 7 darf Tier-1-Tools ausführen
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import date, datetime
from getpass import getuser

_SUITE_DIR = os.path.dirname(os.path.abspath(__file__))
SCOPE_FILE = os.path.join(_SUITE_DIR, "authorized_scopes.json")
LOG_DIR    = os.path.join(_SUITE_DIR, "logs")
AUDIT_LOG  = os.path.join(LOG_DIR, "audit_phase9.jsonl")


@dataclass
class GateDecision:
    target:        str
    tier1_allowed: bool = False
    tier2_allowed: bool = False
    tier3_allowed: bool = False
    reasons:       dict = field(default_factory=dict)   # tier -> Begründung

    @property
    def allowed(self) -> bool:
        """Team 7 läuft überhaupt nur, wenn mindestens Tier 1 erlaubt ist."""
        return self.tier1_allowed

    @property
    def summary(self) -> str:
        parts = []
        for tier, ok in (
            ("tier1", self.tier1_allowed),
            ("tier2", self.tier2_allowed),
            ("tier3", self.tier3_allowed),
        ):
            parts.append(f"{tier}={'OK' if ok else 'BLOCKED'}")
        return " · ".join(parts)


def _load_scopes() -> list[dict]:
    if not os.path.exists(SCOPE_FILE):
        return []
    try:
        with open(SCOPE_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("scopes", [])
    except Exception:
        return []


def _find_entry(target: str, scopes: list[dict]) -> dict | None:
    for entry in scopes:
        if entry.get("target", "").strip().lower() == target.strip().lower():
            return entry
    return None


def _is_expired(entry: dict) -> bool:
    valid_until = entry.get("valid_until")
    if not valid_until:
        return True  # kein Datum = keine gültige Freigabe
    try:
        return date.fromisoformat(valid_until) < date.today()
    except ValueError:
        return True


def _interactive_confirm(prompt_text: str, target: str) -> bool:
    """Live-Bestätigung — erfordert TTY, tippt exakt den Zielnamen. Kein Fallback in Cron/CI."""
    if not sys.stdin.isatty():
        return False
    try:
        from rich.prompt import Prompt
        typed = Prompt.ask(f"  [bold yellow]{prompt_text}[/]\n  Zielname zur Bestätigung eingeben")
    except Exception:
        typed = input(f"{prompt_text}\nZielname zur Bestätigung eingeben: ")
    return typed.strip().lower() == target.strip().lower()


def check_scope(
    target: str,
    enable_injection: bool = False,
    enable_exploit: bool = False,
    flow_id: str = "",
) -> GateDecision:
    """Prüft alle drei Tiers unabhängig voneinander und protokolliert die Entscheidung."""
    scopes = _load_scopes()
    entry  = _find_entry(target, scopes)
    valid  = bool(entry) and not _is_expired(entry)
    tiers  = set(entry.get("tiers", [])) if valid else set()

    decision = GateDecision(target=target)

    # Tier 1 — Whitelist ODER interaktive Bestätigung
    if valid and "tier1" in tiers:
        decision.tier1_allowed = True
        decision.reasons["tier1"] = "whitelisted"
    elif _interactive_confirm(
        f"Aktive Validierung (Tier 1 — safe) gegen '{target}' — autorisiert?", target
    ):
        decision.tier1_allowed = True
        decision.reasons["tier1"] = "interactive-confirmed"
    else:
        decision.reasons["tier1"] = "not whitelisted and no interactive confirmation"

    # Tier 2 — NUR Whitelist, kein interaktiver Bypass
    if enable_injection:
        if valid and "tier2" in tiers:
            decision.tier2_allowed = True
            decision.reasons["tier2"] = "whitelisted"
        else:
            decision.reasons["tier2"] = "--enable-injection requires a tier2 whitelist entry"
    else:
        decision.reasons["tier2"] = "not requested (--enable-injection not set)"

    # Tier 3 — Whitelist UND live Bestätigung pro Run, niemals in Cron/CI
    if enable_exploit:
        if valid and "tier3" in tiers and _interactive_confirm(
            f"EXPLOITATION (Tier 3) gegen '{target}' — pro-Run-Autorisierung erforderlich",
            target,
        ):
            decision.tier3_allowed = True
            decision.reasons["tier3"] = "whitelisted + interactive-confirmed"
        else:
            decision.reasons["tier3"] = (
                "--enable-exploit requires a tier3 whitelist entry AND live per-run confirmation (TTY)"
            )
    else:
        decision.reasons["tier3"] = "not requested (--enable-exploit not set)"

    _audit(decision, flow_id)
    return decision


def _audit(decision: GateDecision, flow_id: str) -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    record = {
        "ts":            datetime.now().isoformat(timespec="seconds"),
        "user":          getuser(),
        "flow_id":       flow_id,
        "target":        decision.target,
        "tier1_allowed": decision.tier1_allowed,
        "tier2_allowed": decision.tier2_allowed,
        "tier3_allowed": decision.tier3_allowed,
        "reasons":       decision.reasons,
    }
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
