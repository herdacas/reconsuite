#!/usr/bin/env python3
"""
test_scope_gate.py — Phase 9.0 Verifikation: Scope-Gate

Deterministische, isolierte Tests für scope_gate.check_scope() — ohne CrewAI,
ohne Ollama, ohne Netzwerk. Deckt die "Scope-Gate"-Zeile aus dem Phase-9-
Verifikationsplan in roadmap.md ab:

    | Scope-Gate | Ziel außerhalb der Whitelist | Abbruch vor jedem aktiven
      Request, Audit-Log-Eintrag |

Zusätzlich: Tier-2/Tier-3-Regeln (kein interaktiver Bypass, Tier 3 erfordert
zwingend TTY) und dass jede Entscheidung im Audit-Log landet.

Verwendung:
    python3 testing/test_scope_gate.py
    → exit 0 wenn alle Assertions bestehen, sonst AssertionError + exit 1.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scope_gate as sg


def _with_temp_scope_file(scopes: dict):
    """Context manager: lenkt scope_gate.SCOPE_FILE/AUDIT_LOG auf ein Temp-Verzeichnis um,
    damit die Tests nicht den echten authorized_scopes.json / audit_phase9.jsonl berühren."""
    class _Ctx:
        def __enter__(self_):
            self_.tmpdir = tempfile.mkdtemp(prefix="scope_gate_test_")
            self_._orig_scope_file = sg.SCOPE_FILE
            self_._orig_audit_log  = sg.AUDIT_LOG
            sg.SCOPE_FILE = os.path.join(self_.tmpdir, "authorized_scopes.json")
            sg.AUDIT_LOG  = os.path.join(self_.tmpdir, "audit_phase9.jsonl")
            if scopes is not None:
                with open(sg.SCOPE_FILE, "w", encoding="utf-8") as f:
                    json.dump(scopes, f)
            return self_

        def __exit__(self_, *exc):
            sg.SCOPE_FILE = self_._orig_scope_file
            sg.AUDIT_LOG  = self_._orig_audit_log

    return _Ctx()


def test_unlisted_target_blocked_noninteractive():
    """Ziel nicht in der Whitelist, kein TTY → Tier 1 blockiert (fail-safe)."""
    with _with_temp_scope_file({"scopes": []}):
        # sys.stdin.isatty() ist in Testläufen (kein TTY) bereits False —
        # kein Monkeypatch nötig, das ist der reale nicht-interaktive Fall.
        decision = sg.check_scope("evil-unlisted-target.example", flow_id="test-1")
        assert decision.allowed is False, "unlisted target must NOT pass Tier 1 without TTY"
        assert "not whitelisted" in decision.reasons["tier1"]


def test_whitelisted_target_tier1_allowed():
    """Ziel mit tier1 in der Whitelist → Tier 1 erlaubt, Tier 2/3 nicht angefragt."""
    scopes = {"scopes": [{
        "target": "juice-shop.herokuapp.com",
        "valid_until": "2099-12-31",
        "tiers": ["tier1"],
    }]}
    with _with_temp_scope_file(scopes):
        decision = sg.check_scope("juice-shop.herokuapp.com", flow_id="test-2")
        assert decision.allowed is True, "whitelisted tier1 target must pass"
        assert decision.tier2_allowed is False
        assert decision.tier3_allowed is False


def test_tier2_requires_whitelist_not_just_flag():
    """--enable-injection allein reicht nicht — ohne tier2 in der Whitelist bleibt es blockiert."""
    scopes = {"scopes": [{
        "target": "example.com",
        "valid_until": "2099-12-31",
        "tiers": ["tier1"],   # kein tier2!
    }]}
    with _with_temp_scope_file(scopes):
        decision = sg.check_scope("example.com", enable_injection=True, flow_id="test-3")
        assert decision.tier1_allowed is True
        assert decision.tier2_allowed is False, "tier2 must stay blocked without explicit whitelist entry"
        assert "tier2 whitelist entry" in decision.reasons["tier2"]


def test_tier3_always_blocked_without_tty_even_if_whitelisted():
    """Tier 3 verlangt IMMER eine Live-Bestätigung — auch mit vollständiger Whitelist
    bleibt es in einem nicht-interaktiven Lauf (Cron/CI) blockiert."""
    scopes = {"scopes": [{
        "target": "example.com",
        "valid_until": "2099-12-31",
        "tiers": ["tier1", "tier2", "tier3"],
    }]}
    with _with_temp_scope_file(scopes):
        decision = sg.check_scope("example.com", enable_exploit=True, flow_id="test-4")
        assert decision.tier3_allowed is False, "tier3 must require live per-run confirmation (TTY)"


def test_expired_authorization_blocked():
    """Abgelaufene Freigabe (valid_until in der Vergangenheit) zählt wie 'nicht gelistet'."""
    scopes = {"scopes": [{
        "target": "example.com",
        "valid_until": "2020-01-01",
        "tiers": ["tier1"],
    }]}
    with _with_temp_scope_file(scopes):
        decision = sg.check_scope("example.com", flow_id="test-5")
        assert decision.allowed is False, "expired scope entry must not authorize Tier 1"


def test_every_decision_is_audited():
    """Jede check_scope()-Entscheidung muss als JSON-Zeile im Audit-Log landen."""
    with _with_temp_scope_file({"scopes": []}) as ctx:
        sg.check_scope("audited-target.example", flow_id="test-6")
        assert os.path.exists(sg.AUDIT_LOG), "audit log must be created on first decision"
        with open(sg.AUDIT_LOG, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 1
        record = lines[0]
        assert record["target"] == "audited-target.example"
        assert record["flow_id"] == "test-6"
        assert record["tier1_allowed"] is False
        assert "reasons" in record and "tier1" in record["reasons"]


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = []
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except AssertionError as e:
            failed.append(t.__name__)
            print(f"  ✗ {t.__name__}: {e}")
    print()
    if failed:
        print(f"FAILED: {len(failed)}/{len(tests)} — {', '.join(failed)}")
        sys.exit(1)
    print(f"PASS: {len(tests)}/{len(tests)} — Phase 9.0 Scope-Gate verifiziert")
    sys.exit(0)


if __name__ == "__main__":
    main()
