#!/usr/bin/env python3
"""
verify_phase7.py — Roadmap-Verifikationsplan Phase 7 (offline-Ebenen 1, 2, 3, 6).

Deterministische Tests ohne echten Scan. Die E2E-Ebene 5 (echte Scans) läuft separat.

Ebenen:
  1 — Unit/Team:    Import; Team 4 ohne Key → no_key; Team 6 Score-Math; OWASP-Recall
  2 — Datenvertrag: Team1→Team4 CVE/IP-Extraktion; Team2→Team6 CVSS; Team6 leer
  3 — Routing:      route_results() CLEAN / CVA / FULL
  6 — Regression:   scope→Team-1-Pipeline (quick/osint ohne neue Teams)

Usage:
    python3 debugging/verify_phase7.py
"""
import sys, os, json, tempfile, warnings
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agentscanit"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
# Team 4 No-Key-Pfad deterministisch erzwingen
for _k in ("OTX_API_KEY", "SHODAN_API_KEY", "VT_API_KEY"):
    os.environ.pop(_k, None)
warnings.filterwarnings("ignore")

PASS, FAIL, SKIP = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m", "\033[33mSKIP\033[0m"
results: list[tuple[str, str, str]] = []   # (ebene, name, status)

def check(ebene, name, cond, detail=""):
    status = PASS if cond else FAIL
    results.append((ebene, name, "PASS" if cond else "FAIL"))
    print(f"  [{ebene}] {status}  {name}" + (f"  — {detail}" if detail else ""))

def skip(ebene, name, reason):
    results.append((ebene, name, "SKIP"))
    print(f"  [{ebene}] {SKIP}  {name}  — {reason}")


def _mock_workflow_json(cve_refs=None, ips=None, exploitable=False) -> str:
    """Schreibt eine temporäre workflow_last.json-artige Datei, gibt den Pfad zurück."""
    tasks = {"findings": {"cve_references": cve_refs or []}}
    if ips:
        tasks["blue"] = {"target_ips": ips}
    if exploitable:
        tasks["red"] = {"exploitable_findings": ["RCE via X"], "cve_references": cve_refs or []}
    data = {"target": "example.com", "timestamp": "20260611_000000", "tasks": tasks}
    fd, path = tempfile.mkstemp(suffix=".json", prefix="verify_p7_")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return path


print("\n=== verify_phase7.py — Ebenen 1/2/3/6 ===\n")

# ─────────────────────────────────────────────────────────────────────────────
# Ebene 1 — Unit-Tests pro Team
# ─────────────────────────────────────────────────────────────────────────────
print("Ebene 1 — Unit/Team")

# 1.1 Import aller 3 Teams
try:
    import threatintel_agent, compliance_agent, risk_scorer
    from threatintel_agent.tools import otx_tool
    from risk_scorer.risk_flow import run_risk_flow, _has_in_the_wild
    check("1", "Import aller 3 Teams", True)
except Exception as e:
    check("1", "Import aller 3 Teams", False, repr(e)[:120])
    print("\n  Abbruch — Import gescheitert.")
    sys.exit(1)

# 1.2 Team 4 ohne API-Key → no_key
try:
    r = otx_tool.lookup_cve("CVE-2021-44228")
    check("1", "Team 4 OTX ohne Key → no_key", r.get("status") == "no_key", f"status={r.get('status')}")
except Exception as e:
    check("1", "Team 4 OTX ohne Key → no_key", False, repr(e)[:120])

# 1.3 Team 6: CVSS 9.8 + exploitable → Score > 8.0
try:
    p = _mock_workflow_json(cve_refs=["CVE-2021-44228"], exploitable=True)
    flow = run_risk_flow(
        scan_json_path=p,
        nvd_results=[{"id": "CVE-2021-44228", "cvss_score": 9.8, "cvss_severity": "CRITICAL"}],
        has_exploitable=True,
    )
    os.unlink(p)
    check("1", "Team 6: CVSS 9.8 + exploitable → >8.0", flow.state.risk_score > 8.0,
          f"score={flow.state.risk_score}")
except Exception as e:
    check("1", "Team 6: CVSS 9.8 + exploitable → >8.0", False, repr(e)[:120])

# 1.4 Team 6: leere Inputs → Score 0, kein Crash
try:
    p = _mock_workflow_json(cve_refs=[])
    flow = run_risk_flow(scan_json_path=p, nvd_results=[], has_exploitable=False)
    os.unlink(p)
    check("1", "Team 6: leere Inputs → Score 0", flow.state.risk_score == 0.0,
          f"score={flow.state.risk_score}")
except Exception as e:
    check("1", "Team 6: leere Inputs → Score 0", False, repr(e)[:120])

# 1.5 Team 6: _has_in_the_wild Keyword-Matching
try:
    pos = _has_in_the_wild("CVE wird aktiv ausgenutzt (in-the-wild)")
    neg = _has_in_the_wild("Keine aktive Exploitation bekannt.")
    check("1", "Team 6: _has_in_the_wild Keywords", pos and not neg, f"pos={pos} neg={neg}")
except Exception as e:
    check("1", "Team 6: _has_in_the_wild Keywords", False, repr(e)[:120])

# 1.6 OWASP-Knowledge-Recall (best-effort — braucht Embedder)
try:
    from knowledge.owasp import owasp_knowledge
    from crewai.knowledge.knowledge import Knowledge
    from config import EMBED_BASE_URL, EMBED_MODEL
    emb = {"provider": "ollama", "config": {"url": f"{EMBED_BASE_URL}/api/embeddings", "model_name": EMBED_MODEL}}
    kn = Knowledge(collection_name="verify_owasp", sources=[owasp_knowledge], embedder=emb)
    kn.add_sources()   # embeddet die Quellen in die Storage (kein Auto-Embed im __init__)
    hits = kn.query(["SQL Injection"])
    # CrewAI knowledge-search liefert dicts mit Key 'content' (nicht 'context').
    text = " ".join(h.get("content", "") if isinstance(h, dict) else str(h) for h in hits)
    check("1", "OWASP-Recall 'SQL Injection' → A03", "A03" in text, f"hits={len(hits)}")
except Exception as e:
    skip("1", "OWASP-Recall 'SQL Injection' → A03", f"Embedder/Knowledge n/v: {repr(e)[:80]}")

# ─────────────────────────────────────────────────────────────────────────────
# Ebene 2 — Datenvertrag
# ─────────────────────────────────────────────────────────────────────────────
print("\nEbene 2 — Datenvertrag")

# 2.1 Team1→Team4: CVE + IP aus workflow_last.json extrahiert
try:
    from threatintel_agent.threatintel_flow import ThreatIntelFlow
    p = _mock_workflow_json(cve_refs=["CVE-2021-44228", "CVE-2020-1938"], ips=["44.228.249.3"])
    tf = ThreatIntelFlow()
    tf.state.scan_json_path = p
    tf.kickoff()   # no-key → schnell
    os.unlink(p)
    ok = ("CVE-2021-44228" in tf.state.cve_ids and "CVE-2020-1938" in tf.state.cve_ids
          and "44.228.249.3" in tf.state.ips)
    check("2", "Team1→Team4: CVE+IP-Extraktion", ok,
          f"cves={len(tf.state.cve_ids)} ips={tf.state.ips}")
except Exception as e:
    check("2", "Team1→Team4: CVE+IP-Extraktion", False, repr(e)[:120])

# 2.2 Team2→Team6: nvd_results CVSS wird gelesen (Score spiegelt CVSS)
try:
    p = _mock_workflow_json(cve_refs=["CVE-2099-0001"])
    flow = run_risk_flow(
        scan_json_path=p,
        nvd_results=[{"id": "CVE-2099-0001", "cvss_score": 7.5, "cvss_severity": "HIGH"}],
        has_exploitable=False,
    )
    os.unlink(p)
    # base=7.5, mul 1.0 → 7.5
    check("2", "Team2→Team6: CVSS gelesen (7.5→7.5)", abs(flow.state.risk_score - 7.5) < 0.01,
          f"score={flow.state.risk_score}")
except Exception as e:
    check("2", "Team2→Team6: CVSS gelesen", False, repr(e)[:120])

# 2.3 Team 6 mit threat_intel_output="" → kein Fehler
try:
    p = _mock_workflow_json(cve_refs=["CVE-2099-0002"])
    flow = run_risk_flow(scan_json_path=p,
                         nvd_results=[{"id": "CVE-2099-0002", "cvss_score": 5.0, "cvss_severity": "MEDIUM"}],
                         threat_intel_output="", has_exploitable=False)
    os.unlink(p)
    check("2", "Team6 mit threat_intel_output='' → ok", flow.state.risk_score == 5.0,
          f"score={flow.state.risk_score}")
except Exception as e:
    check("2", "Team6 mit threat_intel_output='' → ok", False, repr(e)[:120])

# ─────────────────────────────────────────────────────────────────────────────
# Ebene 3 — Flow-Routing
# ─────────────────────────────────────────────────────────────────────────────
print("\nEbene 3 — Routing")
try:
    from flow import ReconSuiteFlow

    def _route(has_cve, has_exploit):
        f = ReconSuiteFlow()
        f.state.has_cve_findings = has_cve
        f.state.has_exploitable  = has_exploit
        return f.route_results()

    check("3", "kein CVE → CLEAN",        _route(False, False) == "clean")
    check("3", "CVE, kein Exploit → CVA", _route(True, False) == "cve_analysis")
    check("3", "CVE + Exploit → FULL",    _route(True, True) == "full_analysis")
except Exception as e:
    check("3", "Routing route_results()", False, repr(e)[:140])

# ─────────────────────────────────────────────────────────────────────────────
# Ebene 6 — Regression (Team-1-Pipeline pro Scope)
# ─────────────────────────────────────────────────────────────────────────────
print("\nEbene 6 — Regression")
try:
    from crew import AgentScanITCrew
    qp = AgentScanITCrew("example.com", "", "quick"); qp.crew()
    op = AgentScanITCrew("example.com", "", "osint"); op.crew()
    check("6", "scope=quick → [research,blue,findings,report]",
          qp.pipeline == ["research", "blue", "findings", "report"], str(qp.pipeline))
    check("6", "scope=osint → [research,report]",
          op.pipeline == ["research", "report"], str(op.pipeline))
except Exception as e:
    check("6", "scope→Team-1-Pipeline", False, repr(e)[:120])

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
n_pass = sum(1 for _, _, s in results if s == "PASS")
n_fail = sum(1 for _, _, s in results if s == "FAIL")
n_skip = sum(1 for _, _, s in results if s == "SKIP")
print(f"\n=== Ergebnis: {n_pass} PASS, {n_fail} FAIL, {n_skip} SKIP ===")
if n_fail:
    print("  FAILs:")
    for eb, name, s in results:
        if s == "FAIL":
            print(f"    [{eb}] {name}")
sys.exit(1 if n_fail else 0)
