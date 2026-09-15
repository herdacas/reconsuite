#!/usr/bin/env python3
"""Test: _tools_executed_guardrail-Fallback bei fabrizierten (nicht nur
fehlenden) Tool-Zuschreibungen — 2026-09-15, Live-Fund `rastede.de full`.

RedScanOutput.tools_executed nannte 2x 'curl_http_headers (...)', obwohl curl
in der red_scan-Task selbst NICHT lief (die 2 echten Calls waren nuclei+
nikto — curl lief tatsächlich in der VORHERIGEN blue-Phase). Der bestehende
Fabrikations-Check (real_used nicht leer, anders als der bereits gefixte
0-Calls-Fall) rejected zwar beim ERSTEN Auftreten korrekt, akzeptierte aber
beim Fallback (2. Versuch, reject_count>=1) dieselbe fabrizierte Zuschreibung
unverändert — derselbe Fallback-Fehler wie beim red_scan-0-Calls-Fall (Commit
bab38f2) und _searchsploit_version_guardrail (Commit 477ea1f).

Nutzt die echten CrewAI-Klassen (TaskOutput/GuardrailResult/convert_to_model),
Lehre aus test_guardrail_mutation_persistence.py (2026-09-15).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from crewai.tasks.task_output import TaskOutput  # noqa: E402
from crewai.utilities.guardrail import GuardrailResult  # noqa: E402
from crewai.utilities.converter import convert_to_model  # noqa: E402

from tools.trace import run_trace  # noqa: E402
from tasks import _tools_executed_guardrail, BlueOutput, RedScanOutput  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


def apply(to: TaskOutput, cls):
    ok, data = _tools_executed_guardrail(to)
    gr = GuardrailResult.from_tuple((ok, data))
    if not gr.success:
        return "REJECTED", gr.error, to
    if isinstance(gr.result, str):
        to.raw = gr.result
        model_output = convert_to_model(gr.result, cls, None, None, None)
        to.pydantic = model_output if isinstance(model_output, cls) else None
    elif isinstance(gr.result, TaskOutput):
        to = gr.result
    return "ACCEPTED", None, to


# --- Reproduktion des echten rastede-de-Live-Funds (red_scan, real_used nicht leer) ---
rs_kwargs = dict(
    targeted_findings=[
        "curl_http_headers (www.rastede.de) → Server: Apache → Apache httpd",
        "curl_http_headers (smarttime.rastede.de) → Server: WildFly/8 → WildFly 8",
        "nuclei_vulnerability_scanner (www.rastede.de, tags=wordpress,php,apache,plesk, severity=critical,high) → keine Treffer",
        "nikto_scanner (www.rastede.de:8443, tuning=4) → Missing X-Frame-Options header",
    ],
    tools_executed=[
        "curl_http_headers (www.rastede.de)",
        "curl_http_headers (smarttime.rastede.de)",
        "nuclei_vulnerability_scanner (www.rastede.de, wordpress/php/apache/plesk tags)",
        "nikto_scanner (www.rastede.de:8443, tuning=4)",
    ],
    open_ports=[443],
    vulnerabilities=[],
    analysis="x",
)

run_trace.activate("rastede.de", "test", "full", ["red_scan"])
run_trace.record_execution(
    ["/root/go/bin/nuclei", "-u", "https://www.rastede.de", "-tags", "wordpress,php,apache,plesk"],
    "keine kritischen/hohen Treffer", 5.0,
)
run_trace.record_execution(
    ["nikto", "-h", "https://www.rastede.de:8443"],
    "+ Missing X-Frame-Options header", 3.0,
)

ro1 = RedScanOutput(**rs_kwargs)
to1 = TaskOutput(description="d", raw=ro1.model_dump_json(), pydantic=ro1, agent="a")
status1, err1, _ = apply(to1, RedScanOutput)
check(f"1. Versuch: fabrizierte curl-Zuschreibung wird abgelehnt (status={status1})", status1 == "REJECTED")
check("reject_count auf 1", run_trace._guardrail_reject_count == 1)

ro2 = RedScanOutput(**rs_kwargs)
to2 = TaskOutput(description="d", raw=ro2.model_dump_json(), pydantic=ro2, agent="a")
status2, _, final2 = apply(to2, RedScanOutput)
check(f"2. Versuch (Fallback): wird akzeptiert (status={status2})", status2 == "ACCEPTED")
check("Fallback: tools_executed enthält kein curl_http_headers mehr",
      all("curl_http_headers" not in t for t in final2.pydantic.tools_executed))
check("Fallback: echte Tools (nuclei/nikto) bleiben in tools_executed erhalten",
      len(final2.pydantic.tools_executed) == 2)
check("Fallback: targeted_findings-Einträge von curl_http_headers entfernt (4->2)",
      len(final2.pydantic.targeted_findings) == 2)
check("Fallback: verbleibende targeted_findings sind die echten nuclei/nikto-Einträge",
      all(e.startswith("nuclei_vulnerability_scanner") or e.startswith("nikto_scanner")
          for e in final2.pydantic.targeted_findings))
check("Fallback: raw (downstream-Kontext) enthält 'curl_http_headers' nicht mehr",
      "curl_http_headers" not in final2.raw)
run_trace.reset()

# --- Negativkontrolle: blue-Task (kein targeted_findings-Feld) -> nur tools_executed betroffen ---
run_trace.activate("example.com", "test", "full", ["blue"])
run_trace.record_execution(["httpx", "example.com"], "Server: nginx", 0.5)
bo_kwargs = dict(tools_executed=["httpx_prober", "wafw00f"], open_ports=[443],
                  vulnerabilities=["x"], analysis="x")
bo1 = BlueOutput(**bo_kwargs)
to_b1 = TaskOutput(description="d", raw=bo1.model_dump_json(), pydantic=bo1, agent="a")
status_b1, _, _ = apply(to_b1, BlueOutput)
check(f"blue 1. Versuch: fabriziertes 'wafw00f' wird abgelehnt (status={status_b1})", status_b1 == "REJECTED")

bo2 = BlueOutput(**bo_kwargs)
to_b2 = TaskOutput(description="d", raw=bo2.model_dump_json(), pydantic=bo2, agent="a")
status_b2, _, final_b2 = apply(to_b2, BlueOutput)
check(f"blue 2. Versuch (Fallback): wird akzeptiert (status={status_b2})", status_b2 == "ACCEPTED")
check("blue-Fallback: 'wafw00f' aus tools_executed entfernt",
      final_b2.pydantic.tools_executed == ["httpx_prober"])
check("blue-Fallback: vulnerabilities unangetastet (kein targeted_findings-Feld auf BlueOutput)",
      final_b2.pydantic.vulnerabilities == ["x"])
run_trace.reset()

# --- Regression: kein Fehlalarm wenn alle Tools real gegroundet sind ---
run_trace.activate("example.com", "test", "full", ["blue"])
run_trace.record_execution(["httpx", "example.com"], "Server: nginx", 0.5)
run_trace.record_execution(["nmap", "example.com"], "443/tcp open", 1.0)
bo3 = BlueOutput(tools_executed=["httpx_prober", "nmap_scanner"], open_ports=[443],
                  vulnerabilities=["x"], analysis="x")
to_b3 = TaskOutput(description="d", raw=bo3.model_dump_json(), pydantic=bo3, agent="a")
status_b3, _, final_b3 = apply(to_b3, BlueOutput)
check(f"Regression: alle Tools real -> Accept ohne Änderung (status={status_b3})", status_b3 == "ACCEPTED")
check("Regression: tools_executed unverändert", final_b3.pydantic.tools_executed == ["httpx_prober", "nmap_scanner"])
run_trace.reset()

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
