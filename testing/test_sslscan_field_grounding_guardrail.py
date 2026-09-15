#!/usr/bin/env python3
"""Test für _blue_findings_sslscan_grounding_guardrail (blue/findings) — 2026-09-15.

Backlog-Punkt 3 (CLAUDE.md, 2026-09-12): sslscan-Banner-Kontamination erreicht
Team 5 (compliance) / Team 6 (risk_scorer), nicht nur den finalen Reporter-
Task (dort bereits durch _value_grounding_guardrail + _strip_sslscan_self_
banner geschützt). ComplianceFlow.load_findings() liest die rohen 'preview'-
Texte ALLER Tasks (inkl. blue/findings) direkt aus workflow_last.json, OHNE
Filterung — die Kontamination muss also schon in blue/findings' EIGENEM
strukturierten Output verhindert werden.

Nutzt echte CrewAI-Reexport-Mechanik (TaskOutput + GuardrailResult +
convert_to_model, wie testing/test_guardrail_mutation_persistence.py) statt
nur das Python-Objekt direkt zu prüfen — Lehre aus dem Begleitfund bei
_open_ports_completeness_guardrail (2026-09-15).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from crewai.tasks.task_output import TaskOutput  # noqa: E402
from crewai.utilities.guardrail import GuardrailResult  # noqa: E402
from crewai.utilities.converter import convert_to_model  # noqa: E402

from tools.trace import run_trace  # noqa: E402
from tasks import (  # noqa: E402
    _blue_findings_sslscan_grounding_guardrail,
    BlueOutput,
    FindingsOutput,
)

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


def apply_guardrail_success(task_output: TaskOutput, output_pydantic_cls):
    ok, data = _blue_findings_sslscan_grounding_guardrail(task_output)
    gr = GuardrailResult.from_tuple((ok, data))
    assert gr.success, f"Guardrail rejected unerwartet: {gr.error}"
    if isinstance(gr.result, str):
        task_output.raw = gr.result
        model_output = convert_to_model(gr.result, output_pydantic_cls, None, None, None)
        task_output.pydantic = model_output if isinstance(model_output, output_pydantic_cls) else None
    elif isinstance(gr.result, TaskOutput):
        task_output = gr.result
    return task_output


# --- Reproduktion des echten example-com-Fixture-Falls (blue) ---
# corpus/fixtures/example-com/scanner_trace.json: sslscan lieferte NUR den
# Eigenbanner ('Version: 2.1.2\nOpenSSL 3.0.13 30 Jan 2024'), blue.vulnerabilities
# übernahm '3.0.13' trotzdem als angebliche Ziel-Finding.
run_trace.activate("example.com", "test", "full", ["blue"])
run_trace.record_execution(
    ["sslscan", "example.com:443"],
    "Version: 2.1.2\nOpenSSL 3.0.13 30 Jan 2024\n",
    0.3,
)
bo = BlueOutput(
    tools_executed=["sslscan_tls"],
    open_ports=[443],
    services={},
    vulnerabilities=[
        "Missing X-Frame-Options header on HTTPS endpoint.",
        "OpenSSL 3.0.13 detected; while not currently known to have critical CVEs, continuous patching is recommended.",
    ],
    analysis="x",
)
to = TaskOutput(description="d", raw=bo.model_dump_json(), pydantic=bo, agent="a")
to_final = apply_guardrail_success(to, BlueOutput)
check("blue: kontaminierter Vulnerability-Eintrag entfernt",
      to_final.pydantic is not None
      and all("3.0.13" not in v for v in to_final.pydantic.vulnerabilities))
check("blue: unabhängiger Eintrag bleibt erhalten",
      "Missing X-Frame-Options header on HTTPS endpoint." in to_final.pydantic.vulnerabilities)
check("blue: raw (downstream-Kontext-Text) enthält '3.0.13' nicht mehr",
      "3.0.13" not in to_final.raw)
run_trace.close_phase("blue")

# --- Reproduktion des echten Falls (findings, sslscan bereits in closed phase 'blue') ---
fo = FindingsOutput(
    service_versions=["OpenSSL 3.0.13"],
    cve_references=["CVE-2011-1468"],
    risk_summary="x",
)
to2 = TaskOutput(description="d", raw=fo.model_dump_json(), pydantic=fo, agent="a")
to2_final = apply_guardrail_success(to2, FindingsOutput)
check("findings: kontaminierte service_versions entfernt (sslscan lief in blue, nicht in findings selbst)",
      to2_final.pydantic is not None and to2_final.pydantic.service_versions == [])
run_trace.reset()

# --- Negativkontrolle: ECHTE sslscan-Scan-Daten (nicht nur Banner) bleiben erhalten ---
run_trace.activate("other.example", "test", "full", ["blue"])
run_trace.record_execution(
    ["sslscan", "other.example:443"],
    "Version: 2.1.2\nOpenSSL 3.0.13 30 Jan 2024\n\n"
    "Testing SSL server other.example on port 443\n\n"
    "  TLS_AES_256_GCM_SHA384\n"
    "Server key exchange: X25519\nSSL Certificate:\n"
    "  Subject: other.example\n",
    2.0,
)
bo2 = BlueOutput(
    tools_executed=["sslscan_tls"],
    open_ports=[443],
    services={},
    vulnerabilities=["TLS 1.3 with TLS_AES_256_GCM_SHA384 negotiated."],
    analysis="x",
)
to3 = TaskOutput(description="d", raw=bo2.model_dump_json(), pydantic=bo2, agent="a")
to3_final = apply_guardrail_success(to3, BlueOutput)
check("Accept: kein Fehlalarm wenn sslscan echte Scan-Daten liefert (kein Banner-only-Versionsmatch)",
      to3_final.pydantic.vulnerabilities == ["TLS 1.3 with TLS_AES_256_GCM_SHA384 negotiated."])

# --- Negativkontrolle: kein sslscan gelaufen -> Guardrail rührt nichts an ---
run_trace.reset()
run_trace.activate("example.com", "test", "web", ["blue"])
run_trace.record_execution(["nmap", "example.com"], "443/tcp open", 1.0)
bo3 = BlueOutput(tools_executed=["nmap_scanner"], open_ports=[443],
                  vulnerabilities=["OpenSSL 3.0.13 mentioned somewhere unrelated."], analysis="x")
to4 = TaskOutput(description="d", raw=bo3.model_dump_json(), pydantic=bo3, agent="a")
to4_final = apply_guardrail_success(to4, BlueOutput)
check("Accept: kein sslscan-Call -> Feld bleibt unangetastet",
      to4_final.pydantic.vulnerabilities == ["OpenSSL 3.0.13 mentioned somewhere unrelated."])
run_trace.reset()

# --- Skip: pydantic=None crasht nicht ---
ok5, _ = _blue_findings_sslscan_grounding_guardrail(TaskOutput(description="d", raw="raw text", agent="a"))
check(f"Skip: pydantic=None crasht nicht (ok={ok5})", ok5 is True)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
