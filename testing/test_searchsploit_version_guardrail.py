#!/usr/bin/env python3
"""Test für _searchsploit_version_guardrail (red) — Fallback-Fix 2026-09-15.

Backlog-Punkt 4 (CLAUDE.md, ungeprüfte Wissenslücke -> bei Untersuchung als
echter Bug bestätigt): der bestehende Reject+Retry-Pfad allein reicht
nachweislich NICHT — corpus/fixtures/rastede-de/scanner_trace.json (red-Phase)
zeigt, dass die 7 versionslosen searchsploit-Funde (ActiveMQ, uralte Apache-
CVEs, 'searchsploit --json Apache' ohne Version) trotz bereits aktivem
Guardrail im finalen structured_output landeten — dasselbe Muster wie bei
_tools_executed_guardrail (0/28 korrekt trotz aktivem Reject-Pfad, Commit
bab38f2). Fix: der Fallback (zweiter Versuch, reject_count>=1) leert
confirmed_attack_surface/exploitable_findings deterministisch statt
stillschweigend zu akzeptieren.

Nutzt die echten CrewAI-Klassen (TaskOutput/GuardrailResult/convert_to_model)
um CrewAI's Reexport-Mechanismus nachzustellen (Lehre aus
test_guardrail_mutation_persistence.py, 2026-09-15).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from crewai.tasks.task_output import TaskOutput  # noqa: E402
from crewai.utilities.guardrail import GuardrailResult  # noqa: E402
from crewai.utilities.converter import convert_to_model  # noqa: E402

from tools.trace import run_trace  # noqa: E402
from tasks import _searchsploit_version_guardrail, RedOutput  # noqa: E402

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
    ok, data = _searchsploit_version_guardrail(to)
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


ro_kwargs = dict(
    confirmed_attack_surface=[
        "Apache httpd:80 — ActiveMQ < 5.14.0 - Web Shell Upload (Metasploit)",
        "Apache httpd:80 — Apache 1.3.1",
    ],
    exploitable_findings=[
        "Apache httpd:80 — ActiveMQ < 5.14.0 - Web Shell Upload (Metasploit)",
        "Apache httpd:80 — Apache 1.3.1",
    ],
    cve_references=["CVE-2016-3088"],
)

# --- 1. Versuch: versionsloser Call + nicht-leere Felder -> REJECT ---
run_trace.activate("rastede.de", "test", "full", ["red"])
run_trace.record_execution(
    ["/usr/local/bin/searchsploit", "--json", "Apache"],
    '{"RESULTS_EXPLOIT": [{"Title":"ActiveMQ < 5.14.0 - Web Shell Upload (Metasploit)","Codes":"CVE-2016-3088"}]}',
    0.5,
)
ro1 = RedOutput(**ro_kwargs)
to1 = TaskOutput(description="d", raw=ro1.model_dump_json(), pydantic=ro1, agent="a")
status1, err1, _ = apply(to1, RedOutput)
check(f"1. Versuch: versionsloser Call wird abgelehnt (status={status1})", status1 == "REJECTED")
check("reject_count auf 1 gesetzt", run_trace._guardrail_reject_count == 1)

# --- 2. Versuch (Fallback): Agent liefert dieselben Funde erneut -> deterministisch geleert ---
ro2 = RedOutput(**ro_kwargs)
to2 = TaskOutput(description="d", raw=ro2.model_dump_json(), pydantic=ro2, agent="a")
status2, _, final2 = apply(to2, RedOutput)
check(f"2. Versuch (Fallback): wird akzeptiert, nicht erneut abgelehnt (status={status2})", status2 == "ACCEPTED")
check("Fallback: confirmed_attack_surface geleert", final2.pydantic.confirmed_attack_surface == [])
check("Fallback: exploitable_findings geleert", final2.pydantic.exploitable_findings == [])
check("Fallback: exploitable_findings_count synchron auf 0", final2.pydantic.exploitable_findings_count == 0)
check("Fallback: raw (downstream-Kontext) enthält 'ActiveMQ' nicht mehr", "ActiveMQ" not in final2.raw)
check("Fallback: cve_references bleibt unangetastet (separat durch _cve_trace_guardrail geschützt)",
      final2.pydantic.cve_references == ["CVE-2016-3088"])
run_trace.reset()

# --- Reproduktion des echten rastede-de-Fixture-Falls (2. Versuch direkt) ---
import json  # noqa: E402
d = json.load(open(Path(__file__).resolve().parent.parent / "corpus/fixtures/rastede-de/scanner_trace.json"))
red_phase = d["phases"]["red"]
run_trace.activate("rastede.de", "test", "full", ["red"])
for tc in red_phase["tool_calls"]:
    run_trace.record_execution(tc["command"], tc["raw_output"], tc["duration_s"])
run_trace._guardrail_reject_count = 1  # simuliert: erster Reject bereits erfolgt
ro3 = RedOutput(**{k: v for k, v in red_phase["structured_output"].items() if k in RedOutput.model_fields})
to3 = TaskOutput(description="d", raw=ro3.model_dump_json(), pydantic=ro3, agent="a")
status3, _, final3 = apply(to3, RedOutput)
check(f"Fixture-Reproduktion rastede-de: Fallback greift (status={status3})", status3 == "ACCEPTED")
check("Fixture-Reproduktion: confirmed_attack_surface geleert (7 fabrizierte Funde entfernt)",
      final3.pydantic.confirmed_attack_surface == [])
check("Fixture-Reproduktion: exploitable_findings geleert",
      final3.pydantic.exploitable_findings == [])
run_trace.reset()

# --- Negativkontrolle: searchsploit MIT Version -> kein Reject, kein Fallback-Clearing ---
run_trace.activate("example.com", "test", "full", ["red"])
run_trace.record_execution(
    ["searchsploit", "OpenSSH", "9.6p1"],
    '{"RESULTS_EXPLOIT": [{"Title":"OpenSSH 9.6p1 - Something","Codes":"CVE-2024-6387"}]}',
    0.5,
)
ro4 = RedOutput(
    confirmed_attack_surface=["ssh:22 — OpenSSH 9.6p1 regreSSHion"],
    exploitable_findings=["ssh:22 — OpenSSH 9.6p1 regreSSHion"],
    cve_references=["CVE-2024-6387"],
)
to4 = TaskOutput(description="d", raw=ro4.model_dump_json(), pydantic=ro4, agent="a")
status4, _, final4 = apply(to4, RedOutput)
check(f"Accept: versions-tragender Call wird nicht abgelehnt (status={status4})", status4 == "ACCEPTED")
check("Accept: Felder bleiben unverändert (echte Version vorhanden)",
      final4.pydantic.confirmed_attack_surface == ["ssh:22 — OpenSSH 9.6p1 regreSSHion"])
run_trace.reset()

# --- Negativkontrolle: leere Felder -> Guardrail greift gar nicht ---
run_trace.activate("example.com", "test", "full", ["red"])
run_trace.record_execution(["searchsploit", "Apache"], "{}", 0.2)
ro5 = RedOutput()
to5 = TaskOutput(description="d", raw=ro5.model_dump_json(), pydantic=ro5, agent="a")
status5, _, _ = apply(to5, RedOutput)
check(f"Skip: leere Felder -> kein Reject nötig (status={status5})", status5 == "ACCEPTED")
check("reject_count bleibt 0 (Guardrail griff gar nicht ein)", run_trace._guardrail_reject_count == 0)
run_trace.reset()

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
