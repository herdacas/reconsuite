#!/usr/bin/env python3
"""Test: überlebt eine In-Place-Mutation eines Guardrails CrewAI's echten
Guardrail-Reexport-Mechanismus? (2026-09-15)

Befund beim Bau von _open_ports_completeness_guardrail: CrewAI's
Task._invoke_guardrail_function behandelt einen String-Rückgabewert als
"Reexport-Anweisung" — es baut output.pydantic NEU aus dem zurückgegebenen
String auf (convert_to_model), unabhängig davon ob das pydantic-Objekt vorher
in-place mutiert wurde. Ein Guardrail der mutiert und trotzdem den ALTEN raw-
String zurückgibt, verliert die Mutation beim echten Crew-Run — ein Unit-Test
der nur das Python-Objekt direkt prüft (FakeTaskOutput-Pattern) sieht das
NICHT, weil er CrewAI's Reexport-Pfad gar nicht durchläuft.

Dieser Test nutzt die ECHTEN CrewAI-Klassen/Funktionen (TaskOutput,
GuardrailResult, convert_to_model) um exakt nachzustellen was
Task._invoke_guardrail_function bei Erfolg tut (crewai/task.py, Zeile ~1360ff),
statt CrewAI's Verhalten zu vermuten.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from crewai.tasks.task_output import TaskOutput  # noqa: E402
from crewai.utilities.guardrail import GuardrailResult  # noqa: E402
from crewai.utilities.converter import convert_to_model  # noqa: E402

from tools.trace import run_trace  # noqa: E402
from tasks import (  # noqa: E402
    _tools_executed_guardrail,
    _open_ports_completeness_guardrail,
    BlueOutput,
    RedScanOutput,
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


def apply_guardrail_success(task_output: TaskOutput, guardrail_fn, output_pydantic_cls):
    """Repliziert exakt den Erfolgs-Zweig von Task._invoke_guardrail_function
    (crewai/task.py) für EINEN Guardrail-Aufruf — kein Retry-Loop nötig, wir
    testen nur ob die Mutation den Reexport überlebt."""
    ok, data = guardrail_fn(task_output)
    gr = GuardrailResult.from_tuple((ok, data))
    assert gr.success, f"Guardrail rejected unerwartet: {gr.error}"
    if isinstance(gr.result, str):
        task_output.raw = gr.result
        model_output = convert_to_model(gr.result, output_pydantic_cls, None, None, None)
        task_output.pydantic = model_output if isinstance(model_output, output_pydantic_cls) else None
    elif isinstance(gr.result, TaskOutput):
        task_output = gr.result
    return task_output


# --- red_scan: 0 echte Calls -> Felder müssen NACH dem vollen Reexport-Pfad leer sein ---
run_trace.activate("example.com", "test", "full", ["red_scan"])
rso = RedScanOutput(
    targeted_findings=["OpenSSL 3.0.13"],
    tools_executed=["nmap_scanner", "sslscan_tls"],
    open_ports=[80, 443, 8880],
    vulnerabilities=["Missing X-Frame-Options header."],
    analysis="x",
)
raw_before = rso.model_dump_json()
to = TaskOutput(description="d", raw=raw_before, pydantic=rso, agent="a")
to_final = apply_guardrail_success(to, _tools_executed_guardrail, RedScanOutput)
check("red_scan-Reexport: pydantic.open_ports leer NACH vollem CrewAI-Pfad",
      to_final.pydantic is not None and to_final.pydantic.open_ports == [])
check("red_scan-Reexport: raw enthält NICHT mehr '8880' (downstream-Kontext-Text)",
      "8880" not in to_final.raw)
check("red_scan-Reexport: raw enthält NICHT mehr 'OpenSSL 3.0.13' (downstream-Kontext-Text)",
      "OpenSSL 3.0.13" not in to_final.raw)
run_trace.reset()

# --- blue: nmap fand einen Port der im Feld fehlt -> muss NACH vollem Pfad ergänzt sein ---
run_trace.activate("example.com", "test", "full", ["blue"])
run_trace.record_execution(
    ["nmap", "-p", "1-65535", "example.com"],
    "PORT     STATE SERVICE\n80/tcp   open  http\n8880/tcp open  cddbp-alt\n",
    5.0,
)
bo = BlueOutput(tools_executed=["nmap_scanner"], open_ports=[80], vulnerabilities=[], analysis="x")
raw_before2 = bo.model_dump_json()
to2 = TaskOutput(description="d", raw=raw_before2, pydantic=bo, agent="a")
to2_final = apply_guardrail_success(to2, _open_ports_completeness_guardrail, BlueOutput)
check("blue-Reexport: pydantic.open_ports enthält 8880 NACH vollem CrewAI-Pfad",
      to2_final.pydantic is not None and 8880 in to2_final.pydantic.open_ports)
check("blue-Reexport: raw enthält jetzt '8880' (downstream-Kontext-Text)",
      "8880" in to2_final.raw)
run_trace.reset()

# --- Negativkontrolle: unveränderter Passthrough (kein echter Call in Trace) übersteht Reexport ---
run_trace.activate("example.com", "test", "full", ["blue"])
bo2 = BlueOutput(tools_executed=["httpx_prober"], open_ports=[443], vulnerabilities=[], analysis="x")
raw_before3 = bo2.model_dump_json()
to3 = TaskOutput(description="d", raw=raw_before3, pydantic=bo2, agent="a")
to3_final = apply_guardrail_success(to3, _open_ports_completeness_guardrail, BlueOutput)
check("Passthrough (kein nmap-Call): open_ports unverändert nach Reexport",
      to3_final.pydantic is not None and to3_final.pydantic.open_ports == [443])
run_trace.reset()

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
