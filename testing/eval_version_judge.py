#!/usr/bin/env python3
"""
eval_version_judge.py — Dimension 2 (Ergänzung): LLM-Judge für Versions-Treue

Unabhängige zweite Meinung zum deterministischen BUG-17-Banner-Versions-Gate
(reporting_flow._version_confirmed_in_scan). Der Judge bekommt den erkannten
Service-Banner + die CVE (mit affected-Versionen) und urteilt, ob die laufende
Version plausibel betroffen ist.

Zweck: Validieren, dass das deterministische Gate vernünftig urteilt — NICHT es
ersetzen. Metrik = Konsens-Rate zwischen Judge und Gate (Ziel ≥ 0.8).

Nutzt das aktive Remote-Modell (kostet Calls). Read-only bzgl. Framework.

Verwendung:
    python3 eval_version_judge.py            # Selbsttest gegen die 5 BUG-17-Fälle
"""
from __future__ import annotations
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "agentscanit"))

# Die 5 BUG-17-Referenzfälle: (banner_im_scan, cve_beschreibung_kurz, GATE_erwartung)
#   GATE_erwartung True  = Version verifiziert (Banner trägt konkrete Version, passt)
#   GATE_erwartung False = unbestätigt (versionsloser Banner)
BUG17_CASES = [
    ("OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13",
     "CVE-2018-15473: OpenSSH before 7.7 user enumeration", True),
    ("Apache httpd 2.4.7 (Ubuntu)",
     "CVE-2017-9798: Apache httpd OPTIONS memory disclosure (Optionsbleed)", True),
    ("Apache Tomcat 8.5.19",
     "CVE-2017-12615: Tomcat 7.0.0-7.0.79 / 8.5.x PUT method RCE", True),
    ("Oracle WebLogic Server 12.2.1.3",
     "CVE-2023-21839: WebLogic 12.2.1.3/12.2.1.4/14.1.1 T3/IIOP RCE", True),
    ("Apache-Coyote/1.1",
     "CVE-2025-24813: Apache Tomcat 9.0.0-11.0.x RCE via partial PUT", False),
]

_JUDGE_PROMPT = """You are a precise vulnerability-version analyst. Given a service banner detected in a scan and a CVE, decide whether the RUNNING version is plausibly affected.

Banner detected: {banner}
CVE: {cve}

Rules:
- Answer "AFFECTED" only if the banner contains a CONCRETE version number that falls in the CVE's affected range.
- Answer "UNCONFIRMED" if the banner has NO concrete version (e.g. only a protocol token like "Apache-Coyote/1.1"), so the version match cannot be verified.
- Answer "NOT_AFFECTED" if the banner version is clearly outside the affected range.

Reply with EXACTLY one word: AFFECTED, UNCONFIRMED, or NOT_AFFECTED."""


def _judge_call(banner: str, cve: str) -> str:
    import config
    from openai import OpenAI
    client = OpenAI(base_url=config.OLLAMA_BASE_URL.rstrip("/") + "/v1",
                    api_key=config.OLLAMA_API_KEY or "ollama")
    r = client.chat.completions.create(
        model=config.MODEL_ANALYSIS,
        messages=[{"role": "user", "content": _JUDGE_PROMPT.format(banner=banner, cve=cve)}],
        max_tokens=2048, temperature=0.0, extra_body={"think": False},
    )
    out = (r.choices[0].message.content or "").strip().upper()
    for label in ("NOT_AFFECTED", "UNCONFIRMED", "AFFECTED"):
        if label in out:
            return label
    return "UNPARSEABLE"


def _judge_to_gate(judge: str) -> bool:
    """Judge-Urteil auf die Gate-Semantik (verifiziert=True) abbilden."""
    return judge == "AFFECTED"   # nur AFFECTED = versions-verifiziert


def run_selftest() -> dict:
    agree = 0
    rows = []
    for banner, cve, gate_expected in BUG17_CASES:
        judge = _judge_call(banner, cve)
        judge_verified = _judge_to_gate(judge)
        consensus = (judge_verified == gate_expected)
        agree += consensus
        rows.append({"banner": banner, "judge": judge,
                     "judge_verified": judge_verified, "gate": gate_expected,
                     "consensus": consensus})
    rate = agree / len(BUG17_CASES)
    return {"consensus_rate": rate, "rows": rows, "passed": rate >= 0.8}


if __name__ == "__main__":
    res = run_selftest()
    print("=== Dim 2: LLM-Judge Versions-Treue vs. BUG-17-Gate ===")
    for r in res["rows"]:
        mark = "✓" if r["consensus"] else "✗ DISSENS"
        print(f"  {mark}  judge={r['judge']:13} gate_verif={r['gate']!s:5}  «{r['banner'][:40]}»")
    print(f"  Konsens-Rate: {res['consensus_rate']:.2f} (Ziel ≥ 0.8) → "
          f"{'PASS' if res['passed'] else 'FAIL'}")
    sys.exit(0 if res["passed"] else 1)
