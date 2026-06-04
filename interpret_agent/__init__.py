"""
interpret-agent — Team 2: CVE Enrichment & Validation

Liest CVE-IDs aus Scan-Outputs, validiert gegen NVD API v2.
Kein LLM — alle Daten sind authoritative von NVD.
"""
import sys
import os

_dir       = os.path.dirname(os.path.abspath(__file__))
_suite_dir = os.path.dirname(_dir)   # recon-suite/ — needed for agentscanit imports
for _p in (_suite_dir, _dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from interpret_flow import InterpretFlow, InterpretState, run_interpret_flow  # noqa: E402

__all__ = ["InterpretFlow", "InterpretState", "run_interpret_flow"]
