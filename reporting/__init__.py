"""
reporting — Team 3: Assessment Reporting

Führt Scan-Daten (agentscanit) und CVE-Validation (interpret-agent)
zu einem finalen Bericht zusammen. Kein LLM.
"""
import sys
import os

_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from reporting_flow import ReportingFlow, ReportingState, run_reporting_flow  # noqa: E402

__all__ = ["ReportingFlow", "ReportingState", "run_reporting_flow"]
