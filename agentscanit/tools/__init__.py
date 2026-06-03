"""
tools/ — AgentScanIT tool package

Active scanning  (blue_agent)   → tools/active_scanning.py   (12 tools)
Passive recon    (research_agent)→ tools/passive_recon.py     (14 tools)
Shared helpers                  → tools/_base.py
"""

from tools.active_scanning import (
    nmap_tool, nikto_tool, whatweb_tool, sslscan_tool, testssl_tool,
    curl_tool, ping_tool, nuclei_tool, ffuf_tool, enum4linux_tool,
    httpx_tool, naabu_tool,
)

from tools.passive_recon import (
    ddg_search_tool, theharvester_tool, sublist3r_tool, subfinder_tool,
    dnsrecon_tool, dig_tool, whois_tool, amass_tool, assetfinder_tool,
    dnsx_tool, katana_tool, waybackurls_tool, gau_tool, searchsploit_tool,
)

from tools.nvd import nvd_tool

__all__ = [
    # active scanning
    "nmap_tool", "nikto_tool", "whatweb_tool", "sslscan_tool", "testssl_tool",
    "curl_tool", "ping_tool", "nuclei_tool", "ffuf_tool", "enum4linux_tool",
    "httpx_tool", "naabu_tool",
    # passive recon
    "ddg_search_tool", "theharvester_tool", "sublist3r_tool", "subfinder_tool",
    "dnsrecon_tool", "dig_tool", "whois_tool", "amass_tool", "assetfinder_tool",
    "dnsx_tool", "katana_tool", "waybackurls_tool", "gau_tool", "searchsploit_tool",
    # nvd
    "nvd_tool",
]
