"""Service Name Normalization Knowledge Source.

HTTP-Server-Header enthalten interne Bezeichnungen die in NVD/searchsploit
nicht direkt auffindbar sind. Diese Knowledge Source mappt rohe Header-Werte
auf die kanonischen Produktnamen für korrekte CVE-Suchen.

Storage + Embedder werden von der Crew via Crew(embedder=...) gesetzt —
kein manuelles KnowledgeStorage hier nötig.
"""

from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

SERVICE_NORM_TEXT = """
# Service Name Normalization for CVE Search

When scanning web services, HTTP headers and tool outputs often report internal
or abbreviated service names that do not match NVD/searchsploit product names.
Always translate before searching CVEs:

## Java Application Servers
Apache-Coyote      → Apache Tomcat  ⚠ VERSION WARNING: The number after the slash (e.g. /1.1) is the Coyote HTTP connector version, NOT the Tomcat version. Do NOT use it as the Tomcat version. Report the Tomcat version as "unknown" unless whatweb, nmap, or another tool explicitly reports a Tomcat version string.
Apache-Coyote/1.1  → Apache Tomcat (version unknown — connector v1.1 ≠ Tomcat version)
Apache-Coyote/1.0  → Apache Tomcat (version unknown — connector v1.0 ≠ Tomcat version)

## Java Web Servers
Jetty              → Eclipse Jetty
jetty              → Eclipse Jetty

## Ruby Web Servers
WEBrick            → Ruby WEBrick
webrick            → Ruby WEBrick

## Python Web Frameworks
Werkzeug           → Python Werkzeug (Flask)
gunicorn           → Gunicorn

## Microsoft
IIS                → Microsoft IIS
Microsoft-IIS      → Microsoft IIS

## Node.js
Express            → Express.js (Node.js)

## General Rule
Use the product name as listed on NVD (https://nvd.nist.gov).
Use whatweb/httpx-detected technology names over raw HTTP header values.
When in doubt, search both the raw name and the normalized name.
"""

service_normalization_knowledge = StringKnowledgeSource(
    content=SERVICE_NORM_TEXT,
    metadata={"category": "service-normalization", "use": "cvesearch"},
)
