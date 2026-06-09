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
Apache-Coyote      → Apache Tomcat
Apache-Coyote/1.1  → Apache Tomcat
Apache-Coyote/1.0  → Apache Tomcat

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
