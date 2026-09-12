**Target:** westerstede.de  
**Date:** 2026-09-12 02:52  
**Source:** AgentScanIT scan + NVD API v2

---

# Final Report: westerstede.de

## Reconnaissance Summary
  - IP: 62.67.46.162
  - Open ports: 25, 80, 443, 587, 993, 3400, 8443
  - Live subdomains: mail2.westerstede.de, mail3.westerstede.de, mail5.westerstede.de

## Scope & Methodik
| Tool | Zweck | Abgedeckte Assets |
|------|-------|-------------------|
| nmap | Port scanning & service detection | mail2.westerstede.de, mail3.westerstede.de, mail5.westerstede.de |
| httpx | HTTP/HTTPS probing & status code detection | mail2.westerstede.de, mail3.westerstede.de, mail5.westerstede.de |
| whatweb | Web server & application fingerprinting | mail2.westerstede.de, mail3.westerstede.de, mail5.westerstede.de |
| sslscan | TLS service details | mail2.westerstede.de, mail3.westerstede.de, mail5.westerstede.de |
| subfinder | Subdomain enumeration | westerstede.de |
| dig | DNS enumeration | westerstede.de |
| whois | WHOIS lookup | westerstede.de |
| ddg_search | Search engine reconnaissance | westerstede.de |

## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|---------|------|-------------|------|------------|
| SMTP | 25 | open | nmap | 1 |
| HTTP | 80 | 301 redirect | httpx | 2 |
| HTTPS | 443 | 403 forbidden | httpx | 3 |
| SMTP Submission | 587 | open | nmap | 4 |
| IMAPS | 993 | open | nmap | 5 |
| unknown | 3400 | open | nmap | 6 |
| HTTPS-alt | 8443 | open | nmap | 7 |

## Detected Technologies
whatweb → Apache httpd 2.4.52 (Ubuntu)
whatweb → hMailServer 5.4.4

## CVE Validation (NVD API v2)

*Source: https://nvd.nist.gov — 2026-09-12 02:52*

- Gelistet: **10**  Critical: **10**  High: **0**

### 🔴 CVE-2020-11984 — CVSS 9.8 (CRITICAL)
- **Published:** 2020-08-07  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:communications_element_manager:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:communications_session_report_manager:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:communications_session_route_manager:*:*:*:*:*:*:*:*`

**References:**
- http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00068.html
- http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00071.html
- http://packetstormsecurity.com/files/159009/Apache2-mod_proxy_uwsgi-Incorrect-Request-Handling.html
- http://www.openwall.com/lists/oss-security/2020/08/08/1
- http://www.openwall.com/lists/oss-security/2020/08/08/10

### 🔴 CVE-2021-26691 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-06-10  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause a heap overflow

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:enterprise_manager_ops_center:12.4.0.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.1:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.3:*:*:*:*:*:*:*`

**References:**
- http://httpd.apache.org/security/vulnerabilities_24.html
- http://www.openwall.com/lists/oss-security/2021/06/10/7
- https://lists.apache.org/thread.html/r50cae1b71f1e7421069036b213c26da7d8f47dd59874e3bd956959fe%40%3Cannounce.httpd.apache.org%3E
- https://lists.apache.org/thread.html/r7f2b70b621651548f4b6f027552f1dd91705d7111bb5d15cda0a68dd%40%3Cdev.httpd.apache.org%3E
- https://lists.apache.org/thread.html/re026d3da9d7824bd93b9f871c0fdda978d960c7e62d8c43cba8d0bf3%40%3Ccvs.httpd.apache.org%3E

### 🔴 CVE-2021-39275 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-09-16  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache HTTP Server 2.4.48 and earlier.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:storagegrid:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:http_server:12.2.1.3.0:*:*:*:*:*:*:*`

**References:**
- https://cert-portal.siemens.com/productcert/pdf/ssa-685781.pdf
- https://httpd.apache.org/security/vulnerabilities_24.html
- https://lists.apache.org/thread.html/r3925e167d5eb1c75def3750c155d753064e1d34a143028bb32910432%40%3Cusers.httpd.apache.org%3E
- https://lists.apache.org/thread.html/r61fdbfc26ab170f4e6492ef3bd5197c20b862ce156e9d5a54d4b899c%40%3Cusers.httpd.apache.org%3E
- https://lists.apache.org/thread.html/r82838efc5fa6fc4c73986399c9b71573589f78b31846aff5bd9b1697%40%3Cusers.httpd.apache.org%3E

### 🔴 CVE-2021-41773 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-10-05  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.1:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.3:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*`

**References:**
- http://packetstormsecurity.com/files/164418/Apache-HTTP-Server-2.4.49-Path-Traversal-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/164418/Apache-HTTP-Server-2.4.49-Path-Traversal.html
- http://packetstormsecurity.com/files/164629/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/164941/Apache-HTTP-Server-2.4.50-Remote-Code-Execution.html
- http://www.openwall.com/lists/oss-security/2021/10/05/2

### 🔴 CVE-2021-44790 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-12-20  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the vulnerabilty though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and earlier.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:tenable:tenable.sc:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:communications_element_manager:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:communications_operations_monitor:4.3:*:*:*:*:*:*:*`

**References:**
- http://httpd.apache.org/security/vulnerabilities_24.html
- http://packetstormsecurity.com/files/171631/Apache-2.4.x-Buffer-Overflow.html
- http://seclists.org/fulldisclosure/2022/May/33
- http://seclists.org/fulldisclosure/2022/May/35
- http://seclists.org/fulldisclosure/2022/May/38

### 🔴 CVE-2022-22720 — CVSS 9.8 (CRITICAL)
- **Published:** 2022-03-14  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP Request Smuggling

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:enterprise_manager_ops_center:12.4.0.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:http_server:12.2.1.3.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:http_server:12.2.1.4.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:zfs_storage_appliance_kit:8.8:*:*:*:*:*:*:*`

**References:**
- http://seclists.org/fulldisclosure/2022/May/33
- http://seclists.org/fulldisclosure/2022/May/35
- http://seclists.org/fulldisclosure/2022/May/38
- http://www.openwall.com/lists/oss-security/2022/03/14/3
- https://httpd.apache.org/security/vulnerabilities_24.html

### 🔴 CVE-2022-23943 — CVSS 9.8 (CRITICAL)
- **Published:** 2022-03-14  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and prior versions.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:http_server:12.2.1.3.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:http_server:12.2.1.4.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:zfs_storage_appliance_kit:8.8:*:*:*:*:*:*:*`
- `cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*`

**References:**
- http://www.openwall.com/lists/oss-security/2022/03/14/1
- https://httpd.apache.org/security/vulnerabilities_24.html
- https://lists.debian.org/debian-lts-announce/2022/03/msg00033.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RGWILBORT67SHMSLYSQZG2NMXGCMPUZO/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/X73C35MMMZGBVPQQCH7LQZUMYZNQA5FO/

### 🔴 CVE-2022-31813 — CVSS 9.8 (CRITICAL)
- **Published:** 2022-06-09  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on client side Connection header hop-by-hop mechanism. This may be used to bypass IP based authentication on the origin server/application.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*`
- `cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*`
- `cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*`

**References:**
- http://www.openwall.com/lists/oss-security/2022/06/08/8
- https://httpd.apache.org/security/vulnerabilities_24.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7QUGG2QZWHTITMABFLVXA4DNYUOTPWYQ/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YPY2BLEVJWFH34AX77ZJPLD2OOBYR6ND/
- https://security.gentoo.org/glsa/202208-20

### 🔴 CVE-2023-25690 — CVSS 9.8 (CRITICAL)
- **Published:** 2023-03-07  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack.




Configurations are affected when mod_proxy is enabled along with some form of RewriteRule
 or ProxyPassMatch in which a non-specific pattern matches
 some portion of the user-supplied request-target (URL) data and is then
 re-inserted into the proxied request-target using variable 
substitution. For example, something like:




RewriteEngine on
RewriteRule "^/here/(.*)" "http://example.com:8080/elsewhere?$1"; [P]
ProxyPassReverse /here/ http://example.com:8080/


Request splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`

**References:**
- http://packetstormsecurity.com/files/176334/Apache-2.4.55-mod_proxy-HTTP-Request-Smuggling.html
- https://httpd.apache.org/security/vulnerabilities_24.html
- https://lists.debian.org/debian-lts-announce/2023/04/msg00028.html
- https://security.gentoo.org/glsa/202309-01
- http://packetstormsecurity.com/files/176334/Apache-2.4.55-mod_proxy-HTTP-Request-Smuggling.html

### 🔴 CVE-2021-42013 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-10-07  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.1:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.3:*:*:*:*:*:*:*`

**References:**
- http://jvn.jp/en/jp/JVN51106450/index.html
- http://packetstormsecurity.com/files/164501/Apache-HTTP-Server-2.4.50-Path-Traversal-Code-Execution.html
- http://packetstormsecurity.com/files/164609/Apache-HTTP-Server-2.4.50-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/164629/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/164941/Apache-HTTP-Server-2.4.50-Remote-Code-Execution.html
