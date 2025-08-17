# agents/owasp_url_scanner_tool.py
from typing import Dict
from pydantic import BaseModel, Field
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
import requests
from urllib.parse import urlparse, urlencode

class UrlScanInput(BaseModel):
    url: str = Field(..., description="URL to test (https preferred)")

class UrlScanOutput(BaseModel):
    report: Dict = Field(..., description="Headers, quick tests, and findings")

SEC_HEADERS = [
    "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Strict-Transport-Security", "Permissions-Policy"
]

@tool(
    name="scan_url_owasp",
    description="Fetches a URL and evaluates common OWASP Top 10 signals: headers, cookies, simple XSS/open-redirect probes.",
    permission=ToolPermission.ADMIN
)
def scan_url_owasp(url: str) -> Dict:
    findings = []
    headers = {}
    cookies = []
    status = None

    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        status = r.status_code
        headers = dict(r.headers)
        cookies = [c.name + ("; HttpOnly" if c.has_nonstandard_attr("HttpOnly") else "")
                   for c in r.cookies]
    except Exception as e:
        return {"report": {"error": f"fetch failed: {e}"}}

    # HTTPS check
    if urlparse(url).scheme != "https":
        findings.append({"issue":"No HTTPS","owasp":"A02: Cryptographic Failures","severity":"HIGH",
                         "recommendation":"Serve over HTTPS with HSTS."})

    # Security headers
    for h in SEC_HEADERS:
        if h not in headers:
            findings.append({"issue": f"Missing header: {h}",
                             "owasp": "A05: Security Misconfiguration",
                             "severity": "MEDIUM",
                             "recommendation": f"Add {h} with a sane baseline."})

    # Cookie flags
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        if "HttpOnly" not in set_cookie:
            findings.append({"issue":"Cookies without HttpOnly","owasp":"A07: Identification & Auth Failures",
                             "severity":"MEDIUM","recommendation":"Add HttpOnly to session cookies."})
        if "Secure" not in set_cookie and url.startswith("https"):
            findings.append({"issue":"Cookies without Secure","owasp":"A02: Cryptographic Failures",
                             "severity":"MEDIUM","recommendation":"Add Secure to cookies over HTTPS."})

    # Simple reflected-XSS probe (harmless payload)
    try:
        probe = {"q": "<xss_test_123>"}
        test_url = url
        glue = "&" if "?" in url else "?"
        test_url = f"{url}{glue}{urlencode(probe)}"
        t = requests.get(test_url, timeout=10)
        if "<xss_test_123>" in t.text:
            findings.append({"issue":"Potential reflected XSS",
                             "owasp":"A07: XSS","severity":"HIGH",
                             "recommendation":"Encode/escape reflected params; set CSP; validate inputs."})
    except Exception:
        pass

    # Open redirect hint
    try:
        for p in ["next","redirect","url","return"]:
            glue = "&" if "?" in url else "?"
            rd = f"{url}{glue}{p}=https://example.com"
            resp = requests.get(rd, timeout=10, allow_redirects=False)
            if 300 <= resp.status_code < 400 and "Location" in resp.headers and "example.com" in resp.headers["Location"]:
                findings.append({"issue":"Open Redirect via parameter",
                                 "owasp":"A01: Broken Access Control","severity":"MEDIUM",
                                 "recommendation":"Validate/allowlist redirect targets or use relative paths."})
                break
    except Exception:
        pass

    # Verbose server banner
    server = headers.get("Server","")
    if server and any(x in server.lower() for x in ["apache/","nginx/","iis/","express"]):
        findings.append({"issue":"Verbose Server banner","owasp":"A05: Security Misconfiguration","severity":"LOW",
                         "recommendation":"Remove/obfuscate version banners to reduce fingerprinting."})

    report = {
        "status": status,
        "headers": headers,
        "cookies": cookies,
        "findings": findings
    }
    return {"report": report}
