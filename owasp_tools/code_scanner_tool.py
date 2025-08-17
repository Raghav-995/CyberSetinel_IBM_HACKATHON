# agents/owasp_code_scanner_tool.py
from typing import List, Dict, Optional
from pydantic import BaseModel, Field, validator
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
import re
import os
import json
import requests
import logging
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityFinding(BaseModel):
    issue: str = Field(..., description="Short description of the vulnerability")
    owasp: str = Field(..., description="OWASP category (e.g., A03:2021 Injection)")
    severity: Severity = Field(..., description="Severity level")
    line: int = Field(default=0, description="Line number where issue was found")
    snippet: str = Field(default="", description="Code snippet showing the issue")
    recommendation: str = Field(..., description="How to fix the vulnerability")

class ScanResult(BaseModel):
    findings: List[VulnerabilityFinding] = Field(default_factory=list)

    @validator('findings', pre=True)
    def validate_findings(cls, v):
        if isinstance(v, dict):
            return [VulnerabilityFinding(**v)]
        return v

class SecurityHeader(str, Enum):
    X_FRAME_OPTIONS = "X-Frame-Options"
    X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options"
    STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security"
    CONTENT_SECURITY_POLICY = "Content-Security-Policy"

class CodePattern(BaseModel):
    pattern: str
    issue_type: str
    owasp_category: str
    severity: Severity
    recommendation: str

class CodeAnalyzer:
    def __init__(self):
        self.patterns = [
            CodePattern(
                pattern=r"(os\.system|subprocess\.(call|run|Popen))",
                issue_type="Command Injection via subprocess.exec",
                owasp_category="A03:2021 Injection",
                severity=Severity.CRITICAL,
                recommendation="Use subprocess.run(args=[...]) with args list; never concatenate shell commands."
            ),
            CodePattern(
                pattern=r"(SELECT|INSERT|UPDATE|DELETE).*\+.*",
                issue_type="SQL Injection via string concatenation",
                owasp_category="A03:2021 Injection",
                severity=Severity.HIGH,
                recommendation="Use parameterized queries/prepared statements."
            ),
            # Add more patterns as needed
        ]

    def scan_code(self, code: str, language: str) -> ScanResult:
        result = ScanResult()
        lines = code.splitlines()
        
        for i, line in enumerate(lines, 1):
            for pattern in self.patterns:
                if re.search(pattern.pattern, line, re.IGNORECASE):
                    result.findings.append(
                        VulnerabilityFinding(
                            issue=pattern.issue_type,
                            owasp=pattern.owasp_category,
                            severity=pattern.severity,
                            line=i,
                            snippet=line[:180],
                            recommendation=pattern.recommendation
                        )
                    )
        return result

@tool(
    name="scan_code_owasp",
    description="Scans source code for OWASP Top 10 vulnerabilities using static analysis and AI",
    permission=ToolPermission.ADMIN
)
def scan_code_owasp(
    language: str,
    code: str,
    framework: Optional[str] = None
) -> List[Dict]:
    """
    Enhanced code scanner with better validation and error handling
    
    Args:
        language: Programming language (python, javascript, java, etc.)
        code: Source code to analyze
        framework: Optional framework (express, flask, django, etc.)
    
    Returns:
        List of vulnerability findings as dictionaries
    """
    try:
        # Validate inputs
        if not code or len(code) > 100000:
            return [{
                "issue": "Invalid input",
                "owasp": "N/A",
                "severity": Severity.INFO.value,
                "line": 0,
                "snippet": "",
                "recommendation": "Provide valid code (<100KB)"
            }]

        # Static analysis
        analyzer = CodeAnalyzer()
        result = analyzer.scan_code(code, language)
        
        # AI analysis if available
        try:
            ai_result = analyze_with_watsonx(code, language)
            if ai_result and ai_result.findings:
                result.findings.extend(ai_result.findings)
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            result.findings.append(
                VulnerabilityFinding(
                    issue="AI analysis failed",
                    owasp="N/A",
                    severity=Severity.INFO,
                    line=0,
                    snippet="",
                    recommendation=f"Error: {str(e)}"
                )
            )

        # Return as list of dicts ✅
        return [f.dict() for f in result.findings]
    
    except Exception as e:
        logger.error(f"Code scan failed: {str(e)}")
        return [{
            "issue": "Scan failed",
            "owasp": "N/A",
            "severity": Severity.INFO.value,
            "line": 0,
            "snippet": "",
            "recommendation": f"Error: {str(e)}"
        }]

@tool(
    name="scan_url_owasp",
    description="Scans a URL for common web vulnerabilities",
    permission=ToolPermission.ADMIN
)
def scan_url_owasp(url: str) -> List[Dict]:
    """
    Enhanced URL scanner with better validation and security checks
    
    Args:
        url: Target URL to scan
    
    Returns:
        List of vulnerability findings as dictionaries
    """
    result = ScanResult()
    
    try:
        # Fix URL
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        # Security headers check
        response = requests.get(url, timeout=10, allow_redirects=False)
        headers = response.headers
        
        header_checks = {
            SecurityHeader.X_FRAME_OPTIONS: "A05:2021 Security Misconfiguration",
            SecurityHeader.X_CONTENT_TYPE_OPTIONS: "A05:2021 Security Misconfiguration",
            SecurityHeader.STRICT_TRANSPORT_SECURITY: "A02:2021 Cryptographic Failures",
            SecurityHeader.CONTENT_SECURITY_POLICY: "A07:2021 XSS"
        }
        
        for header, owasp_cat in header_checks.items():
            if header.value not in headers:
                result.findings.append(
                    VulnerabilityFinding(
                        issue=f"Missing {header.value} header",
                        owasp=owasp_cat,
                        severity=Severity.MEDIUM,
                        line=0,
                        snippet=f"URL: {url}",
                        recommendation=f"Add {header.value} security header"
                    )
                )
        
        # Content checks
        content = response.text.lower()
        if "error" in content and "sql" in content:
            result.findings.append(
                VulnerabilityFinding(
                    issue="Possible SQL error disclosure",
                    owasp="A03:2021 Injection",
                    severity=Severity.HIGH,
                    line=0,
                    snippet=url,
                    recommendation="Implement proper error handling"
                )
            )
            
    except requests.exceptions.RequestException as e:
        logger.error(f"URL scan failed: {str(e)}")
        result.findings.append(
            VulnerabilityFinding(
                issue="URL scan failed",
                owasp="N/A",
                severity=Severity.INFO,
                line=0,
                snippet=url,
                recommendation=f"Error: {str(e)}"
            )
        )
    
    return [f.dict() for f in result.findings]

def analyze_with_watsonx(code: str, language: str) -> ScanResult:
    """Enhanced AI analysis using watsonx.ai with better error handling"""
    result = ScanResult()
    
    try:
        from ibm_watsonx_ai.foundation_models import Model
        
        api_key = os.getenv("WATSONX_APIKEY")
        project_id = os.getenv("WATSONX_PROJECT_ID")
        
        if not api_key or not project_id:
            raise ValueError("WatsonX credentials not configured")
            
        model = Model(
            model_id="ibm/granite-13b-instruct-v2",
            params={"max_new_tokens": 512, "temperature": 0.1},
            credentials={"apikey": api_key, "url": "https://us-south.ml.cloud.ibm.com"},
            project_id=project_id
        )
        
        prompt = f"""Analyze this {language} code for OWASP Top 10 (2021) vulnerabilities.
Return ONLY a JSON array of objects with:
- "issue": short description
- "owasp": OWASP ID like "A03:2021 Injection"
- "severity": "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
- "line": line number (0 if unknown)
- "snippet": up to 180 chars around the issue
- "recommendation": actionable fix

Only return the JSON array. No extra text.

Code:
{code[:8000]}"""

        response = model.generate_text(prompt=prompt)
        generated_text = response["results"][0]["generated_text"].strip()

        # Extract JSON from markdown block
        match = re.search(r"```json\s*(\[.*\])\s*```", generated_text, re.DOTALL)
        if match:
            findings = json.loads(match.group(1))
        else:
            try:
                findings = json.loads(generated_text)
            except:
                findings = []

        # Parse into VulnerabilityFinding
        for item in findings:
            try:
                # Ensure required fields exist
                issue = item.get("issue", "")
                owasp = item.get("owasp", "")
                severity = item.get("severity", "MEDIUM")
                line = item.get("line", 0)
                snippet = item.get("snippet", "")[:180]
                rec = item.get("recommendation", "")

                result.findings.append(
                    VulnerabilityFinding(
                        issue=issue,
                        owasp=owasp,
                        severity=severity,
                        line=line,
                        snippet=snippet,
                        recommendation=rec
                    )
                )
            except Exception as e:
                logger.warning(f"Invalid finding format: {str(e)}")
                
    except Exception as e:
        logger.error(f"AI analysis error: {str(e)}")
    
    return result