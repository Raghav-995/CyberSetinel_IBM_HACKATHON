# agents/owasp_reporter_tool.py
from typing import List, Dict
from pydantic import BaseModel, Field
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission

class ReportInput(BaseModel):
    code_findings: List[Dict] = Field(default_factory=list)
    url_findings: List[Dict] = Field(default_factory=list)

class ReportOutput(BaseModel):
    summary: Dict = Field(...)

@tool(
    name="make_owasp_report",
    description="Consolidates findings, dedupes by OWASP category, assigns risk & gives remediation plan.",
    permission=ToolPermission.ADMIN
)
def make_owasp_report(code_findings: List[Dict] = None, url_findings: List[Dict] = None) -> Dict:
    code_findings = code_findings or []
    url_findings = url_findings or []
    all_f = code_findings + url_findings

    # simple risk score: HIGH=3, MED=2, LOW=1
    score_map = {"HIGH":3, "MEDIUM":2, "LOW":1}
    by_cat = {}
    total = 0
    for f in all_f:
        cat = f.get("owasp","Unknown")
        by_cat.setdefault(cat, {"items":[], "risk":0})
        by_cat[cat]["items"].append(f)
        by_cat[cat]["risk"] += score_map.get(f.get("severity","LOW"),1)
        total += score_map.get(f.get("severity","LOW"),1)

    prioritized = sorted(
        [{"owasp":k,"risk":v["risk"],"count":len(v["items"]), "items":v["items"]} for k,v in by_cat.items()],
        key=lambda x: x["risk"], reverse=True
    )

    summary = {
        "risk_score": total,
        "categories": prioritized,
        "quick_actions": [
            "Enable CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS",
            "Enforce parameterized queries across all data stores",
            "Centralize input validation with a schema library",
            "Rotate any found secrets and move to a secret manager",
            "Add SSRF egress protections / URL allowlist"
        ]
    }
    return {"summary": summary}
