# agents/incident_logger_tool.py
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
import json
from datetime import datetime
import os

# Get the directory where this Python file is located
BASE_DIR = os.path.dirname(__file__)

# Build the path to the JSON file relative to this script
JSON_PATH = os.path.join(BASE_DIR, "data", "incident_data.json")
# -----------------------------
# Input / Output Models
# -----------------------------

class IncidentLoggerInput(BaseModel):
    """Input: list of threats or anomalies to log."""
    events: List[Dict] = Field(..., description="List of threat/anomaly events")

class IncidentLoggerOutput(BaseModel):
    """Output: list of generated incident records."""
    incidents: List[Dict] = Field(
        ..., 
        description="List of incident reports with ID, summary, MITRE mapping, compliance info"
    )

# -----------------------------
# Tool Definition
# -----------------------------

@tool(
    name="log_incident",
    description=(
        "Creates structured incident reports from security events using a knowledge base template. "
        "Maps findings to MITRE ATT&CK and includes compliance metadata."
    ),
    permission=ToolPermission.ADMIN
)
def log_incident(events: List[Dict]) -> Dict:
    """
    Generate incident reports using a dynamic template from the knowledge base.

    Args:
        events: List of dictionaries with keys:
            - source_ip
            - user_id
            - severity
            - mitre_technique
            - reason
            - timestamp

    Returns:
        Dictionary with key 'incidents' containing list of incident records.
    """
    incidents = []
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # 🔥 Load template from knowledge base (via WatsonX Orchestrate)
    try:
        # In real deployment, this would be accessed via `context.knowledge_base`
        # But for local testing, we load manually
        with open(JSON_PATH, "r") as f:
            kb_data = json.load(f)
        template = kb_data["template"]
    except Exception as e:
        return {"incidents": [], "error": f"Failed to load template: {str(e)}"}

    for i, event in enumerate(events):
        ip = event.get("source_ip", "unknown")
        user = event.get("user_id", "unknown")
        severity = event.get("severity", "low").lower()
        mitre = event.get("mitre_technique", "")
        reason = event.get("reason", "")

        # Auto-generate incident ID
        year = now[:4]
        month = now[5:7]
        day = now[8:10]
        incident_id = f"INC-{year}-{month}{day}-{i+1:03d}"

        # Use template variables
        summary = template["summary"].format(user_id=user, country="France" if "France" in reason else "unknown")
        impact = template["impact"]

        # Compliance based on MITRE
        compliance = []
        if "T1078" in mitre:
            compliance.extend(["GDPR Article 33", "NIST SP 800-61 Rev. 2"])
        if "T1110" in mitre:
            compliance.append("ISO 27001 A.16.1.5")

        # Create incident
        incident = {
            "incident_id": incident_id,
            "timestamp": now,
            "source_ip": ip,
            "user_id": user,
            "severity": severity.upper(),
            "mitre_technique": mitre,
            "description": reason,
            "summary": summary,
            "impact": impact,
            "compliance": compliance,
            "status": "open",
            "assigned_to": "SOC Team"
        }

        incidents.append(incident)

    return {"incidents": incidents}