# agents/response_automation_tool.py

from typing import List, Dict
from pydantic import BaseModel, Field
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission

# -----------------------------
# Input / Output Models
# -----------------------------

class ResponseAutomationInput(BaseModel):
    """Input: list of detected threats with severity and MITRE technique."""
    threats: List[Dict] = Field(..., description="List of threat detections from detect_threats")

class ResponseAutomationOutput(BaseModel):
    """Output: list of automated actions to take."""
    actions: List[Dict] = Field(
        ...,
        description="List of actions to execute: block_ip, quarantine_device, apply_patch, alert_security_team"
    )

# -----------------------------
# Tool Definition
# -----------------------------

@tool(
    name="automate_response",
    description=(
        "Automatically responds to security threats based on severity and MITRE ATT&CK technique. "
        "Generates actions like blocking IPs, quarantining devices, or triggering patches."
    ),
    permission=ToolPermission.ADMIN
)
def automate_response(threats: List[Dict]) -> Dict:
    """
    Generate automated responses for detected threats.

    Args:
        threats: List of threat dictionaries with keys:
            - source_ip
            - severity (high/medium/low)
            - mitre_technique
            - reason

    Returns:
        Dictionary with key 'actions' containing list of response actions.
    """
    actions = []

    for threat in threats:
        ip = threat.get("source_ip")
        severity = threat.get("severity", "low").lower()
        mitre = threat.get("mitre_technique", "").upper()

        # Decision Logic
        if severity == "critical" or severity == "high":
            if "T1110" in mitre or "T1078" in mitre:
                actions.append({
                    "action": "block_ip",
                    "target": ip,
                    "reason": f"High-severity brute-force or account compromise attempt ({mitre})",
                    "priority": "urgent"
                })
            if "T1059" in mitre or "T1195" in mitre:
                actions.append({
                    "action": "quarantine_device",
                    "target": ip,
                    "reason": f"Execution of malicious code detected ({mitre})",
                    "priority": "urgent"
                })

        elif severity == "medium":
            if "T1078" in mitre:
                actions.append({
                    "action": "alert_security_team",
                    "target": ip,
                    "reason": f"Medium-severity account anomaly ({mitre})",
                    "priority": "high"
                })

        else:
            actions.append({
                "action": "log_only",
                "target": ip,
                "reason": f"Low-severity event: {threat.get('reason', 'unknown')}",
                "priority": "low"
            })

    return {"actions": actions}

# Export the tool function
__all__ = ["automate_response"]