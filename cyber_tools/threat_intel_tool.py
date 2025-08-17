# agents/threat_intel_tool.py
from typing import List, Dict, Optional
from pydantic import BaseModel, Field
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
import json
import os

# Get the directory where this Python file is located
BASE_DIR = os.path.dirname(__file__)

# Build the path to the JSON file relative to this script
JSON_PATH = os.path.join(BASE_DIR, "data", "mitre_attack_kb.json")
# -----------------------------
# Input / Output Models
# -----------------------------

class ThreatIntelInput(BaseModel):
    """Input: list of detected threats."""
    threats: List[Dict] = Field(..., description="List of threat detections with mitre_technique")

class ThreatIntelOutput(BaseModel):
    """Output: enriched threat intelligence with context."""
    intel: List[Dict] = Field(
        ..., 
        description="List of MITRE ATT&CK mappings with tactic, description, and mitigation"
    )

# -----------------------------
# Tool Definition
# -----------------------------

@tool(
    name="get_threat_intel",
    description=(
        "Provides MITRE ATT&CK context for detected threats. "
        "Maps findings to techniques, tactics, and mitigation strategies."
    ),
    permission=ToolPermission.ADMIN
)
def get_threat_intel(threats: List[Dict]) -> Dict:
    """
    Enrich threat detections with MITRE ATT&CK context.

    Args:
        threats: List of dictionaries with keys:
            - mitre_technique (e.g., "T1078 - Validated account")
            - reason
            - severity

    Returns:
        Dictionary with key 'intel' containing detailed intelligence.
    """
    intel_data = []

    try:
        # Load knowledge base
        with open(JSON_PATH, "r") as f:
            kb_data = json.load(f)
        techniques = kb_data["techniques"]
    except Exception as e:
        return {"intel": [], "error": f"Failed to load KB: {str(e)}"}

    for threat in threats:
        mitre_id = threat.get("mitre_technique", "").split(" - ")[0]
        match = next((t for t in techniques if t["id"] == mitre_id), None)

        if match:
            intel_entry = {
                "mitre_id": match["id"],
                "name": match["name"],
                "tactic": match["tactic"],
                "description": match["description"],
                "mitigation": match["mitigation"],
                "threat_reason": threat.get("reason", ""),
                "severity": threat.get("severity", "unknown")
            }
            intel_data.append(intel_entry)
        else:
            intel_data.append({
                "mitre_id": mitre_id,
                "name": "Unknown",
                "tactic": "Unknown",
                "description": "No MITRE ATT&CK mapping found.",
                "mitigation": "Check logs and escalate to SOC team.",
                "threat_reason": threat.get("reason", ""),
                "severity": threat.get("severity", "unknown")
            })

    return {"intel": intel_data}