# test_incident_logger.py
from ibm_watsonx_orchestrate.agent_builder import AgentBuilder
from dotenv import load_dotenv

load_dotenv()

# Load the agent
agent = AgentBuilder.from_yaml("cyber_agents/incident_logger_agent.yaml")

# Simulate input from threat_response_agent
input_data = {
    "events": [
        {
            "is_threat": True,
            "confidence": 0.92,
            "source_ip": "103.245.12.33",
            "user_id": "john.doe",
            "reason": "Login from unusual country: France (Paris)",
            "severity": "high",
            "mitre_technique": "T1078 - Validated account"
        }
    ]
}

# Run inference
result = agent.run(prompt="Log these events", inputs=input_data)

print("✅ Generated Incidents:")
for inc in result["incidents"]:
    print(f"- {inc['incident_id']}: {inc['summary']} → {inc['impact']}")