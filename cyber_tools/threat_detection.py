from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
from ibm_watsonx_ai.foundation_models import Model
from ibm_watsonx_ai import Credentials
import pandas as pd
from ibm_watsonx_ai import APIClient
import os

@tool(
    name='detect_threats',
    description="Detect anomalies in network logs such as brute-force attacks or off-hours logins. Uses rule-based logic and LLM reasoning to map findings to MITRE ATT&CK techniques.",
    permission=ToolPermission.ADMIN,
)
def detect_threats(logs: list[dict]) -> dict:
    """Detects security threats from network logs and maps them to MITRE ATT&CK techniques.

    Args:
        logs (list[dict]): A list of dictionaries representing log events.
            Each dictionary should contain:
                - timestamp: Time of the event (str or datetime)
                - source_ip: Source IP address (str)
                - action: Action taken (e.g., 'success', 'failure') (str)
                - bytes_transferred: Number of bytes transferred (int, optional)
                - user_agent: User agent string (str, optional)

    Returns:
        dict: A dictionary with a single key 'threats' containing:
            A list of dictionaries, each representing a detected threat with:
                - is_threat: Boolean indicating if this is a threat (bool)
                - confidence: Confidence score (0.0-1.0) (float)
                - source_ip: Source IP address (str)
                - reason: Description of the threat (str)
                - severity: Threat severity ('low', 'medium', 'high') (str)
                - mitre_technique: MITRE ATT&CK technique ID and explanation (str)
    """
    df = pd.DataFrame(logs)
    results = []
    
    # Ensure timestamp column is in datetime format
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    grouped = df.groupby('source_ip')

    for ip, group in grouped:
        # Brute-force detection
        failures = group[group['action'].str.lower() == 'failure']
        if len(failures) >= 4:
            first_fail = failures.iloc[0]['timestamp']
            last_fail = failures.iloc[-1]['timestamp']
            duration = last_fail - first_fail
            if duration.total_seconds() <= 300:
                reason = f"Brute-force attack detected: {len(failures)} failed logins from {ip} in {duration.total_seconds()} seconds."
                results.append({
                    "is_threat": True,
                    "confidence": 0.92,
                    "source_ip": ip,
                    "reason": reason,
                    "severity": "high"
                })

        # Off-hours login check (adjusting for potential case sensitivity)
        successes = group[group['action'].str.lower() == 'success']
        recent_logins = successes[
            successes['timestamp'].dt.hour.isin([3, 4, 5])
        ]
        if not recent_logins.empty:
            reason = f"Login during off-hours (3AM-5AM) from {ip}."
            results.append({
                "is_threat": True,
                "confidence": 0.78,
                "source_ip": ip,
                "reason": reason,
                "severity": "medium"
            })

    # LLM Analysis for MITRE mapping
    try:
        # Read credentials directly from environment variables
        # api_key = "iRinh96p0t_GzO2sf1fXzPctMuwCBRT09qBgj"
        # project_id = "64237db3-f24a-4b56-be31a69"
        api_key = os.getenv("WATSONX_APIKEY")
        project_id = os.getenv("WATSONX_PROJECT_ID")
        
        if not api_key or not project_id:
            raise ValueError("WATSONX_API_KEY and WATSONX_PROJECT_ID must be set as environment variables.")
                # Correct way to instantiate APIClient
        credentials = Credentials(
            url="https://us-south.ml.cloud.ibm.com",
            api_key=api_key
        )
        # client = APIClient(credentials=credentials, project_id=project_id)
    except Exception as e:
        return {"threats": [], "error": f"Failed to initialize AI client. Details: {str(e)}"}

    enriched_results = []
    for event in results:
        prompt = f"""
        Analyze this security event and map it to a MITRE ATT&CK technique.
        - Event Reason: {event['reason']}
        - Source IP: {event['source_ip']}

        Based on the MITRE ATT&CK framework, which technique does this most closely represent?
        Respond only with the MITRE ATT&CK ID (e.g., T1078) and a short explanation in a single sentence.
        """
        
        try:
# Initialize the model
            model = Model(
                model_id="ibm/granite-3-2-8b-instruct",
                credentials=credentials,
                project_id=project_id
            )
            # Generate text
            response = model.generate_text(
                prompt=prompt,
                params={"max_new_tokens": 100}
            )
            mitre_analysis = response
        except Exception as e:
            mitre_analysis = f"LLM mapping failed: {str(e)}"

        event["mitre_technique"] = mitre_analysis.strip()
        enriched_results.append(event)

    return {"threats": enriched_results}