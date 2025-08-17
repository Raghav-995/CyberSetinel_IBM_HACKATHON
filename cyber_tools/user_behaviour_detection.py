from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
from ibm_watsonx_ai.foundation_models import Model
from ibm_watsonx_ai import Credentials
import pandas as pd
import json
import os

# Get the directory where this Python file is located
BASE_DIR = os.path.dirname(__file__)

# Build the path to the JSON file relative to this script
JSON_PATH = os.path.join(BASE_DIR, "data", "geolocations.json")

@tool(
    name='analyze_user_behavior',
    description="Detects anomalous user behavior such as logins from unusual locations, multiple devices, or failed attempts. Uses rule-based logic and LLM reasoning to map findings to MITRE ATT&CK techniques.",
    permission=ToolPermission.ADMIN,
)
def analyze_user_behavior(logs: list[dict]) -> dict:
    """Analyzes user login behavior to detect potential account compromise."""

    df = pd.DataFrame(logs)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    anomalies = []

    # Load geo data
    try:
        with open(JSON_PATH, "r") as f:
            geo_data = json.load(f)
        trusted_countries = set(geo_data.get("trusted_locations", []))
        unusual_countries = set(geo_data.get("unusual_countries", []))
    except Exception as e:
        return {"anomalies": [], "error": f"Failed to load geo data: {str(e)}"}

    # Group by user for analysis
    grouped = df.groupby('user_id')

    for user, group in grouped:
        group = group.sort_values('timestamp')

        # 1. Check for login from unusual country
        recent_logins = group[group['country'].isin(unusual_countries)]
        if not recent_logins.empty:
            reason = f"Login from unusual country: {recent_logins.iloc[0]['country']} ({recent_logins.iloc[0]['location']})"
            anomalies.append({
                "user_id": user,
                "reason": reason,
                "severity": "high",
                "mitre_technique": "T1078 - Validated account"
            })

        # 2. Check for login from multiple countries (any change)
        if group['country'].nunique() > 1:
            reason = f"User logged in from multiple countries: {', '.join(group['country'].unique())}"
            anomalies.append({
                "user_id": user,
                "reason": reason,
                "severity": "high",
                "mitre_technique": "T1078 - Validated account"
            })

        # 3. Check for multiple devices (>= 2 instead of > 2)
        devices = group['device'].unique()
        if len(devices) >= 2:
            reason = f"Multiple devices used: {', '.join(devices)}"
            anomalies.append({
                "user_id": user,
                "reason": reason,
                "severity": "medium",
                "mitre_technique": "T1078 - Validated account"
            })

        # 4. Detect failed login immediately followed by success
        for i in range(len(group) - 1):
            if (group.iloc[i]['action'].lower() == 'failure' and
                group.iloc[i+1]['action'].lower() == 'success'):
                reason = "Failed login immediately followed by a success"
                anomalies.append({
                    "user_id": user,
                    "reason": reason,
                    "severity": "high",
                    "mitre_technique": "T1110 - Brute Force"
                })

    # MITRE ATT&CK mapping using IBM watsonx.ai
    enriched_anomalies = []
    if anomalies:
        try:
            credentials = Credentials(
                url="https://us-south.ml.cloud.ibm.com",
                 api_key = os.getenv("WATSONX_APIKEY")
        
                # api_key="iRinh96p0t_GzfXzPctMuw-6icwdpCBRT09qBgj"  # Replace with actual API key
            )
            
            model = Model(
                model_id="ibm/granite-3-2-8b-instruct",
                credentials=credentials,
                # project_id="64237db3-f24a-4b56-be15023101a69"  # Replace with actual project ID
                project_id = os.getenv("WATSONX_PROJECT_ID")
            )
            
            for anomaly in anomalies:
                prompt = f"""Analyze this user behavior anomaly:
- User: {anomaly['user_id']}
- Reason: {anomaly['reason']}
- Severity: {anomaly['severity']}

Map this to a MITRE ATT&CK technique. Respond with:
1. MITRE Technique ID (e.g., T1078)
2. Brief explanation (1 sentence)"""

                response = model.generate_text(
                    prompt=prompt,
                    params={"max_new_tokens": 100}
                )
                anomaly["mitre_technique"] = response.strip()
                enriched_anomalies.append(anomaly)
                
        except Exception as e:
            for anomaly in anomalies:
                anomaly["mitre_technique"] = f"MITRE mapping failed: {str(e)}"
                enriched_anomalies.append(anomaly)

    return {"anomalies": enriched_anomalies}

# from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
# from ibm_watsonx_ai.foundation_models import Model
# from ibm_watsonx_ai import Credentials
# import pandas as pd
# import json
# import os

# # Get the directory where this Python file is located
# BASE_DIR = os.path.dirname(__file__)

# # Build the path to the JSON file relative to this script
# JSON_PATH = os.path.join(BASE_DIR, "data", "geolocations.json")

# @tool(
#     name='analyze_user_behavior',
#     description="Detects anomalous user behavior such as logins from unusual locations, multiple devices, or failed attempts. Uses rule-based logic and LLM reasoning to map findings to MITRE ATT&CK techniques.",
#     permission=ToolPermission.ADMIN,
# )
# def analyze_user_behavior(logs: list[dict]) -> dict:
#     """Analyzes user login behavior to detect potential account compromise.

#     Args:
#         logs (list[dict]): A list of dictionaries representing login events.
#             Each dictionary should contain:
#                 - timestamp: Time of the event (str or datetime)
#                 - user_id: User identifier (str)
#                 - source_ip: Source IP address (str)
#                 - device: Device used (str)
#                 - location: Physical location (str)
#                 - country: Country code (str)
#                 - action: Action taken ('success' or 'failure') (str)

#     Returns:
#         dict: A dictionary with a single key 'anomalies' containing:
#             A list of dictionaries, each representing a detected anomaly with:
#                 - user_id: The affected user (str)
#                 - reason: Description of the anomaly (str)
#                 - severity: Anomaly severity ('low', 'medium', 'high') (str)
#                 - mitre_technique: MITRE ATT&CK technique ID and explanation (str)
#     """
#     df = pd.DataFrame(logs)
#     df['timestamp'] = pd.to_datetime(df['timestamp'])
#     anomalies = []

#     # Load unusual countries from geo data
#     try:
#         with open(JSON_PATH, "r") as f:
#             geo_data = json.load(f)
#         trusted_countries = set(geo_data["trusted_locations"])
#         unusual_countries = set(geo_data["unusual_countries"])
#     except Exception as e:
#         return {"anomalies": [], "error": f"Failed to load geo data: {str(e)}"}

#     # Group by user for analysis
#     grouped = df.groupby('user_id')

#     for user, group in grouped:
#         # Check for login from unusual country
#         recent_logins = group[group['country'].isin(unusual_countries)]
#         if not recent_logins.empty:
#             reason = f"Login from unusual country: {recent_logins.iloc[0]['country']} ({recent_logins.iloc[0]['location']})"
#             anomalies.append({
#                 "user_id": user,
#                 "reason": reason,
#                 "severity": "high",
#                 "mitre_technique": "T1078 - Validated account"
#             })

#         # Check for multiple devices
#         devices = group['device'].unique()
#         if len(devices) > 2:
#             reason = f"Multiple devices used: {', '.join(devices)}"
#             anomalies.append({
#                 "user_id": user,
#                 "reason": reason,
#                 "severity": "medium",
#                 "mitre_technique": "T1078 - Validated account"
#             })

#         # Check for failed attempts after success
#         success = group[group['action'].str.lower() == 'success']
#         failure = group[group['action'].str.lower() == 'failure']
#         if not success.empty and not failure.empty:
#             last_success = success.iloc[-1]['timestamp']
#             first_failure = failure.iloc[0]['timestamp']
#             if first_failure > last_success:
#                 reason = "Failed login attempt after successful login"
#                 anomalies.append({
#                     "user_id": user,
#                     "reason": reason,
#                     "severity": "high",
#                     "mitre_technique": "T1078 - Validated account"
#                 })

#     # MITRE ATT&CK mapping using IBM watsonx.ai
#     enriched_anomalies = []
#     if anomalies:
#         try:
#             credentials = Credentials(
#                 url="https://us-south.ml.cloud.ibm.com",
#                 api_key="iRinh96p0t_GzO2sf1fXzPctMuw-6icwdpCBRT09qBgj"  # Replace with actual API key
#             )
            
#             model = Model(
#                 model_id="ibm/granite-3-2-8b-instruct",
#                 credentials=credentials,
#                 project_id="64237db3-f24a-4b56-be30-c15023101a69"  # Replace with actual project ID
#             )
            
#             for anomaly in anomalies:
#                 prompt = f"""Analyze this user behavior anomaly:
# - User: {anomaly['user_id']}
# - Reason: {anomaly['reason']}
# - Severity: {anomaly['severity']}

# Map this to a MITRE ATT&CK technique. Respond with:
# 1. MITRE Technique ID (e.g., T1078)
# 2. Brief explanation (1 sentence)"""

#                 response = model.generate_text(
#                     prompt=prompt,
#                     params={"max_new_tokens": 100}
#                 )
#                 anomaly["mitre_technique"] = response.strip()
#                 enriched_anomalies.append(anomaly)
                
#         except Exception as e:
#             for anomaly in anomalies:
#                 anomaly["mitre_technique"] = f"MITRE mapping failed: {str(e)}"
#                 enriched_anomalies.append(anomaly)

#     return {"anomalies": enriched_anomalies}