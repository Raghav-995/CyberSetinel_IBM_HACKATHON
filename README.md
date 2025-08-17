# Cyber Agents with IBM watsonx Orchestrate
This project provides a collection of cyber agents for vulnerability and security analysis using the IBM watsonx Orchestrate platform. This README will guide you through the setup, including installing dependencies, configuring the environment, and running the agents locally.

# Prerequisites
Before you begin, ensure you have the following installed on your system:

Python: Version 3.11 or later.

uv: A fast Python package manager and build tool. You can install it with pip install uv.

Docker: Required to run the local Orchestrate server.

You also need the following credentials from your IBM watsonx account:

WATSONX_API_KEY

WATSONX_PROJECT_ID

WATSONX_URL

## Getting Started
Follow these steps to set up and run the agents on your local machine.

#### Step 1: Clone the Repository
Clone this repository to your local machine using the following command:

```sh
git clone https://github.com/your-username/your-repo-name.git
```

```sh
cd your-repo-name
```

#### Step 2: Set Up the Environment
Create a virtual environment and activate it using uv.

```sh
uv venv
```
```sh
source .venv/bin/activate
```

Install the required Python packages, including ibm-watsonx-orchestrate, ibm-watson-ai, and pandas.

```sh
uv pip install ibm-watsonx-orchestrate ibm-watson-ai pandas
```

#### Step 3: Configure Environment Variables
Create a file named .env in the root directory of your project and add your IBM watsonx credentials.

.env file example:

WATSONX_API_KEY="your_api_key"
WATSONX_PROJECT_ID="your_project_id"
WATSONX_URL="your_url"

⚠️ Important: The .env file should not be committed to Git as it contains sensitive information. It is already included in the .gitignore file for this project.

#### Step 4: Start the Orchestrate Server
Start the local Orchestrate server, which acts as a bridge to the IBM services and provides the development environment.

```sh
uv run orchestrate server start --env-file .env
```

#### Step 5: Activate the Local Environment
Check if the local environment is available and then activate it.

List all available environments:

```sh
uv run orchestrate env list
```

If local is in the list, activate it:

```sh
uv run orchestrate env activate local
```

#### Step 6: Import Tools
The agents require specific tools to function. Import the tool files from the cyber_tools and owasp_tools folders.

```sh
uv run orchestrate tools import -f cyber_tools/file_name.py -r cyber_tools/requirements.py
```
```sh
uv run orchestrate tools import -f owasp_tools/file_name.py -r owasp_tools/requirements.py
```

(Replace file_name.py and requirements.py with the actual file names in the folders).

#### Step 7: Import Knowledge Bases
Import the knowledge base file for the cyber agents.

```sh
uv run orchestrate knowledge-bases import -f cyber-agent/knowledge_bases.py
```

You can verify that the knowledge bases were imported correctly by listing them:

```sh
uv run orchestrate knowledge-bases list
```

#### Step 8: Import Agents
Finally, import all the agents from the cyber_agents folder.

```sh
uv run orchestrate agents import -f cyber_agents/file_name.yaml
```

(Replace file_name.yaml with the actual file names in the folder).

#### Step 9: Test the Agents
Once everything is set up, start the local chat interface to test your agents.

```sh
uv run orchestrate chat start
```

Open your web browser and navigate to http://localhost:3000/chat-lite to interact with your newly created cyber agents.

```sh
http://localhost:3000/chat-lite
```