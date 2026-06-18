# Auto-CTI: Autonomous CTI Triage and Reporting Network

## 📌 Project Overview
Auto-CTI is an autonomous multi-agent system designed to scrape, aggregate, filter, and analyze daily emerging cyber threats, including CVEs, threat landscape news, and Indicators of Compromise (IoCs)[cite: 1]. The system automatically filters out false positives, maps threat behaviors to the MITRE ATT&CK framework, and generates actionable threat intelligence briefings[cite: 1].

## 🤖 Agent Architecture
The system utilizes three specialized AI agents working in a sequential, cooperative workflow[cite: 1]:

*   **The Scout Agent (Data Collector):** Continuously monitors and fetches raw threat data from external sources such as NIST NVD API, AlienVault OTX, cybersecurity RSS feeds, and curated security feeds on X (Twitter)[cite: 1].
*   **The Triage Agent (Threat Analyst):** Processes the raw data stream[cite: 1]. It filters out low-priority alerts, deduces severity based on CVSS metrics, maps the threat behavior to MITRE ATT&CK techniques, and calculates a custom "Urgency Score" tailored to an organization's tech stack[cite: 1].
*   **The Publisher Agent (Reporter):** Takes the analyzed structured data and compiles it into clean, executive-ready security briefings[cite: 1]. Outputs include structured JSON feeds for SIEM integration, markdown bimonthly reports, or automated Slack/Email alerts[cite: 1].

## 🛠️ Tech Stack
*   **Programming Language:** Python[cite: 1]
*   **Agent Framework:** CrewAI[cite: 1]
*   **LLM Engine:** Claude 3.5 Sonnet (for reasoning) & Mistral via Ollama/Groq (for operational agents)[cite: 1]
*   **Vector Database:** ChromaDB[cite: 1]
*   **User Interface:** Streamlit[cite: 1]

## 🚀 Objective
To automate the heavy lifting of Cyber Threat Intelligence (CTI) gathering and triage, allowing security teams to focus on mitigation rather than manual data collection and formatting.
