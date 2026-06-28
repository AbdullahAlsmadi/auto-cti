import os
import json
import re
import datetime
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv
import sys

sys.stdout.reconfigure(encoding='utf-8')  # type: ignore

load_dotenv()

today_date = datetime.datetime.now().strftime("%B %d, %Y")

scout_file_path = os.path.join("JoFile", "Scout_Agent_Results", "cti_report.json")

try:
    with open(scout_file_path, 'r', encoding='utf-8') as f:
        all_reports = json.load(f)
        raw_threat_data = all_reports.get(today_date, {})
except FileNotFoundError:
    print(f"Error: Could not find {scout_file_path}. Please run scout_agent.py first.")
    exit()

if not raw_threat_data:
    print(f"No data found for today ({today_date}) in the JSON file.")
    exit()

cve_count = len(raw_threat_data) if isinstance(raw_threat_data, list) else len(raw_threat_data.get("vulnerabilities", raw_threat_data))
print(f"DEBUG - CVEs received from Scout: {cve_count}")

output_dir = os.path.join("JoFile", "triage_agent_result")
os.makedirs(output_dir, exist_ok=True)

triage_llm = LLM(
    model="gemini/gemini-3.1-flash-lite",
    api_key=os.getenv("GEMINI_API_KEY"),
    max_retries=5  # type: ignore
)

triage_agent = Agent(
    role='Senior Cyber Threat Intelligence Analyst',
    goal=(
        'Analyze raw CVE data using CVSS v3.1, assign CWE classifications, '
        'map to MITRE ATT&CK techniques, write professional descriptions, '
        'provide verifiable online references, assign a finding name, '
        'write a proof of concept, and calculate an Urgency Score.'
    ),
    backstory=(
        'You are an elite threat intelligence analyst with deep expertise in '
        'CVSS v3.1 scoring, CWE classification, and MITRE ATT&CK framework mapping. '
        'You produce formal, board-level security intelligence reports. '
        'Your descriptions explain the vulnerability concept clearly and professionally. '
        'You always provide real, accessible online references for every CVE.'
    ),
    verbose=True,
    llm=triage_llm,
    allow_delegation=False
)

output_file_path = os.path.join(output_dir, f'Triaged_Report_{today_date}.json')

triage_task = Task(
    description=f'''You are analyzing CVE threat data collected on {today_date}.

MANDATORY: The input contains exactly {cve_count} CVE entries. You MUST produce exactly {cve_count} objects in your output array. Do NOT stop early. Do NOT skip any entry. Process every single one.

RAW THREAT DATA:
{json.dumps(raw_threat_data, indent=2)}

For EACH CVE entry, produce a complete professional triage record following these rules:

1. CVE_ID: Copy exactly as given. Never modify.

2. Finding_Name: A short, descriptive human-readable title for the vulnerability (3-8 words).
   Examples: "Remote Code Execution in Apache HTTP Server", "SQL Injection in Login Handler",
   "Privilege Escalation via Buffer Overflow in Linux Kernel".

3. Description: Write 2-3 professional sentences explaining:
   - What the vulnerability is and which component is affected
   - How it can be exploited (the attack concept)
   - What the potential impact is on confidentiality, integrity, or availability

4. CVSS_Score: Copy the numeric score exactly as given. Do NOT estimate or change it.

5. CVSS_Severity: Map the score to the correct CVSS v3.1 label:
   - 0.0 = None | 0.1-3.9 = Low | 4.0-6.9 = Medium | 7.0-8.9 = High | 9.0-10.0 = Critical
   Do NOT use "Moderate" or "Important".

6. CVSS_Vector: The CVSS v3.1 vector string. Use data if available, otherwise derive from vulnerability type.
   Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
   Must include all 8 base metrics: AV, AC, PR, UI, S, C, I, A.

7. CVSS_Breakdown: Human-readable interpretation of each CVSS v3.1 base metric as a JSON object:
   {{
     "Attack_Vector": "Network" | "Adjacent" | "Local" | "Physical",
     "Attack_Complexity": "Low" | "High",
     "Privileges_Required": "None" | "Low" | "High",
     "User_Interaction": "None" | "Required",
     "Scope": "Unchanged" | "Changed",
     "Confidentiality": "None" | "Low" | "High",
     "Integrity": "None" | "Low" | "High",
     "Availability": "None" | "Low" | "High"
   }}

8. CWE_ID: Copy exactly as given from the raw data.

9. MITRE_Mappings: 1-3 relevant MITRE ATT&CK technique IDs (e.g. T1190, T1059). Codes only.

10. Urgency_Score: 1-100 score:
    - Base = CVSS score * 9 (max 90)
    - Add 10 if AlienVault pulses are present
    - Subtract 5 if severity is Low or None
    Round to nearest integer.

11. PoC: Write 2-4 sentences describing HOW an attacker would realistically exploit this vulnerability.
    Be specific about: attack vector and prerequisites, the specific action taken, and the outcome.
    Technical enough for a security engineer. Do NOT include actual exploit code.
    Example format: "An unauthenticated remote attacker can send a specially crafted HTTP POST request
    to the vulnerable endpoint. The server processes the malicious payload without input validation,
    resulting in arbitrary code execution under the web server process context. This grants the attacker
    full system access and the ability to pivot to internal network resources."

12. References: Exactly 2 URLs:
    - https://nvd.nist.gov/vuln/detail/{{CVE_ID}}
    - https://www.cve.org/CVERecord?id={{CVE_ID}}

CRITICAL OUTPUT RULES:
- Output ONLY a raw valid JSON array. No markdown. No code fences. No extra text.
- Every field must be present in every object.
- The JSON must be parseable by Python json.loads() without any cleanup.''',

    expected_output=f'''A raw valid JSON array containing exactly {cve_count} objects:
[
  {{
    "CVE_ID": "CVE-2026-XXXXX",
    "Finding_Name": "Remote Code Execution in Example Component",
    "Description": "Professional 2-3 sentence explanation.",
    "CVSS_Score": 9.8,
    "CVSS_Severity": "Critical",
    "CVSS_Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS_Breakdown": {{
      "Attack_Vector": "Network",
      "Attack_Complexity": "Low",
      "Privileges_Required": "None",
      "User_Interaction": "None",
      "Scope": "Unchanged",
      "Confidentiality": "High",
      "Integrity": "High",
      "Availability": "High"
    }},
    "CWE_ID": "CWE-89",
    "MITRE_Mappings": ["T1190", "T1059"],
    "Urgency_Score": 95,
    "PoC": "An unauthenticated attacker can exploit this by...",
    "References": [
      "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX",
      "https://www.cve.org/CVERecord?id=CVE-2026-XXXXX"
    ]
  }}
]
The array MUST contain {cve_count} entries.''',

    agent=triage_agent,
    output_file=output_file_path
)

triage_crew = Crew(
    agents=[triage_agent],
    tasks=[triage_task],
    verbose=True
)

if __name__ == "__main__":
    print(f"Waking up the Triage Agent to analyze threats for {today_date}...")
    result = triage_crew.kickoff()

    print("\n================================================")
    print("Triage Analysis Complete!")
    print("================================================")

    raw_result = str(result).strip()

    if raw_result.startswith("```json"):
        raw_result = raw_result[7:]
    if raw_result.startswith("```"):
        raw_result = raw_result[3:]
    if raw_result.endswith("```"):
        raw_result = raw_result[:-3]
    raw_result = raw_result.strip()

    raw_result = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', raw_result)

    try:
        parsed = json.loads(raw_result)
        with open(output_file_path, 'w', encoding='utf-8') as f:
            json.dump(parsed, f, indent=2, ensure_ascii=False)
        print(f"Triage report saved: {output_file_path}")
        print(f"Total CVEs triaged: {len(parsed)}")
    except json.JSONDecodeError as e:
        print(f"Warning: Could not parse output as clean JSON: {e}")
        print("Saving raw output as fallback...")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(raw_result)
        print(f"Raw output saved: {output_file_path}")