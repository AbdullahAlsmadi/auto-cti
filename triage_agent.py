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

output_dir = os.path.join("JoFile", "triage_agent_result")
os.makedirs(output_dir, exist_ok=True)

triage_llm = LLM(
    model="ollama/qwen2.5",
    base_url="http://localhost:11434"
)

triage_agent = Agent(
    role='Senior Cyber Threat Intelligence Analyst',
    goal=(
        'Analyze raw CVE data using CVSS v3.1, assign CWE classifications, '
        'map to MITRE ATT&CK techniques, write professional descriptions, '
        'provide verifiable online references, and calculate an Urgency Score.'
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

RAW THREAT DATA:
{json.dumps(raw_threat_data, indent=2)}

For EACH CVE entry, produce a complete professional triage record following these rules:

1. CVE_ID: Copy exactly as given. Never modify.

2. Description: Write 2-3 professional sentences that explain:
   - What the vulnerability is and which component is affected
   - How it can be exploited (the attack concept)
   - What the potential impact is on confidentiality, integrity, or availability
   Keep it formal and suitable for a CISO-level audience.

3. CVSS_Score: Copy the numeric score exactly as given. Do NOT estimate or change it.
   This score follows the CVSS v3.1 standard (Common Vulnerability Scoring System version 3.1).

4. CVSS_Severity: Map the score to the correct CVSS v3.1 severity label:
   - 0.0       = None
   - 0.1-3.9   = Low
   - 4.0-6.9   = Medium
   - 7.0-8.9   = High
   - 9.0-10.0  = Critical
   Use these exact labels. Do NOT use "Moderate" or "Important" — those are not CVSS v3.1 terms.

5. CWE_ID: Copy exactly as given from the raw data. This identifies the root cause weakness category.

6. MITRE_Mappings: Provide 1-3 relevant MITRE ATT&CK technique IDs (e.g. T1190, T1059).
   Choose techniques that match the vulnerability's exploitation method.
   Use only technique codes — no names, no descriptions.

7. Urgency_Score: Calculate a score from 1 to 100 using this logic:
   - Start with CVSS score * 9 as base (max 90 from CVSS alone)
   - Add 10 if AlienVault pulses are present (active exploitation evidence)
   - Subtract 5 if severity is Low or None
   Round to nearest integer.

8. References: Provide exactly 2 real, publicly accessible online URLs:
   - Always include: https://nvd.nist.gov/vuln/detail/{{CVE_ID}}
   - Always include: https://www.cve.org/CVERecord?id={{CVE_ID}}

CRITICAL OUTPUT RULES:
- Output ONLY a raw valid JSON array. No markdown. No code fences. No extra text.
- Every field must be present in every object.
- The JSON must be parseable by Python json.loads() without any cleanup.''',

    expected_output='''A raw valid JSON array. Every object must follow this exact structure:
[
  {
    "CVE_ID": "CVE-2026-XXXXX",
    "Description": "Professional 2-3 sentence explanation of the vulnerability concept, exploitation method, and impact.",
    "CVSS_Score": 9.8,
    "CVSS_Severity": "Critical",
    "CWE_ID": "CWE-89",
    "MITRE_Mappings": ["T1190", "T1059"],
    "Urgency_Score": 95,
    "References": [
      "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX",
      "https://www.cve.org/CVERecord?id=CVE-2026-XXXXX"
    ]
  }
]''',
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