import os
import json
import re
import datetime
import sys
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv
from cvss import CVSS3

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


def recalculate_score_from_vector(entry: dict) -> dict:
    vector = entry.get("CVSS_Vector", "")
    if not vector or vector == "N/A":
        return entry
    try:
        c = CVSS3(vector)
        calculated_score = float(c.base_score)  # type: ignore
        entry["CVSS_Score"] = calculated_score
        entry["CVSS_Severity"] = c.severities()[0]
        entry["Score_Source"] = entry.get("Score_Source", "verified") + "_recalculated"
    except Exception:
        pass
    return entry


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

3. Description: Write exactly 3 professional sentences:
   - Sentence 1: Name the exact vulnerable component and function/method
     (e.g., OBSmilesParser::ParseSmiles, payWithCredit(), save-job handler),
     and identify the vulnerability class (heap buffer overflow, race condition,
     sandbox escape, IDOR, prototype pollution, NULL pointer dereference, etc.).
   - Sentence 2: Explain the technical root cause — what fails and why
     (e.g., missing bounds check, lack of atomic locking, insufficient
     authorization verification, improper memory deallocation).
   - Sentence 3: State the concrete security impact using CIA triad terminology
     and specify exploitation prerequisites (authenticated/unauthenticated,
     local/remote access required).

4. CVSS_Score: Copy the numeric score exactly as given, UNLESS the rule in step 4a applies.

4a. MISSING/INCOMPLETE SCORE HANDLING (IMPORTANT):
   If the input CVSS_Score is 0.0, null, "N/A", or absent, you MUST check whether the
   vulnerability description and Confidentiality/Integrity/Availability impact indicate
   real severity (e.g. RCE, authentication bypass, privilege escalation, token forgery,
   sandbox escape). If so, a score of 0.0 is INVALID and must NOT be reported as-is.
   In that case, DERIVE an estimated CVSS_Score and CVSS_Vector yourself based on the
   vulnerability type and impact described, following standard CVSS v3.1 scoring logic.
   Mark this entry by setting "Score_Source": "estimated" (vs "Score_Source": "verified"
   for scores copied directly from input). Never leave a clearly severe vulnerability
   classified as CVSS 0.0 / Severity "None".

5. CVSS_Severity: Map the score to the correct CVSS v3.1 label:
   - 0.0 = None | 0.1-3.9 = Low | 4.0-6.9 = Medium | 7.0-8.9 = High | 9.0-10.0 = Critical
   Do NOT use "Moderate" or "Important". Do NOT output "None" for a vulnerability that
   has high confidentiality/integrity/availability impact — that combination is invalid
   and indicates you must apply rule 4a instead.

6. CVSS_Vector:
   PRIORITY ORDER:
   a) If the input data contains a CVSS vector string, copy it EXACTLY — do not modify.
   b) If no vector is provided but a CVSS_Score exists, derive a vector that mathematically
      produces that exact score using the CVSS v3.1 formula.
   c) If both are missing (Score=0.0), derive vector based on vulnerability type and impact.

   IMPORTANT: The vector you provide MUST be mathematically consistent with the score.
   Use https://www.first.org/cvss/calculator/3.1 logic to verify before outputting.
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

11. PoC: Write a technical proof-of-concept in exactly 4 sentences:
   - Sentence 1: State the exact prerequisites (e.g., "An unauthenticated remote
     attacker", "An authenticated user with low privileges", "A local user with
     read access to the filesystem").
   - Sentence 2: Describe the specific attack action with technical precision —
     include the exact endpoint, function, parameter name, or file type involved.
     Example: "The attacker sends a POST request to /api/jobs/save with body
     {{"job_id": "<victim_id>"}} without an ownership check."
     Example: "The attacker submits a MOL2 file with a missing atom definition
     block, causing OBAtom::SetFormalCharge to dereference a null pointer."
   - Sentence 3: Describe what happens server-side — which code path is triggered
     and why it fails (e.g., "The server processes the request without verifying
     that the requesting user owns the target resource.").
   - Sentence 4: State the final impact — what the attacker gains or what system
     state is compromised (e.g., "This results in full cluster compromise and
     lateral movement across all Kubernetes nodes.").

   IMPORTANT:
   - Use specific function names, endpoints, or file types from the description.
   - Do NOT write generic text like "the attacker exploits the vulnerability".
   - Do NOT include actual working exploit code or shellcode.

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
    "Description": "Professional 3-sentence explanation.",
    "CVSS_Score": 9.8,
    "CVSS_Severity": "Critical",
    "CVSS_Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "Score_Source": "verified",
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
    "PoC": "An unauthenticated remote attacker targets the vulnerable endpoint. The attacker sends a POST request to /api/example with a crafted payload containing injected DQL syntax. The server passes the input directly to the query engine without sanitization, executing the attacker-controlled query. This results in unauthorized extraction of all stored user credentials from the database.",
    "References": [
      "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX",
      "https://www.cve.org/CVERecord?id=CVE-2026-XXXXX"
    ]
  }}
]
The array MUST contain {cve_count} entries. "Score_Source" must be either "verified"
(CVSS_Score copied directly from input data) or "estimated" (CVSS_Score derived by you
because the input score was missing/zero on a clearly impactful vulnerability, per rule 4a).''',

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
        parsed = [recalculate_score_from_vector(e) for e in parsed]
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