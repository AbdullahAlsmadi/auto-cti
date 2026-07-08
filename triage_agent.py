import os
import json
import re
import time
import requests
import datetime
import sys
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv
from cvss import CVSS3

sys.stdout.reconfigure(encoding='utf-8')                 # type: ignore

load_dotenv()

today_date = datetime.datetime.now().strftime("%B %d, %Y")

#reading the data___________________________________________________________________________________________

scout_file_path = os.path.join("JoFile", "Scout_Agent_Results", "cti_report.json")

try:
    with open(scout_file_path, 'r', encoding='utf-8') as f:
        all_reports = json.load(f)
                                                                                   
        day_data = all_reports.get(today_date, {})
        if isinstance(day_data, dict) and "vulnerabilities" in day_data:
            raw_threat_data = day_data["vulnerabilities"]
        else:
            raw_threat_data = day_data
except FileNotFoundError:
    print(f"Error: Could not find {scout_file_path}. Please run scout_agent.py first.")
    exit()

if not raw_threat_data:
    print(f"No data found for today ({today_date}) in the JSON file.")
    exit()

cve_count = len(raw_threat_data)
print(f"DEBUG - CVEs received from Scout: {cve_count}")

output_dir = os.path.join("JoFile", "triage_agent_result")
os.makedirs(output_dir, exist_ok=True)

#the llm model____________________________________________________________________________________________

triage_llm = LLM(
   model="gemini/gemini-2.5-flash",
    api_key=os.getenv("GEMINI_API_KEY"),
    max_retries=5                # type: ignore
)

                                                                      
                                                                                                                                           
cve_source_lookup = {}
if isinstance(raw_threat_data, list):
    for item in raw_threat_data:
        cid = item.get("cve_id")
        if cid:
            cve_source_lookup[cid] = {
                "cvss_source": item.get("cvss_source", "ghsa_only"),
                "score":       item.get("cvss_score"),
                "vector":      item.get("cvss_vector", "N/A"),
            }

#using Tenable to fetch missing CVSS vectors___________________________________________________________________________________________
def fetch_tenable_live_cvss(cve_id: str):
    try:
        url = f"https://www.tenable.com/cve/{cve_id}"
        r = requests.get(url, timeout=12, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200: return None
        clean_text = re.sub(r'<[^>]+>', ' ', r.text)
        clean_text = re.sub(r'\s+', ' ', clean_text)
        v3_header = re.search(r'CVSS\s*v3\b', clean_text)
        if not v3_header: return None
        section_start = v3_header.end()
        boundary = re.search(r'CVSS\s*v4\b|EPSS\b', clean_text[section_start:])
        section_end = section_start + (boundary.start() if boundary else 600)
        section = clean_text[section_start:section_end]
        score_match  = re.search(r'Base\s*Score[\s:*]*([0-9]{1,2}\.[0-9])', section, re.IGNORECASE)
        vector_match = re.search(r'(CVSS:3\.[01]/[A-Za-z0-9:/]+)', section)
        severity_match = re.search(r'Severity[\s:*]*(Critical|High|Medium|Low|None)', section, re.IGNORECASE)
        if not score_match or not vector_match: return None
        return {
            "score": float(score_match.group(1)),
            "vector": vector_match.group(1),
            "severity": severity_match.group(1).capitalize() if severity_match else "Unknown",
        }
    except Exception as e:
        return None
print("\nDEBUG - Performing Pre-Triage Tenable Enrichment for missing vectors...")
if isinstance(raw_threat_data, list):
    for item in raw_threat_data:
        cid = item.get("cve_id")
        source = item.get("cvss_source", "")
        vector = item.get("cvss_vector", "N/A")
        
        if source in ("ghsa_only", "cna_no_cvss") or vector == "N/A":
            if cid:
                tenable_data = fetch_tenable_live_cvss(cid)
                if tenable_data and tenable_data.get("vector") and tenable_data.get("vector") != "N/A":
                    item["cvss_score"] = tenable_data["score"]
                    item["cvss_vector"] = tenable_data["vector"]
                    item["cvss_severity"] = tenable_data["severity"]
                    item["cvss_source"] = "tenable_verified"
                    print(f" --> [SUCCESS] Pre-enriched {cid} directly from Tenable.")
            time.sleep(0.3)
print("DEBUG - Pre-Enrichment Complete.\n")

#This is function for later using at vector_____________________________________________________________________________________________
def parse_cvss_vector(vector: str):
    """
    Deterministically parses a CVSS:3.1 vector string into the same
    human-readable breakdown structure used throughout the report, instead
    of trusting the LLM to describe the vector in its own words.
    """
    labels = {
        "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low", "H": "High"},
        "PR": {"N": "None", "L": "Low", "H": "High"},
        "UI": {"N": "None", "R": "Required"},
        "S":  {"U": "Unchanged", "C": "Changed"},
        "C":  {"N": "None", "L": "Low", "H": "High"},
        "I":  {"N": "None", "L": "Low", "H": "High"},
        "A":  {"N": "None", "L": "Low", "H": "High"},
    }
    field_names = {
        "AV": "Attack_Vector", "AC": "Attack_Complexity", "PR": "Privileges_Required",
        "UI": "User_Interaction", "S": "Scope", "C": "Confidentiality",
        "I": "Integrity", "A": "Availability",
    }
    breakdown = {}
    try:
        parts = vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/")
        for part in parts:
            key, _, value = part.partition(":")
            if key in labels and value in labels[key]:
                breakdown[field_names[key]] = labels[key][value]
    except Exception:
        pass
    return breakdown


def enforce_authoritative_cvss(entry: dict, source_info: dict) -> dict:
    """
    For CVEs where Scout already confirmed an official score AND vector
    (nvd_verified / cna_official), this function completely overrides
    whatever CVSS_Score, CVSS_Vector, CVSS_Severity, and CVSS_Breakdown the
    LLM produced. The LLM's own vector must never be trusted for these
    entries, since a self-invented vector being fed back into a
    "recalculate score from vector" step is exactly what silently corrupted
    officially-verified scores in earlier runs.
    """
    cvss_source = source_info["cvss_source"]
    vector      = source_info.get("vector", "N/A")

    if cvss_source not in ("nvd_verified", "cna_official", "tenable_verified") or not vector or vector == "N/A":
        return None                                                                                      # type: ignore

    entry["CVSS_Vector"] = vector
    entry["CVSS_Breakdown"] = parse_cvss_vector(vector)
    try:
        c = CVSS3(vector)
        entry["CVSS_Score"] = float(c.base_score)                 # type: ignore
        entry["CVSS_Severity"] = c.severities()[0]
    except Exception:
        entry["CVSS_Score"] = source_info.get("score", entry.get("CVSS_Score"))
    entry["Score_Source"] = cvss_source
    return entry


def map_source_to_score_source(cvss_source: str, was_estimated_by_llm: bool) -> str:
    """
    Deterministically decides the final Score_Source field for a triaged CVE,
    based on the trust level Scout already assigned, instead of trusting
    whatever label the LLM produced on its own.
    """
    if cvss_source in ("nvd_verified", "cna_official", "tenable_verified"):
                                                                            
                                                                      
        return cvss_source
    if cvss_source == "cna_no_cvss":
                                                                        
                                                                             
        return "estimated_no_cna_score"
                                                                          
                                                                       
    return "estimated_unverified"


def recalculate_score_from_vector(entry: dict) -> dict:
    """
    Independently recomputes the CVSS base score from the CVSS_Vector string
    using the `cvss` library. This catches cases where the LLM wrote a score
    and a vector that are not mathematically consistent with each other.
    """
    vector = entry.get("CVSS_Vector", "")
    if not vector or vector == "N/A":
        return entry
    try:
        c = CVSS3(vector)
        calculated_score = float(c.base_score)                 # type: ignore
        entry["CVSS_Score"] = calculated_score
        entry["CVSS_Severity"] = c.severities()[0]
        entry["Score_Source"] = entry.get("Score_Source", "estimated_unverified") + "_recalculated"
    except Exception:
        pass
    return entry


def is_reference_alive(url: str) -> bool:
    """
    Performs a real network check on a reference URL using GET instead of
    HEAD, since some sites (including Tenable) do not reliably support HEAD
    requests. Only a confirmed 404 (the page genuinely does not exist) is
    treated as dead. Timeouts or blocks are treated as inconclusive and the
    link is kept, since some hosts block requests based on region/ISP
    without the page actually being missing.
    """
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, stream=True)
        r.close()
        if r.status_code == 404:
            return False
        return True
    except Exception:
        return True


#for references_____________________________________________________________________________________________
def build_verified_references(cve_id: str) -> list:
    """
    Builds the References list independently in Python instead of trusting
    whatever the LLM wrote. Checks, in priority order:
        1. NVD          - the primary authoritative source
        2. CVE.org      - the official CVE Program record
        3. Tenable      - a reliable third-party CVE database, used when a
                          CVE has not yet propagated to NVD/CVE.org
    NVD/CVE.org links are ONLY included if they are confirmed to exist.
    If none of the three resolve, a GitHub Advisory search link is used as
    a last-resort fallback so the report never ships with zero references.
    """
    candidates = [
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        f"https://www.cve.org/CVERecord?id={cve_id}",
        f"https://www.tenable.com/cve/{cve_id}",
    ]

    alive_refs = []
    for url in candidates:
        if is_reference_alive(url):
            alive_refs.append(url)
        time.sleep(0.1)

    if not alive_refs:
        alive_refs = [f"https://github.com/advisories?query={cve_id}"]

    return alive_refs

#agent tools______________________________________________________________________________________________
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

if os.path.exists(output_file_path):
    os.remove(output_file_path)
    print(f"Removed old report before regenerating: {output_file_path}")
    
triage_task = Task(
    description=f'''You are analyzing CVE threat data collected on {today_date}.

MANDATORY: The input contains exactly {cve_count} CVE entries. You MUST produce exactly {cve_count} objects in your output array. Do NOT stop early. Do NOT skip any entry. Process every single one.

RAW THREAT DATA:
{json.dumps(raw_threat_data, indent=2)}

Each entry in the raw data carries a "cvss_source" field and, when available,
a "cvss_vector" field set by the data collection stage.
- "nvd_verified", "cna_official", or "tenable_verified" with a real cvss_vector
  (not "N/A"): the score AND vector are AUTHORITATIVE. Copy CVSS_Score and
  CVSS_Vector EXACTLY as given, character for character. Do not compute,
  adjust, or reformat them. (Note: these two fields will also be independently
  re-verified and corrected afterwards if they do not match, so copying them
  exactly is the only way to avoid a mismatch being flagged.)
- "cna_no_cvss" or "ghsa_only", or a missing cvss_vector: no authoritative score
  was confirmed. Apply rule 4a below.

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

4. CVSS_Score: Copy the numeric score exactly as given when cvss_source is
   "nvd_verified" or "cna_official". Otherwise apply rule 4a.

4a. MISSING/INCOMPLETE SCORE HANDLING (only applies when cvss_source is
   "cna_no_cvss" or "ghsa_only"):
   If the input CVSS_Score is 0.0, null, "N/A", or absent, check whether the
   vulnerability description and Confidentiality/Integrity/Availability impact
   indicate real severity (e.g. RCE, authentication bypass, privilege escalation,
   token forgery, sandbox escape). If so, a score of 0.0 is INVALID and must NOT
   be reported as-is. In that case, DERIVE an estimated CVSS_Score and CVSS_Vector
   yourself based on the vulnerability type and impact described, following
   standard CVSS v3.1 scoring logic. Never leave a clearly severe vulnerability
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

12. References: Output an empty array []. Do NOT generate reference URLs
    yourself — they are built and independently verified in a separate step
    afterwards, checking NVD, CVE.org, and Tenable directly.

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
    "References": []
  }}
]
The array MUST contain {cve_count} entries. Do NOT include a "Score_Source" field
yourself — it is added automatically afterwards based on the original cvss_source.''',

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

        fixed_entries = []
        for entry in parsed:
                                                                       
            cve_id = entry.get("CVE_ID") or entry.get("cve_id") or ""
            entry["CVE_ID"] = cve_id  
            
            source_info = cve_source_lookup.get(
                cve_id, {"cvss_source": "ghsa_only", "score": None, "vector": "N/A"}
            )
            cvss_source = source_info["cvss_source"]

                                                                                  
            enforced = enforce_authoritative_cvss(entry, source_info)
            if enforced is not None:
                entry = enforced
            else:
                entry["Score_Source"] = map_source_to_score_source(cvss_source, True)
                entry = recalculate_score_from_vector(entry)

            entry["References"] = build_verified_references(cve_id)

            fixed_entries.append(entry)

        with open(output_file_path, 'w', encoding='utf-8') as f:
            json.dump(fixed_entries, f, indent=2, ensure_ascii=False)
        print(f"Triage report saved: {output_file_path}")
        print(f"Total CVEs triaged: {len(fixed_entries)}")
    except json.JSONDecodeError as e:
        print(f"Warning: Could not parse output as clean JSON: {e}")
        print("Saving raw output as fallback...")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(raw_result)
        print(f"Raw output saved: {output_file_path}")