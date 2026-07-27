import os
import json
import re
import time
import requests
import datetime
from crewai import Agent, Task, Crew, LLM
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.secure_config import init_config

init_config()

sys.stdout.reconfigure(encoding='utf-8')

today_date = datetime.datetime.now().strftime("%B %d, %Y")
print(f"Scout Agent started. Today: {today_date}")
print(f"Gemini API Key loaded: {bool(os.getenv('GEMINI_API_KEY'))}")
print(f"NVD API Key loaded: {bool(os.getenv('NVD_API_KEY'))}")

DATA_DIR = os.path.expanduser("~/.auto-cti/data")
os.makedirs(DATA_DIR, exist_ok=True)

MAMORE_DIR = os.path.join(DATA_DIR, "MAMORE")
SEEN_CVES_PATH = os.path.join(MAMORE_DIR, "seen_cve_ids.json")
os.makedirs(MAMORE_DIR, exist_ok=True)

DESIRED_CVE_COUNT = 100

def load_seen_cve_ids() -> set:
    if not os.path.exists(SEEN_CVES_PATH):
        return set()
    try:
        with open(SEEN_CVES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return set(data.get("seen_cve_ids", []))
    except (json.JSONDecodeError, IOError) as e:
        print(f"DEBUG - Could not load seen_cve_ids.json, starting fresh: {e}")
        return set()

def save_seen_cve_ids(seen_ids: set) -> None:
    os.makedirs(MAMORE_DIR, exist_ok=True)
    with open(SEEN_CVES_PATH, "w", encoding="utf-8") as f:
        json.dump({"seen_cve_ids": sorted(seen_ids)}, f, indent=2, ensure_ascii=False)
    print(f"DEBUG - Saved {len(seen_ids)} total seen CVE IDs to {SEEN_CVES_PATH}")

def fetch_cve_services_cvss(cve_id: str):
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        r = requests.get(url, timeout=15)
        if r.status_code == 404:
            return "not_found"
        if r.status_code != 200:
            return None
        data = r.json()
        cna = data.get("containers", {}).get("cna", {})
        metrics = cna.get("metrics", [])
        for m in metrics:
            for key in ["cvssV3_1", "cvssV3_0"]:
                if key in m:
                    cvss = m[key]
                    score = cvss.get("baseScore")
                    vector = cvss.get("vectorString")
                    severity = cvss.get("baseSeverity")
                    if score is not None and vector:
                        return {"score": score, "vector": vector, "severity": severity}
        return {"score": None, "vector": None, "severity": None}
    except Exception as e:
        print(f"DEBUG - CVE Services Error for {cve_id}: {e}")
        return None

def fetch_opencve_cvss(cve_id: str):
    username = os.getenv("OPENCVE_USERNAME")
    password = os.getenv("OPENCVE_PASSWORD")
    if not username or not password:
        return None
    try:
        url = f"https://app.opencve.io/api/cve/{cve_id}"
        r = requests.get(url, auth=(username, password), timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        metrics = data.get("metrics", {})
        cvss_block = metrics.get("cvssV3_1") or metrics.get("cvssV3_0") or {}
        score = cvss_block.get("score")
        vector = cvss_block.get("vector")
        severity = cvss_block.get("severity")
        if score is not None and vector:
            return {"score": score, "vector": vector, "severity": severity}
        return {"score": None, "vector": None, "severity": None}
    except Exception as e:
        print(f"DEBUG - OpenCVE Error for {cve_id}: {e}")
        return None

def fetch_tenable_cvss(cve_id: str):
    try:
        url = f"https://www.tenable.com/cve/{cve_id}"
        r = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return None
        clean_text = re.sub(r'<[^>]+>', ' ', r.text)
        clean_text = re.sub(r'\s+', ' ', clean_text)
        v3_header = re.search(r'CVSS\s*v3\b', clean_text)
        if not v3_header:
            return None
        section_start = v3_header.end()
        boundary = re.search(r'CVSS\s*v4\b|EPSS\b', clean_text[section_start:])
        section_end = section_start + (boundary.start() if boundary else 600)
        section = clean_text[section_start:section_end]
        score_match = re.search(r'Base\s*Score[\s:*]*([0-9]{1,2}\.[0-9])', section, re.IGNORECASE)
        vector_match = re.search(r'(CVSS:3\.[01]/[A-Za-z0-9:/]+)', section)
        severity_match = re.search(r'Severity[\s:*]*(Critical|High|Medium|Low|None)', section, re.IGNORECASE)
        if not score_match or not vector_match:
            return None
        return {
            "score": float(score_match.group(1)),
            "vector": vector_match.group(1),
            "severity": severity_match.group(1).capitalize() if severity_match else None,
        }
    except Exception as e:
        print(f"DEBUG - Tenable Error for {cve_id}: {e}")
        return None

def verify_cvss(cve_id: str, fallback_score, fallback_severity):
    result = fetch_cve_services_cvss(cve_id)
    if result == "not_found" or result is None:
        result = fetch_opencve_cvss(cve_id)
    if result is not None and result.get("score") is not None:
        return (
            result["score"],
            result.get("severity", fallback_severity),
            "cna_official",
            result.get("vector") or "N/A",
        )
    tenable_result = fetch_tenable_cvss(cve_id)
    if tenable_result is not None:
        return (
            tenable_result["score"],
            fallback_severity,
            "tenable_verified",
            tenable_result["vector"],
        )
    if result is not None:
        return fallback_score, fallback_severity, "cna_no_cvss", "N/A"
    return fallback_score, fallback_severity, "ghsa_only", "N/A"

class CVEEntry(BaseModel):
    cve_id: str = Field(..., description="The official CVE ID starting with CVE-")
    description: str = Field(..., description="Vulnerability description or summary")
    cvss_score: float = Field(..., description="The numeric CVSS score")
    cvss_severity: str = Field(..., description="The calculated or verified severity")
    cvss_source: str = Field(..., description="The source database of the CVSS score")
    cvss_vector: str = Field(..., description="The standard CVSS vector string or N/A")
    cwe_id: str = Field(..., description="The associated CWE ID")
    alienvault_pulse_count: int = Field(0, description="Set this to 0. Python will update it natively.")

class ScoutReport(BaseModel):
    vulnerabilities: List[CVEEntry]

class NISTSearchTool(BaseTool):
    name: str = "NIST NVD Recent Search Tool"
    description: str = f"Fetches the {DESIRED_CVE_COUNT} most recent CVEs published in the last 7 days."

    def _run(self, query: str) -> str:
        seen_ids = load_seen_cve_ids()
        print(f"DEBUG - Loaded {len(seen_ids)} previously seen CVE IDs from MAMORE.")
        headers = {"User-Agent": "Auto-CTI-Agent/1.0"}
        nvd_api_key = os.getenv("NVD_API_KEY")
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        def parse_nvd_response(data):
            verified_cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                if cve_id in seen_ids:
                    continue
                desc = "No description available."
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", desc)
                        break
                cvss_score = "N/A"
                cvss_severity = "N/A"
                cvss_vector = "N/A"
                cwe_id = "N/A"
                metrics = cve.get("metrics", {})
                cvss_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                if cvss_list:
                    cvss_data = cvss_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    cvss_severity = cvss_data.get("baseSeverity", "N/A")
                    cvss_vector = cvss_data.get("vectorString", "N/A")
                for weakness in cve.get("weaknesses", []):
                    for wd in weakness.get("description", []):
                        if wd.get("lang") == "en":
                            cwe_id = wd.get("value", "N/A")
                            break
                if cvss_vector != "N/A":
                    cvss_source = "nvd_verified"
                else:
                    cvss_source = "nvd_no_vector"
                verified_cves.append(
                    f"SOURCE: NVD | VERIFIED_CVE_ID: {cve_id} | "
                    f"CVSS: {cvss_score} | SEVERITY: {cvss_severity} | "
                    f"CWE: {cwe_id} | CVSS_SOURCE: {cvss_source} | "
                    f"CVSS_VECTOR: {cvss_vector} | DESC: {desc[:500]}"
                )
            return verified_cves

        try:
            print(f"DEBUG - Trying NVD (resultsPerPage={DESIRED_CVE_COUNT})...")
            params = {
                "resultsPerPage": DESIRED_CVE_COUNT,
                "sortBy": "publishDate",
                "sortOrder": "desc"
            }
            r = requests.get(nvd_url, headers=headers, params=params, timeout=30)
            print(f"DEBUG - NVD Status: {r.status_code}")
            if r.status_code == 200:
                cves = parse_nvd_response(r.json())
                if cves:
                    return "STRICT INSTRUCTION: USE EXACTLY THESE IDs AND SCORES:\n" + "\n".join(cves)
        except Exception as e:
            print(f"DEBUG - NVD Error: {e}")

        try:
            print("DEBUG - Trying GitHub Advisory Database (GraphQL, paginated)...")
            TARGET_COUNT = DESIRED_CVE_COUNT
            MAX_PAGES = 10
            verified_cves = []
            seen_cve_ids = set()
            cursor = None
            gh_headers = {"Content-Type": "application/json"}
            gh_token = os.getenv("GITHUB_TOKEN")
            if gh_token:
                gh_headers["Authorization"] = f"Bearer {gh_token}"

            for page in range(MAX_PAGES):
                if len(verified_cves) >= TARGET_COUNT:
                    break
                after_clause = f', after: "{cursor}"' if cursor else ""
                query_body = f"""
                {{
                  securityAdvisories(first: 50, orderBy: {{field: PUBLISHED_AT, direction: DESC}}{after_clause}) {{
                    pageInfo {{ hasNextPage endCursor }}
                    nodes {{
                      ghsaId
                      summary
                      severity
                      publishedAt
                      cvss {{ score vectorString }}
                      cwes(first: 1) {{ nodes {{ cweId name }} }}
                      identifiers {{ type value }}
                    }}
                  }}
                }}
                """
                r = requests.post(
                    "https://api.github.com/graphql",
                    json={"query": query_body},
                    headers=gh_headers,
                    timeout=30
                )
                print(f"DEBUG - GitHub Advisory Status (page {page + 1}): {r.status_code}")
                if r.status_code != 200:
                    break
                payload = r.json().get("data", {}).get("securityAdvisories", {})
                advisories = payload.get("nodes", [])
                page_info = payload.get("pageInfo", {})
                for adv in advisories:
                    if len(verified_cves) >= TARGET_COUNT:
                        break
                    cve_id = None
                    for ident in adv.get("identifiers", []):
                        if ident.get("type") == "CVE":
                            cve_id = ident.get("value")
                            break
                    if not cve_id or not cve_id.startswith("CVE-") or cve_id in seen_cve_ids:
                        continue
                    seen_cve_ids.add(cve_id)
                    if cve_id in seen_ids:
                        print(f" --> [SKIPPED] {cve_id}: already reported in a previous run.")
                        continue
                    summary = adv.get("summary", "No description available.")
                    cvss_score = adv.get("cvss", {}).get("score", "N/A")
                    cvss_severity = adv.get("severity", "N/A").capitalize()
                    cwe_nodes = adv.get("cwes", {}).get("nodes", [])
                    cwe_id = cwe_nodes[0].get("cweId", "N/A") if cwe_nodes else "N/A"
                    published = adv.get("publishedAt", "")[:20]
                    verified_score, verified_severity, cvss_source, verified_vector = verify_cvss(
                        cve_id, cvss_score, cvss_severity
                    )
                    time.sleep(0.3)
                    if verified_vector in (None, "N/A"):
                        verified_vector = "N/A"
                        if verified_score in (None, "N/A"):
                            verified_score = 0.0
                        if cvss_source not in ("cna_official", "tenable_verified"):
                            cvss_source = "ghsa_only"
                    verified_cves.append(
                        f"SOURCE: GHSA | VERIFIED_CVE_ID: {cve_id} | "
                        f"CVSS: {verified_score} | SEVERITY: {verified_severity} | "
                        f"CWE: {cwe_id} | PUBLISHED: {published} | "
                        f"CVSS_SOURCE: {cvss_source} | CVSS_VECTOR: {verified_vector} | "
                        f"DESC: {summary[:500]}"
                    )
                    print(f" --> [KEPT] {cve_id} ({len(verified_cves)}/{TARGET_COUNT})")
                if not page_info.get("hasNextPage"):
                    break
                cursor = page_info.get("endCursor")

            if verified_cves:
                final_cves = verified_cves[:TARGET_COUNT]
                print(f"DEBUG - GitHub Advisory: collected {len(final_cves)} VERIFIED CVEs")
                return "STRICT INSTRUCTION: USE EXACTLY THESE IDs AND SCORES:\n" + "\n".join(final_cves)
            else:
                print("DEBUG - GitHub Advisory: no verified CVEs found after filtering")
        except Exception as e:
            print(f"DEBUG - GitHub Advisory Error: {e}")

        try:
            print("DEBUG - Trying OSV.dev API...")
            osv_cves = []
            for eco in ["PyPI", "npm", "Go", "Maven", "NuGet", "crates.io"]:
                if len(osv_cves) >= DESIRED_CVE_COUNT:
                    break
                try:
                    r = requests.post(
                        "https://api.osv.dev/v1/query",
                        json={"page_size": 10, "query": {"package": {"ecosystem": eco}}},
                        timeout=20
                    )
                    if r.status_code == 200:
                        for vuln in r.json().get("vulns", []):
                            vuln_id = vuln.get("id", "")
                            if not vuln_id.startswith("CVE-"):
                                vuln_id = next(
                                    (a for a in vuln.get("aliases", []) if a.startswith("CVE-")),
                                    None
                                )
                            if not vuln_id:
                                continue
                            if vuln_id in seen_ids:
                                continue
                            published = vuln.get("published", "")[:20]
                            summary = vuln.get("summary", vuln.get("details", "No description."))
                            verified_score, verified_severity, cvss_source, verified_vector = verify_cvss(
                                vuln_id, "N/A", "N/A"
                            )
                            time.sleep(0.3)
                            if verified_vector in (None, "N/A"):
                                verified_vector = "N/A"
                                if verified_score in (None, "N/A"):
                                    verified_score = 0.0
                                if cvss_source not in ("cna_official", "tenable_verified"):
                                    cvss_source = "ghsa_only"
                            osv_cves.append(
                                f"SOURCE: OSV | VERIFIED_CVE_ID: {vuln_id} | "
                                f"CVSS: {verified_score} | SEVERITY: {verified_severity} | "
                                f"PUBLISHED: {published} | CVSS_SOURCE: {cvss_source} | "
                                f"CVSS_VECTOR: {verified_vector} | DESC: {str(summary)[:500]}"
                            )
                except Exception:
                    continue
            if osv_cves:
                print(f"DEBUG - OSV returned {len(osv_cves)} verified CVEs")
                return "STRICT INSTRUCTION: USE EXACTLY THESE IDs:\n" + "\n".join(osv_cves[:DESIRED_CVE_COUNT])
        except Exception as e:
            print(f"DEBUG - OSV Error: {e}")

        return "Failed to fetch CVEs from all sources."

class TenableSearchTool(BaseTool):
    name: str = "Tenable CVE Search Tool"
    description: str = (
        "Parses and cross-references NIST data with Tenable's database. "
        "It updates or overrides missing/incomplete CVSS scores and vectors. "
        "Pass a JSON string containing 'cve_id', 'nist_score', and 'nist_vector'."
    )

    def _run(self, query: str) -> str:
        try:
            try:
                params = json.loads(query)
                cve_id = params.get("cve_id")
                nist_score = params.get("nist_score")
                nist_vector = params.get("nist_vector")
            except json.JSONDecodeError:
                cve_id = query.strip()
                nist_score = "N/A"
                nist_vector = "N/A"
                tenable_data = fetch_tenable_cvss(cve_id)
                if not tenable_data:
                    return f"No alternative data found on Tenable. Retaining NIST values."
                t_score = tenable_data.get("score")
                t_vector = tenable_data.get("vector")
                t_severity = tenable_data.get("severity") or "N/A"
                if nist_score in ["N/A", "0.0", 0.0, None] or nist_vector in ["N/A", "", None]:
                    if t_score is not None and t_vector != "N/A":
                        return json.dumps({
                            "status": "OVERRIDDEN",
                            "reason": "NIST data was missing or incomplete. Successfully updated from Tenable.",
                            "cvss_score": t_score,
                            "cvss_vector": t_vector,
                            "cvss_severity": t_severity,
                            "cvss_source": "tenable_verified"
                        })
                return json.dumps({
                    "status": "VERIFIED",
                    "reason": "NIST data is already accurate and complete.",
                    "cvss_score": nist_score,
                    "cvss_vector": nist_vector,
                    "cvss_source": "nvd_verified"
                })
        except Exception as e:
            return f"Error during Tenable verification: {str(e)}"

nist_tool = NISTSearchTool()
tenable_tool = TenableSearchTool()

scout_llm = LLM(
    model="gemini/gemini-3.5-flash-lite",
    api_key=os.getenv("GEMINI_API_KEY"),
    max_retries=5
)

scout_agent = Agent(
    role='Strict Cyber Threat Data Collector',
    goal=(
        f'Retrieve ONLY real, verified CVEs published recently. '
        f'Today is {today_date}. Never guess or hallucinate any data.'
    ),
    backstory=(
        f'You are a meticulous cybersecurity data collector. Today is {today_date}. '
        f'YOUR ABSOLUTE RULE: NEVER invent CVE IDs, scores, or descriptions. '
        f'ONLY report data exactly as returned by your tools, including the CVSS_SOURCE tag. '
        f'If the tool returns no valid CVE IDs, output exactly: "No real data found."'
    ),
    verbose=True,
    llm=scout_llm,
    tools=[nist_tool, tenable_tool],
    allow_delegation=False
)

live_task = Task(
    description=f'''Follow these exact steps for {today_date}:

    STEP 1: Call the NIST NVD tool with query "recent".
            It will return recent CVEs with their scores and vectors.

    STEP 2: For EACH CVE ID, run the Tenable CVE Verification Tool by passing the CVE ID, current score, and vector.
            If Tenable returns a status of "OVERRIDDEN", you MUST update the fields with the trusted score, vector, and severity provided by Tenable.

    STEP 3: Populate the required data structures strictly according to the Pydantic schema provided.''',
    expected_output='A structured object containing verified and cross-referenced CVE threat records.',
    agent=scout_agent,
    output_pydantic=ScoutReport
)

cyber_crew = Crew(
    agents=[scout_agent],
    tasks=[live_task],
    verbose=True
)

def fetch_otx_native(item: dict) -> dict:
    cve_id = item.get("cve_id")
    item["alienvault_pulse_count"] = 0
    api_key = os.getenv("OTX_API_KEY")
    if not cve_id or not api_key:
        return item
    try:
        url = f"https://otx.alienvault.com/api/v1/search/pulses?q={cve_id}&limit=1"
        r = requests.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=5)
        if r.status_code == 200:
            item["alienvault_pulse_count"] = r.json().get("count", 0)
    except Exception:
        pass
    return item

if __name__ == "__main__":
    scout_start_time = time.time()
    print(f"\n{'='*60}")
    print(f"  Auto-CTI Scout Agent — {today_date}")
    print(f"{'='*60}\n")

    result = cyber_crew.kickoff()

    results_dir = os.path.join(DATA_DIR, "Scout_Agent_Results")
    os.makedirs(results_dir, exist_ok=True)
    report_filename = os.path.join(results_dir, 'cti_report.json')

    try:
        pydantic_output = result.pydantic
        if pydantic_output:
            final_data = pydantic_output.model_dump()
            new_data = final_data.get("vulnerabilities", [])
        else:
            raise ValueError("Pydantic conversion failed")
        print("\n================================================")
        print("Success! Clean Structured Output Received.")
        print("================================================")
    except Exception as e:
        print(f"Warning: Falling back to string parsing due to: {e}")
        raw_result = str(result).strip()
        if raw_result.startswith("```json"):
            raw_result = raw_result[7:]
        if raw_result.startswith("```"):
            raw_result = raw_result[3:]
        if raw_result.endswith("```"):
            raw_result = raw_result[:-3]
        raw_result = raw_result.strip()
        try:
            new_data = json.loads(raw_result).get("vulnerabilities", [])
        except json.JSONDecodeError:
            new_data = []

    if isinstance(new_data, list) and new_data:
        print(f"\n⚡ [Fast Mode] Enriching {len(new_data)} CVEs with AlienVault OTX pulses natively...")
        enriched_data = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_item = {executor.submit(fetch_otx_native, item): item for item in new_data}
            for future in as_completed(future_to_item):
                enriched_data.append(future.result())
        new_data = enriched_data

    # Calculate Scout Agent execution time
    scout_execution_time = time.time() - scout_start_time

    all_reports = {
        today_date: {
            "vulnerabilities": new_data,
            "metadata": {
                "execution_time": scout_execution_time
            }
        }
    }
    with open(report_filename, 'w', encoding='utf-8') as f:
        json.dump(all_reports, f, indent=4, ensure_ascii=False)

    print(f"\nReport saved safely to: {report_filename}")