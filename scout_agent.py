import os
import json
import re
import time
import requests
import datetime
from crewai import Agent, Task, Crew, LLM
from crewai.tools import BaseTool
from dotenv import load_dotenv
import sys

sys.stdout.reconfigure(encoding='utf-8')  # type: ignore

load_dotenv()

today_date = datetime.datetime.now().strftime("%B %d, %Y")
print(f"Scout Agent started. Today: {today_date}")
print(f"Gemini API Key loaded: {bool(os.getenv('GEMINI_API_KEY'))}")
print(f"NVD API Key loaded: {bool(os.getenv('NVD_API_KEY'))}")


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
    """
    Tenable's CVE page structure separates the section header ("CVSS v3")
    from the actual "Base Score:" and "Vector:" lines, with HTML markup and
    other text in between. This strips HTML tags, isolates the CVSS v3
    section specifically (bounded by the next "CVSS v4" or "EPSS" heading
    so the v2 or v4 vector is never picked up by mistake), then extracts
    the score and vector independently within that section.
    """
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

        score_match  = re.search(r'Base\s*Score[\s:*]*([0-9]{1,2}\.[0-9])', section, re.IGNORECASE)
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
    """
    Returns (score, severity, cvss_source, vector).
    Tries three independent sources in priority order before falling back
    to the GHSA-reported (unverified) score:
        1. CVE Services API (cveawg.mitre.org) - the official CNA record
        2. OpenCVE                             - CVSS fallback aggregator
        3. Tenable                             - third-party CVE database,
           often covers CVEs the two sources above have no CVSS for yet
    """
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
        # A CNA record exists but genuinely carries no CVSS score.
        return fallback_score, fallback_severity, "cna_no_cvss", "N/A"

    return fallback_score, fallback_severity, "ghsa_only", "N/A"


class NISTSearchTool(BaseTool):
    name: str = "NIST NVD Recent Search Tool"
    description: str = "Fetches the 20 most recent CVEs published in the last 7 days."

    def _run(self, query: str) -> str:
        headers = {"User-Agent": "Auto-CTI-Agent/1.0"}
        nvd_api_key = os.getenv("NVD_API_KEY")
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key

        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        def parse_nvd_response(data):
            verified_cves = []
            for item in data.get("vulnerabilities", []):
                cve    = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                desc = "No description available."
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", desc)
                        break
                cvss_score    = "N/A"
                cvss_severity = "N/A"
                cvss_vector   = "N/A"
                cwe_id        = "N/A"
                metrics   = cve.get("metrics", {})
                cvss_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                if cvss_list:
                    cvss_data     = cvss_list[0].get("cvssData", {})
                    cvss_score    = cvss_data.get("baseScore", "N/A")
                    cvss_severity = cvss_data.get("baseSeverity", "N/A")
                    cvss_vector   = cvss_data.get("vectorString", "N/A")
                for weakness in cve.get("weaknesses", []):
                    for wd in weakness.get("description", []):
                        if wd.get("lang") == "en":
                            cwe_id = wd.get("value", "N/A")
                            break
                verified_cves.append(
                    f"SOURCE: NVD | VERIFIED_CVE_ID: {cve_id} | "
                    f"CVSS: {cvss_score} | SEVERITY: {cvss_severity} | "
                    f"CWE: {cwe_id} | CVSS_SOURCE: nvd_verified | "
                    f"CVSS_VECTOR: {cvss_vector} | DESC: {desc[:500]}"
                )
            return verified_cves

        try:
            print("DEBUG - Trying NVD (no date filter)...")
            r = requests.get(nvd_url, headers=headers, params={"resultsPerPage": 20}, timeout=30)
            print(f"DEBUG - NVD Status: {r.status_code}")
            if r.status_code == 200:
                cves = parse_nvd_response(r.json())
                if cves:
                    return "STRICT INSTRUCTION: USE EXACTLY THESE IDs AND SCORES:\n" + "\n".join(cves)
        except Exception as e:
            print(f"DEBUG - NVD Error: {e}")

        try:
            end_dt   = datetime.datetime.utcnow()
            start_dt = end_dt - datetime.timedelta(days=7)
            params   = {
                "resultsPerPage":   10,
                "lastModStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S"),
                "lastModEndDate":   end_dt.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            print("DEBUG - Trying NVD (lastModified 7 days)...")
            r = requests.get(nvd_url, headers=headers, params=params, timeout=30)
            print(f"DEBUG - NVD lastMod Status: {r.status_code}")
            if r.status_code == 200:
                cves = parse_nvd_response(r.json())
                if cves:
                    return "STRICT INSTRUCTION: USE EXACTLY THESE IDs AND SCORES:\n" + "\n".join(cves)
        except Exception as e:
            print(f"DEBUG - NVD lastMod Error: {e}")

        try:
            print("DEBUG - Trying GitHub Advisory Database (GraphQL)...")
            query_body = """
            {
              securityAdvisories(first: 30, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
                nodes {
                  ghsaId
                  summary
                  severity
                  publishedAt
                  cvss { score vectorString }
                  cwes(first: 1) { nodes { cweId name } }
                  identifiers { type value }
                  vulnerabilities(first: 1) { nodes { package { name ecosystem } } }
                }
              }
            }
            """
            gh_headers = {"Content-Type": "application/json"}
            gh_token   = os.getenv("GITHUB_TOKEN")
            if gh_token:
                gh_headers["Authorization"] = f"Bearer {gh_token}"

            r = requests.post(
                "https://api.github.com/graphql",
                json={"query": query_body},
                headers=gh_headers,
                timeout=30
            )
            print(f"DEBUG - GitHub Advisory Status: {r.status_code}")

            if r.status_code == 200:
                advisories = (
                    r.json()
                     .get("data", {})
                     .get("securityAdvisories", {})
                     .get("nodes", [])
                )
                verified_cves = []
                for adv in advisories:
                    cve_id = None
                    for ident in adv.get("identifiers", []):
                        if ident.get("type") == "CVE":
                            cve_id = ident.get("value")
                            break
                    if not cve_id or not cve_id.startswith("CVE-"):
                        continue

                    summary       = adv.get("summary", "No description available.")
                    cvss_score    = adv.get("cvss", {}).get("score", "N/A")
                    cvss_severity = adv.get("severity", "N/A").capitalize()
                    cwe_nodes     = adv.get("cwes", {}).get("nodes", [])
                    cwe_id        = cwe_nodes[0].get("cweId", "N/A") if cwe_nodes else "N/A"
                    published     = adv.get("publishedAt", "")[:20]

                    verified_score, verified_severity, cvss_source, verified_vector = verify_cvss(
                        cve_id, cvss_score, cvss_severity
                    )
                    time.sleep(0.3)

                    verified_cves.append(
                        f"SOURCE: GHSA | VERIFIED_CVE_ID: {cve_id} | "
                        f"CVSS: {verified_score} | SEVERITY: {verified_severity} | "
                        f"CWE: {cwe_id} | PUBLISHED: {published} | "
                        f"CVSS_SOURCE: {cvss_source} | CVSS_VECTOR: {verified_vector} | "
                        f"DESC: {summary[:500]}"
                    )

                if verified_cves:
                    final_cves = verified_cves[:20]
                    print(f"DEBUG - GitHub Advisory returned {len(verified_cves)} CVEs, using {len(final_cves)}")
                    return "STRICT INSTRUCTION: USE EXACTLY THESE IDs AND SCORES:\n" + "\n".join(final_cves)
                else:
                    print("DEBUG - GitHub Advisory: no CVE identifiers found in response")

        except Exception as e:
            print(f"DEBUG - GitHub Advisory Error: {e}")

        try:
            print("DEBUG - Trying OSV.dev API...")
            osv_cves = []
            for eco in ["PyPI", "npm", "Go", "Maven", "NuGet", "crates.io"]:
                if len(osv_cves) >= 20:
                    break
                try:
                    r = requests.post(
                        "https://api.osv.dev/v1/query",
                        json={"page_size": 3, "query": {"package": {"ecosystem": eco}}},
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
                            published = vuln.get("published", "")[:20]
                            summary   = vuln.get("summary", vuln.get("details", "No description."))

                            verified_score, verified_severity, cvss_source, verified_vector = verify_cvss(
                                vuln_id, "N/A", "N/A"
                            )
                            time.sleep(0.3)

                            osv_cves.append(
                                f"SOURCE: OSV | VERIFIED_CVE_ID: {vuln_id} | "
                                f"CVSS: {verified_score} | SEVERITY: {verified_severity} | "
                                f"PUBLISHED: {published} | CVSS_SOURCE: {cvss_source} | "
                                f"CVSS_VECTOR: {verified_vector} | DESC: {str(summary)[:500]}"
                            )
                except Exception:
                    continue

            if osv_cves:
                print(f"DEBUG - OSV returned {len(osv_cves)} CVEs")
                return "STRICT INSTRUCTION: USE EXACTLY THESE IDs:\n" + "\n".join(osv_cves[:20])

        except Exception as e:
            print(f"DEBUG - OSV Error: {e}")

        return "Failed to fetch CVEs from all sources."


class AlienVaultOTXTool(BaseTool):
    name: str = "AlienVault OTX Search Tool"
    description: str = (
        "Search AlienVault OTX for active threat pulses for a given CVE ID. "
        "Pass the CVE ID as the query."
    )

    def _run(self, query: str) -> str:
        try:
            api_key = os.getenv("OTX_API_KEY")
            if not api_key:
                return "No active threat pulses found."

            url      = f"https://otx.alienvault.com/api/v1/search/pulses?q={query}&limit=10"
            headers  = {"X-OTX-API-KEY": api_key}
            response = requests.get(url, headers=headers, timeout=20)

            if response.status_code != 200:
                return "No active threat pulses found."

            results = []
            for pulse in response.json().get("results", []):
                pulse_name = pulse.get("name", "N/A")
                tags       = ", ".join(pulse.get("tags", []))
                results.append(f"Pulse: {pulse_name} | Tags: {tags}")

            return "\n".join(results) if results else "No active threat pulses found."

        except Exception:
            # A network hiccup on this enrichment call must NEVER cause the
            # CVE itself to look invalid. Always return a benign, neutral
            # result instead of an alarming error string.
            return "No active threat pulses found."


nist_tool       = NISTSearchTool()
alienvault_tool = AlienVaultOTXTool()

scout_llm = LLM(
    model="gemini/gemini-3.1-flash-lite",
    api_key=os.getenv("GEMINI_API_KEY"),
    max_retries=5  # type: ignore
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
    tools=[nist_tool, alienvault_tool],
    allow_delegation=False
)

live_task = Task(
    description=f'''Follow these exact steps for {today_date}:

    STEP 1: Call the NIST NVD tool with query "recent".
            It will return real CVEs with CVSS scores, CWE IDs, a CVSS_SOURCE tag,
            and a CVSS_VECTOR string (which may be "N/A" if no official vector exists).

    STEP 2: For EACH CVE ID returned, call AlienVault OTX to check for active pulses.

    STEP 3: Compile the final JSON using ONLY data from the tools.
            Do NOT modify CVE IDs, scores, descriptions, the CVSS_SOURCE tag, or the
            CVSS_VECTOR string. Copy CVSS_VECTOR exactly, character for character,
            including when it is "N/A".

    RULES:
    - Use ONLY CVE IDs that start with "CVE-" from the tool output. Never invent IDs.
    - Copy CVSS scores, CWE IDs, CVSS_SOURCE, and CVSS_VECTOR exactly as returned by the tool.
    - Output ONLY a valid JSON array. No markdown, no extra text.
    - If all returned IDs are "N/A" or invalid, output exactly: "No real data found."''',

    expected_output='''[
        {
            "cve_id": "CVE-YYYY-NNNNN",
            "description": "Description...",
            "cvss_score": 9.8,
            "cvss_severity": "Critical",
            "cvss_source": "nvd_verified",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H or N/A",
            "cwe_id": "CWE-89",
            "alienvault_pulses": "Pulse info or No active threat pulses found"
        }
    ]''',
    agent=scout_agent
)

cyber_crew = Crew(
    agents=[scout_agent],
    tasks=[live_task],
    verbose=True
)

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  Auto-CTI Scout Agent — {today_date}")
    print(f"{'='*60}\n")

    result = cyber_crew.kickoff()

    print("\n" + "="*60)
    print("Scout Agent Output:")
    print("="*60)
    print(result)

    results_dir     = os.path.join("JoFile", "Scout_Agent_Results")
    os.makedirs(results_dir, exist_ok=True)
    report_filename = os.path.join(results_dir, 'cti_report.json')

    raw_result = str(result).strip()
    if raw_result.startswith("```json"):
        raw_result = raw_result[7:]
    if raw_result.startswith("```"):
        raw_result = raw_result[3:]
    if raw_result.endswith("```"):
        raw_result = raw_result[:-3]
    raw_result = raw_result.strip()

    try:
        new_data = json.loads(raw_result)
    except json.JSONDecodeError:
        print("Warning: Could not parse output as JSON. Saving raw text.")
        new_data = {"error": "Invalid JSON returned", "raw_text": raw_result}

    all_reports = {today_date: new_data}

    with open(report_filename, 'w', encoding='utf-8') as f:
        json.dump(all_reports, f, indent=4, ensure_ascii=False)

    print(f"\nReport saved to: {report_filename}")