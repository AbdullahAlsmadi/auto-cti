# Copyright 2026 Abdullah Al Smadi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# triage_agent.py — Analyzes raw CVE data using CVSS v3.1, CWE classification,
# MITRE ATT&CK mapping, and multi-source PoC enrichment.
import os
import json
import re
import time
from unittest import result
import requests
import datetime
import sys
import csv
import io
import threading
from crewai import Agent, Task, Crew, LLM
from cvss import CVSS3 
from bs4 import BeautifulSoup 
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.secure_config import init_config

init_config()

sys.stdout.reconfigure(encoding='utf-8')

today_date = datetime.datetime.now().strftime("%B %d, %Y")

DATA_DIR = os.path.expanduser("~/.auto-cti/data")
os.makedirs(DATA_DIR, exist_ok=True)

scout_file_path = os.path.join(DATA_DIR, "Scout_Agent_Results", "cti_report.json")

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

output_dir = os.path.join(DATA_DIR, "triage_agent_result")
os.makedirs(output_dir, exist_ok=True)

MAMORE_DIR = os.path.join(DATA_DIR, "MAMORE")
os.makedirs(MAMORE_DIR, exist_ok=True)

CACHE_FILE = os.path.join(MAMORE_DIR, "triage_cache.json")

cache_lock = threading.Lock()

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_cache(cache_data):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache_data, f, indent=4)

triage_llm = LLM(
    model="gemini/gemini-3.5-flash-lite",
    api_key=os.getenv("GEMINI_API_KEY"),
    max_retries=5
)

def fetch_nvd_cvss(cve_id: str):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"User-Agent": "Auto-CTI-Agent/1.0"}
        nvd_api_key = os.getenv("NVD_API_KEY")
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
        r = requests.get(url, timeout=10, headers=headers)
        if r.status_code != 200:
            return None
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_item = vulns[0].get("cve", {})
        metrics = cve_item.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if not cvss_v3:
            return None
        cvss_data = cvss_v3[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")
        severity = cvss_data.get("baseSeverity")
        if score is not None and vector:
            return {"score": score, "vector": vector, "severity": severity}
        return None
    except Exception:
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
        return None
    except Exception as e:
        print(f"OpenCVE API error for {cve_id}: {e}")
        return None

def fetch_cve_org_cvss(cve_id: str):
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        r = requests.get(url, timeout=10)
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
        return None
    except Exception:
        return None

def fetch_tenable_live_cvss(cve_id: str):
    try:
        url = f"https://www.tenable.com/cve/{cve_id}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        }
        r = requests.get(url, timeout=12, headers=headers)
        if r.status_code != 200:
            print(f"   Tenable status code {r.status_code} for {cve_id}")
            return None
        soup = BeautifulSoup(r.text, 'html.parser')
        text = soup.get_text(separator=' ', strip=True)
        vector_match = re.search(r'(CVSS:3\.[01]/[A-Za-z0-9:/]+)', text)
        if not vector_match:
            vector_match = re.search(r'Vector:?\s*(CVSS:3\.[01]/[A-Za-z0-9:/]+)', text, re.IGNORECASE)
        if not vector_match:
            print(f"   Tenable: no vector found for {cve_id}")
            return None
        vector = vector_match.group(1)
        score_match = re.search(r'Base\s*Score\s*([0-9]{1,2}\.[0-9])', text, re.IGNORECASE)
        if not score_match:
            score_match = re.search(r'Score\s*([0-9]{1,2}\.[0-9])', text, re.IGNORECASE)
        if score_match:
            score = float(score_match.group(1))
        else:
            c = CVSS3(vector)
            base = getattr(c, 'base_score', None)
            try:
                score = float(base) if base is not None else 0.0
            except Exception:
                score = 0.0
        severity_match = re.search(r'Severity\s*(Critical|High|Medium|Low|None)', text, re.IGNORECASE)
        severity = severity_match.group(1).capitalize() if severity_match else "Unknown"
        return {"score": score, "vector": vector, "severity": severity, "page_text": text}
    except Exception as e:
        print(f"   Tenable scraping error for {cve_id}: {e}")
        return None

def verify_tenable_result(cve_id: str, tenable_data: dict, page_text: str) -> bool:
    if not tenable_data:
        return False
    vector = tenable_data.get("vector")
    scraped_score = tenable_data.get("score")
    if cve_id not in page_text:
        print(f"   ⚠️ Tenable check REJECTED for {cve_id}: CVE ID not present on the scraped page.")
        return False
    try:
        c = CVSS3(vector)
        recomputed_score = float(c.base_score)
    except Exception as e:
        print(f"   ⚠️ Tenable check REJECTED for {cve_id}: vector '{vector}' invalid ({e}).")
        return False
    if abs(recomputed_score - float(scraped_score)) > 0.2:
        print(f"   ⚠️ Tenable check REJECTED for {cve_id}: "
              f"scraped score {scraped_score} != vector-derived score {recomputed_score}.")
        return False
    return True

cve_source_lookup = {}
if isinstance(raw_threat_data, list):
    for item in raw_threat_data:
        cid = item.get("cve_id")
        if cid:
            cve_source_lookup[cid] = {
                "cvss_source": item.get("cvss_source", "ghsa_only"),
                "score": item.get("cvss_score"),
                "vector": item.get("cvss_vector", "N/A"),
            }

def verify_and_correct_cvss(entry: dict) -> dict:
    cve_id = entry.get("CVE_ID")
    if not cve_id:
        return entry
    print(f"🔍 Verifying {cve_id} against authoritative sources...")
    official_data = None
    source = None
    nvd_data = fetch_nvd_cvss(cve_id)
    if nvd_data and nvd_data.get("vector") and nvd_data.get("vector") != "N/A":
        official_data = nvd_data
        source = "nvd_verified"
        print(f"   ✅ {cve_id}: Found on NVD (score={official_data['score']})")
    else:
        opencve_data = fetch_opencve_cvss(cve_id)
        if opencve_data and opencve_data.get("vector") and opencve_data.get("vector") != "N/A":
            official_data = opencve_data
            source = "opencve_verified"
            print(f"   ✅ {cve_id}: Found on OpenCVE (score={official_data['score']})")
        else:
            cveorg_data = fetch_cve_org_cvss(cve_id)
            if cveorg_data and cveorg_data.get("vector") and cveorg_data.get("vector") != "N/A":
                official_data = cveorg_data
                source = "cve_org_official"
                print(f"   ✅ {cve_id}: Found on CVE.org (score={official_data['score']})")
            else:
                tenable_data = fetch_tenable_live_cvss(cve_id)
                if (tenable_data and tenable_data.get("vector") and tenable_data.get("vector") != "N/A"
                        and verify_tenable_result(cve_id, tenable_data, tenable_data.get("page_text", ""))):
                    official_data = tenable_data
                    source = "tenable_verified"
                    print(f"   ✅ {cve_id}: Found on Tenable (score={official_data['score']})")
                else:
                    print(f"   ⚠️ {cve_id}: Not found in authoritative sources, keeping estimated values")
                    return entry
    current_score = entry.get("CVSS_Score")
    current_vector = entry.get("CVSS_Vector", "")
    if current_score != official_data["score"] or current_vector != official_data["vector"]:
        print(f"   🔄 {cve_id}: Updating from {current_score}→{official_data['score']}, vector corrected")
        entry["CVSS_Score"] = official_data["score"]
        entry["CVSS_Vector"] = official_data["vector"]
        entry["CVSS_Severity"] = official_data["severity"]
        entry["CVSS_Breakdown"] = parse_cvss_vector(official_data["vector"])
        entry["Score_Source"] = source
    else:
        print(f"   ✅ {cve_id}: Already matches authoritative source")
    return entry

def parse_cvss_vector(vector: str):
    labels = {
        "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low", "H": "High"},
        "PR": {"N": "None", "L": "Low", "H": "High"},
        "UI": {"N": "None", "R": "Required"},
        "S": {"U": "Unchanged", "C": "Changed"},
        "C": {"N": "None", "L": "Low", "H": "High"},
        "I": {"N": "None", "L": "Low", "H": "High"},
        "A": {"N": "None", "L": "Low", "H": "High"},
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
    cvss_source = source_info["cvss_source"]
    vector = source_info.get("vector", "N/A")
    if cvss_source not in ("nvd_verified", "cna_official", "tenable_verified", "opencve_verified", "cve_org_official") or not vector or vector == "N/A":
        return None
    entry["CVSS_Vector"] = vector
    entry["CVSS_Breakdown"] = parse_cvss_vector(vector)
    try:
        c = CVSS3(vector)
        entry["CVSS_Score"] = float(c.base_score)
        entry["CVSS_Severity"] = c.severities()[0].capitalize()
    except Exception:
        entry["CVSS_Score"] = source_info.get("score", entry.get("CVSS_Score"))
    entry["Score_Source"] = cvss_source
    return entry

def map_source_to_score_source(cvss_source: str, was_estimated_by_llm: bool) -> str:
    if cvss_source in ("nvd_verified", "cna_official", "tenable_verified", "opencve_verified", "cve_org_official"):
        return cvss_source
    if cvss_source == "cna_no_cvss":
        return "estimated_no_cna_score"
    return "estimated_unverified"

def recalculate_score_from_vector(entry: dict) -> dict:
    vector = entry.get("CVSS_Vector", "").strip()
    if not vector or vector == "N/A":
        return entry
    if not vector.startswith("CVSS:3."):
        vector = "CVSS:3.1/" + vector.lstrip("/")
    vector = re.sub(r'/+', '/', vector)
    try:
        c = CVSS3(vector)
        base_score = c.base_score
        if base_score is None:
            raise ValueError("CVSS vector produced no base score")
        calculated_score = float(base_score)
        entry["CVSS_Score"] = round(calculated_score, 1)
        entry["CVSS_Severity"] = c.severities()[0].capitalize()
        entry["Score_Source"] = entry.get("Score_Source", "estimated_unverified") + "_recalculated"
    except Exception as e:
        print(f"WARNING: Recalculation failed for {entry.get('CVE_ID', 'unknown')}: {e}")
    return entry

def ensure_severity(entry: dict) -> dict:
    if entry.get("CVSS_Severity") != "Unknown":
        return entry
    vector = entry.get("CVSS_Vector")
    if vector and vector != "N/A":
        try:
            c = CVSS3(vector)
            entry["CVSS_Severity"] = c.severities()[0].capitalize()
            return entry
        except Exception:
            pass
    score = entry.get("CVSS_Score")
    if score is not None:
        if score >= 9.0:
            entry["CVSS_Severity"] = "Critical"
        elif score >= 7.0:
            entry["CVSS_Severity"] = "High"
        elif score >= 4.0:
            entry["CVSS_Severity"] = "Medium"
        elif score >= 0.1:
            entry["CVSS_Severity"] = "Low"
        else:
            entry["CVSS_Severity"] = "None"
    return entry

def is_reference_alive(url: str) -> bool:
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, stream=True)
        r.close()
        return r.status_code != 404   
    except Exception:
        return False   
    
def build_verified_references(cve_id: str) -> list:
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

def recalculate_urgency_score(entry: dict, raw_threat_data: list) -> dict:
    cve_id = entry.get("CVE_ID")
    cvss = entry.get("CVSS_Score")
    if cvss is None:
        return entry
    raw_entry = next((item for item in raw_threat_data if item.get("cve_id") == cve_id), {})
    pulse_count = raw_entry.get("alienvault_pulse_count", 0)
    base = cvss * 9
    if base > 90:
        base = 90
    urgency = base
    if pulse_count > 0:
        urgency += 10
    severity = entry.get("CVSS_Severity", "")
    if severity in ("Low", "None"):
        urgency -= 5
    urgency = int(round(urgency))
    urgency = max(1, min(100, urgency))
    entry["Urgency_Score"] = urgency
    return entry

def fetch_exploit_references(cve_id: str) -> list:
    exploit_tags = {"exploit", "poc", "proof-of-concept", "technical-description", "technical description"}
    found = []
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"User-Agent": "Auto-CTI-Agent/1.0"}
        nvd_api_key = os.getenv("NVD_API_KEY")
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
        r = requests.get(url, timeout=10, headers=headers)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                for ref in vulns[0].get("cve", {}).get("references", []):
                    tags = [t.lower() for t in ref.get("tags", [])]
                    if any(t in exploit_tags for t in tags):
                        found.append(ref.get("url"))
    except Exception as e:
        print(f"   Exploit-ref NVD lookup failed for {cve_id}: {e}")
    if not found:
        try:
            r = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=10)
            if r.status_code == 200:
                cna = r.json().get("containers", {}).get("cna", {})
                for ref in cna.get("references", []):
                    tags = [t.lower() for t in ref.get("tags", [])]
                    if any(t in exploit_tags for t in tags):
                        found.append(ref.get("url"))
        except Exception as e:
            print(f"   Exploit-ref CVE.org lookup failed for {cve_id}: {e}")
    return found

def fetch_github_poc_repos(cve_id: str, cwe_id: str = "") -> list:
    try:
        headers = {"Accept": "application/vnd.github+json"}
        gh_token = os.getenv("GITHUB_TOKEN")
        if gh_token:
            headers["Authorization"] = f"Bearer {gh_token}"
        results = []
        
        # 1. Curated repositories (high confidence)
        curated_repos = [
            "nomi-sec/PoC-in-GitHub",
            "trickest/cve",
            "sirius306/CVE-PoC-Hub",
            "openpoc/openpoc",
            "muratayusuke/known-exploits"
        ]
        for repo in curated_repos:
            query = f'repo:{repo} {cve_id}'
            url = "https://api.github.com/search/code"
            r = requests.get(url, headers=headers, params={"q": query, "per_page": 3}, timeout=15)
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    file_url = item.get("html_url")
                    if file_url and file_url not in results:
                        results.append(file_url)
            time.sleep(0.2)
        if results:
            return results[:5]
        
        # 2. GitHub Advisory Database
        url = f"https://api.github.com/advisories/{cve_id}"
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            references = []
            advisory_url = data.get("html_url")
            if advisory_url:
                references.append(advisory_url)
            for ref in data.get("references", []):
                if ref.get("url"):
                    references.append(ref.get("url"))
            if references:
                return references
        
        # 3. General repository search (with CWE relevance filtering)
        cwe_keywords = _get_cwe_keywords(cwe_id)   # CWE -> keyword mapping
        
        query = f'{cve_id} in:name,description,readme'
        url = "https://api.github.com/search/repositories"
        r2 = requests.get(url, headers=headers, params={"q": query, "sort": "stars", "order": "desc", "per_page": 20}, timeout=15)
        if r2.status_code == 200:
            items = r2.json().get("items", [])
            filtered_repos = []
            for repo in items:
                repo_url = repo.get("html_url")
                if not repo_url or repo_url in results:
                    continue
                name = (repo.get("name") or "").lower()
                desc = (repo.get("description") or "").lower()
                relevant = False
                if not cwe_keywords:
                    if "poc" in desc or "exploit" in desc or "proof of concept" in desc:
                        relevant = True
                else:
                    if any(kw in name or kw in desc for kw in cwe_keywords):
                        relevant = True
                    if not relevant and ("poc" in desc or "exploit" in desc):
                        relevant = True
                if relevant:
                    filtered_repos.append(repo_url)
            results.extend(filtered_repos[:5])

        # 4. Code search fallback
        if len(results) < 3:
            code_query = f'{cve_id} in:file'
            r3 = requests.get("https://api.github.com/search/code", headers=headers, params={"q": code_query, "per_page": 10}, timeout=15)
            if r3.status_code == 200:
                for item in r3.json().get("items", []):
                    file_url = item.get("html_url")
                    if not file_url or file_url in results:
                        continue
                    path = item.get("path", "").lower()
                    if any(ext in path for ext in ["poc", "exploit", "cve", "payload", "rce", "proof"]):
                        results.append(file_url)
                        if len(results) >= 5:
                            break

        return results[:5]

    except Exception as e:
        print(f"   GitHub PoC repo search failed for {cve_id}: {e}")
        return []


# --- CWE-to-keyword mapping for relevance filtering ---
def _get_cwe_keywords(cwe_id: str) -> list:
    if not cwe_id or cwe_id == "N/A":
        return []
    cwe_map = {
        "CWE-79":  ["xss", "cross-site", "injection"],
        "CWE-89":  ["sql", "injection", "sqli"],
        "CWE-502": ["deserialization", "gadget", "serialization"],
        "CWE-119": ["buffer overflow", "memory corruption"],
        "CWE-120": ["buffer overflow", "buffer copy"],
        "CWE-190": ["integer overflow", "overflow"],
        "CWE-787": ["out-of-bounds", "heap overflow"],
        "CWE-416": ["use-after-free", "uaf"],
        "CWE-918": ["ssrf", "request forgery"],
        "CWE-94":  ["code injection", "eval", "rce"],
        "CWE-78":  ["command injection", "os command"],
        "CWE-22":  ["path traversal", "directory traversal"],
        "CWE-862": ["authorization bypass", "access control"],
        "CWE-269": ["privilege escalation", "eop"],
        "CWE-287": ["authentication bypass", "auth bypass"],
    }
    return cwe_map.get(cwe_id, [])

_EXPLOITDB_CSV_CACHE = {"data": None}

def fetch_exploitdb_matches(cve_id: str) -> list:
    if _EXPLOITDB_CSV_CACHE["data"] is None:
        try:
            url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            headers = {"User-Agent": "Auto-CTI-Agent/1.0"}
            r = requests.get(url, timeout=30, headers=headers)
            if r.status_code == 200:
                _EXPLOITDB_CSV_CACHE["data"] = r.text
            else:
                _EXPLOITDB_CSV_CACHE["data"] = ""
        except Exception:
            _EXPLOITDB_CSV_CACHE["data"] = ""
    csv_text = _EXPLOITDB_CSV_CACHE["data"]
    if not csv_text:
        return []
    matches = []
    try:
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            codes = (row.get("codes") or "").upper()
            if cve_id.upper() in codes:
                exploit_id = row.get("id")
                if exploit_id:
                    matches.append(f"https://www.exploit-db.com/exploits/{exploit_id}")
    except Exception:
        pass
    return matches

def fetch_vulners_exploits(cve_id: str) -> list:
    api_key = os.getenv("VULNERS_API_KEY")
    if not api_key:
        return []
    try:
        url = "https://vulners.com/api/v3/search/id"
        payload = {"id": cve_id, "fields": ["*"]}
        headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "Auto-CTI-Agent/1.0"
        }
        r = requests.post(url, json=payload, timeout=15, headers=headers)
        if r.status_code != 200:
            return []
        data = r.json()
        if data.get("result") != "OK":
            return []
        payload_data = data.get("data", {})
        exploits = []
        documents = payload_data.get("documents", {})
        cve_doc = documents.get(cve_id, {})
        for key in ("references", "exploitation"):
            block = cve_doc.get(key)
            if isinstance(block, list):
                for ref in block:
                    if isinstance(ref, str):
                        exploits.append(ref)
                    elif isinstance(ref, dict):
                        href = ref.get("href") or ref.get("url") or ref.get("id")
                        if href:
                            exploits.append(href)
        if exploits:
            return exploits

        # --- Lucene search is gated by environment variable ---
        # To enable, set ENABLE_VULNERS_LUCENE=true in ~/.auto-cti/.env
        if os.getenv("ENABLE_VULNERS_LUCENE", "false").lower() == "true":
            search_url = "https://vulners.com/api/v3/search/lucene/"
            query = f'cve:"{cve_id}" AND type:exploit'
            search_payload = {"query": query, "size": 10}
            r2 = requests.post(search_url, json=search_payload, headers=headers, timeout=15)
            if r2.status_code == 200:
                data2 = r2.json()
                if data2.get("result") == "OK":
                    hits = data2.get("data", {}).get("search", [])
                    for hit in hits:
                        source = hit.get("_source", {})
                        href = source.get("href") or source.get("vhref")
                        if href:
                            exploits.append(href)
        # If disabled, simply return whatever we have (likely empty)
        return exploits
    except Exception:
        return []

def fetch_packetstorm_exploits(cve_id: str) -> list:
    try:
        search_url = "https://packetstormsecurity.com/search/"
        params = {"q": cve_id, "type": "exploit"}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }
        r = requests.get(search_url, params=params, timeout=15, headers=headers)
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, 'html.parser')
        exploits = []
        for link in soup.find_all('a', href=True):
            href = str(link.get('href', ''))
            if ('/files/' in href or '/exploits/' in href) and 'latest' not in href and 'index' not in href and 'search' not in href and '?' not in href:
                full_url = href if href.startswith('http') else f"https://packetstormsecurity.com{href}"
                if full_url not in exploits:
                    exploits.append(full_url)
        return exploits[:5]
    except Exception:
        return []

def fetch_inthewild_exploits(cve_id: str) -> list:
    try:
        url = "https://inthewild.io/api/exploited"
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        refs = []
        for item in data:
            if item.get('id') == cve_id:
                refs.append(f"https://inthewild.io/vuln/{cve_id}")
                for key in ['exploit_links', 'reference_urls']:
                    if key in item and isinstance(item[key], list):
                        refs.extend(item[key])
                break
        return list(set(refs))
    except Exception:
        return []

def fetch_sploitus_exploits(cve_id: str) -> list:
    try:
        url = f"https://sploitus.com/search/?q={cve_id}"
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, timeout=10, headers=headers)
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, 'html.parser')
        refs = []
        for result in soup.find_all('div', class_='result'):
            link = result.find('a', class_='title')
            if link and link.get('href'):
                href = link['href']
                if href.startswith('/'):
                    href = f"https://sploitus.com{href}"
                if href not in refs:
                    refs.append(href)
        return refs[:5]
    except Exception:
        return []

def fetch_0daytoday_exploits(cve_id: str) -> list:
    try:
        url = f"https://raw.githubusercontent.com/vulncheck-oss/0day-today-archive/main/{cve_id}.json"
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        refs = []
        for entry in data.get("exploits", []):
            if entry.get("url"):
                refs.append(entry["url"])
        return refs[:5]
    except Exception:
        return []

def fetch_google_osint_poc(cve_id: str) -> list:
    api_key = os.getenv("GOOGLE_SEARCH_API_KEY")
    cx = os.getenv("GOOGLE_SEARCH_CX")
    if not api_key or not cx:
        return []
    try:
        query = f'"{cve_id}" (PoC OR exploit) (site:github.com OR site:twitter.com OR site:x.com)'
        url = f"https://www.googleapis.com/customsearch/v1?q={query}&key={api_key}&cx={cx}&num=3"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            items = r.json().get("items", [])
            return [item["link"] for item in items]
    except Exception as e:
        print(f"   [OSINT Error] Google Search failed for {cve_id}: {e}")
    return []

def check_rapid7_db(cve_id: str) -> list:
    url = f"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/multi/http/{cve_id.replace('-', '_')}.rb"
    try:
        response = requests.head(url, timeout=3)
        if response.status_code == 200:
            return [f"https://github.com/rapid7/metasploit-framework/search?q={cve_id}"]
    except Exception:
        pass
    return []

def check_seebug(cve_id: str) -> list:
    search_url = f"https://www.seebug.org/search/?keyword={cve_id}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(search_url, headers=headers, timeout=5)
        if "ssv-" in response.text.lower():
            return [search_url]
    except Exception:
        pass
    return []

def fetch_patch_diff(cve_id: str) -> str:
    try:
        r = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=10)
        if r.status_code == 200:
            cna = r.json().get("containers", {}).get("cna", {})
            for ref in cna.get("references", []):
                url = ref.get("url", "")
                if "github.com" in url and "/commit/" in url:
                    diff_url = url + ".diff"
                    diff_req = requests.get(diff_url, timeout=10)
                    if diff_req.status_code == 200:
                        return diff_req.text[:3000]
    except Exception:
        pass
    return ""

def analyze_diff_with_llm(cve_id: str, diff_text: str) -> str:
    llm = triage_llm   # defined at top of file
    prompt = f"""You are a senior reverse engineer. Analyze this Git patch diff for {cve_id}.
Write exactly 4 sentences explaining the technical vulnerability and a theoretical
attack vector based on what was changed in the code.
Focus on the specific functions, variables, and logic modified. Do not include exploit code.

Diff:
{diff_text}"""
    try:
        response = llm(prompt)   # ✅ Correct method
        # CrewAI's LLM may return a string or an object with .content
        report_text = response.content if hasattr(response, 'content') else str(response)
        return report_text.strip()
    except Exception as e:
        print(f"   [LLM Error] Diff analysis failed for {cve_id}: {e}")
        return "No public exploit code is currently available. The theoretical attack path below is derived from vulnerability mechanics:"
    
def enhance_poc(entry: dict) -> dict:
    import os  # ensure os is available (it should already be imported at top)
    poc = entry.get("PoC", "")
    cve_id = entry.get("CVE_ID", "")
    print(f"\n🔎 Checking PoC / exploit references for {cve_id}...")
    if "Verified Exploit" in poc or "Theoretical Attack Vector" in poc:
        print(f"   ⏭️  {cve_id}: Already enriched in a previous pass, skipping.")
        entry["_poc_gap"] = False
        return entry
        
    print(f"   [1/12] Searching NVD / CVE Services API for tagged Exploit references...")
    exploit_refs = fetch_exploit_references(cve_id) if cve_id else []
    time.sleep(0.3)
    source_label = "nvd_cve_org_reference"
    
    if exploit_refs:
        print(f"   ✅ {cve_id}: Found {len(exploit_refs)} reference(s) on NVD/CVE.org.")
    else:
        print(f"   [2/12] Searching GitHub for public PoC repositories...")
        exploit_refs = fetch_github_poc_repos(cve_id, entry.get("CWE_ID", "")) if cve_id else []
        time.sleep(0.3)
        source_label = "github_poc_repo"
        if exploit_refs:
            print(f"   ✅ {cve_id}: Found {len(exploit_refs)} GitHub PoC repo(s).")
        else:
            print(f"   [3/12] Searching Vulners aggregated exploit index...")
            exploit_refs = fetch_vulners_exploits(cve_id) if cve_id else []
            time.sleep(0.3)
            source_label = "vulners_exploit"
            if exploit_refs:
                print(f"   ✅ {cve_id}: Found {len(exploit_refs)} Vulners exploit entry(ies).")
            else:
                print(f"   [4/12] Searching Packet Storm Security for exploits...")
                exploit_refs = fetch_packetstorm_exploits(cve_id) if cve_id else []
                source_label = "packetstorm_exploit"
                if exploit_refs:
                    print(f"   ✅ {cve_id}: Found {len(exploit_refs)} exploit(s) on Packet Storm.")
                else:
                    print(f"   [5/12] Checking inTheWild.io for exploit references...")
                    exploit_refs = fetch_inthewild_exploits(cve_id) if cve_id else []
                    source_label = "inthewild_exploit"
                    if exploit_refs:
                        print(f"   ✅ {cve_id}: Found {len(exploit_refs)} reference(s) on inTheWild.io.")
                    else:
                        # --- Sploitus is gated by environment variable ---
                        # To enable Sploitus, set ENABLE_SPLOITUS=true in ~/.auto-cti/.env
                        if os.getenv("ENABLE_SPLOITUS", "false").lower() == "true":
                            print(f"   [6/12] Searching Sploitus (aggregator) for exploits...")
                            exploit_refs = fetch_sploitus_exploits(cve_id) if cve_id else []
                            source_label = "sploitus_exploit"
                            if exploit_refs:
                                print(f"   ✅ {cve_id}: Found {len(exploit_refs)} exploit(s) on Sploitus.")
                            else:
                                print(f"   [7/12] Sploitus found nothing. Checking 0day.today archive...")
                                exploit_refs = fetch_0daytoday_exploits(cve_id) if cve_id else []
                                source_label = "zeroday_exploit"
                                if exploit_refs:
                                    print(f"   ✅ {cve_id}: Found {len(exploit_refs)} exploit(s) in 0day.today archive.")
                                else:
                                    print(f"   [8/12] Falling back to Exploit-DB index...")
                                    exploit_refs = fetch_exploitdb_matches(cve_id) if cve_id else []
                                    source_label = "exploitdb_verified"
                                    if exploit_refs:
                                        print(f"   ✅ {cve_id}: Found {len(exploit_refs)} Exploit-DB entry(ies).")
                                    else:
                                        print(f"   [9/12] Checking Live OSINT (Google Custom Search)...")
                                        exploit_refs = fetch_google_osint_poc(cve_id) if cve_id else []
                                        source_label = "google_osint_live"
                                        if exploit_refs:
                                            print(f"   ✅ {cve_id}: Found {len(exploit_refs)} live OSINT reference(s).")
                                        else:
                                            print(f"   [10/12] Checking Rapid7 Metasploit database...")
                                            exploit_refs = check_rapid7_db(cve_id) if cve_id else []
                                            source_label = "rapid7_metasploit"
                                            if exploit_refs:
                                                print(f"   ✅ {cve_id}: Found Rapid7 module.")
                                            else:
                                                print(f"   [11/12] Checking Seebug database...")
                                                exploit_refs = check_seebug(cve_id) if cve_id else []
                                                source_label = "seebug_exploit"
                                                if exploit_refs:
                                                    print(f"   ✅ {cve_id}: Found reference on Seebug.")
                                                else:
                                                    print(f"   [12/12] No external PoC. Attempting Patch Diffing / Reverse Engineering...")
                                                    diff_text = fetch_patch_diff(cve_id) if cve_id else ""
                                                    if diff_text:
                                                        print(f"   ✅ {cve_id}: Found GitHub commit diff. Analyzing root cause via Gemini...")
                                                        analysis = analyze_diff_with_llm(cve_id, diff_text)
                                                        entry["PoC"] = analysis + "\n\n**Theoretical Attack Vector (Reverse-Engineered from Patch)**"
                                                        entry["PoC_Source"] = "patch_reverse_engineering"
                                                        entry["_poc_gap"] = False
                                                        return entry
                        else:
                            # Sploitus is disabled – skip directly to 0day.today
                            print(f"   [6/12] Skipping Sploitus (disabled). Checking 0day.today archive...")
                            exploit_refs = fetch_0daytoday_exploits(cve_id) if cve_id else []
                            source_label = "zeroday_exploit"
                            if exploit_refs:
                                print(f"   ✅ {cve_id}: Found {len(exploit_refs)} exploit(s) in 0day.today archive.")
                            else:
                                print(f"   [7/12] Falling back to Exploit-DB index...")
                                exploit_refs = fetch_exploitdb_matches(cve_id) if cve_id else []
                                source_label = "exploitdb_verified"
                                if exploit_refs:
                                    print(f"   ✅ {cve_id}: Found {len(exploit_refs)} Exploit-DB entry(ies).")
                                else:
                                    print(f"   [8/12] Checking Live OSINT (Google Custom Search)...")
                                    exploit_refs = fetch_google_osint_poc(cve_id) if cve_id else []
                                    source_label = "google_osint_live"
                                    if exploit_refs:
                                        print(f"   ✅ {cve_id}: Found {len(exploit_refs)} live OSINT reference(s).")
                                    else:
                                        print(f"   [9/12] Checking Rapid7 Metasploit database...")
                                        exploit_refs = check_rapid7_db(cve_id) if cve_id else []
                                        source_label = "rapid7_metasploit"
                                        if exploit_refs:
                                            print(f"   ✅ {cve_id}: Found Rapid7 module.")
                                        else:
                                            print(f"   [10/12] Checking Seebug database...")
                                            exploit_refs = check_seebug(cve_id) if cve_id else []
                                            source_label = "seebug_exploit"
                                            if exploit_refs:
                                                print(f"   ✅ {cve_id}: Found reference on Seebug.")
                                            else:
                                                print(f"   [11/12] No external PoC. Attempting Patch Diffing / Reverse Engineering...")
                                                diff_text = fetch_patch_diff(cve_id) if cve_id else ""
                                                if diff_text:
                                                    print(f"   ✅ {cve_id}: Found GitHub commit diff. Analyzing root cause via Gemini...")
                                                    analysis = analyze_diff_with_llm(cve_id, diff_text)
                                                    entry["PoC"] = analysis + "\n\n**Theoretical Attack Vector (Reverse-Engineered from Patch)**"
                                                    entry["PoC_Source"] = "patch_reverse_engineering"
                                                    entry["_poc_gap"] = False
                                                    return entry

    if exploit_refs:
        note = "\n\n**Verified Exploit / Technical References:**\n" + \
               "\n".join(f"- {u}" for u in exploit_refs)
        entry["PoC"] = poc + note
        entry["PoC_Source"] = source_label
        entry["_poc_gap"] = False
        print(f"   📌 {cve_id}: PoC enriched via [{source_label}].")
    else:
        entry["PoC"] = poc + "\n\n**Theoretical Attack Vector (No Public Exploit Found)**"
        entry["PoC_Source"] = "llm_only"
        entry["_poc_gap"] = True
        print(f"   ⚠️  {cve_id}: GENUINE PoC GAP — no external reference or patch found.")
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
if os.path.exists(output_file_path):
    os.remove(output_file_path)
    print(f"Removed old report before regenerating: {output_file_path}")

summary_data = []
for item in raw_threat_data:
    summary_data.append({
        "cve_id": item.get("cve_id"),
        "description": item.get("description", "")[:150],
        "cvss_score": item.get("cvss_score"),
        "cvss_vector": item.get("cvss_vector", "N/A"),
        "cvss_source": item.get("cvss_source", "ghsa_only")
    })
summary_json = json.dumps(summary_data, indent=2)

triage_task = Task(
    description=f'''You are analyzing CVE threat data collected on {today_date}.

MANDATORY: The input contains exactly {cve_count} CVE entries. You MUST produce exactly {cve_count} objects in your output array. Do NOT stop early. Do NOT skip any entry. Process every single one.

RAW THREAT DATA (summarised – use these values exactly as given):
{summary_json}

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
- The JSON must be parseable by Python json.loads() without any cleanup.

For EACH CVE, you MUST write a 3-sentence professional description. Do NOT omit this.
''',
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
    triage_start_time = time.time()
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

        def process_entry(entry):
            cve_id = entry.get("CVE_ID") or entry.get("cve_id") or ""
            entry["CVE_ID"] = cve_id
            
            with cache_lock:
                cache = load_cache()
                if cve_id in cache:
                    print(f"   [+] CACHE HIT: Skipping enrichment API calls for {cve_id}")
                    return cache[cve_id]
            
            if not entry.get("Description") or entry["Description"] == "No description available.":
                raw_desc = next((item.get("description") for item in raw_threat_data if item.get("cve_id") == cve_id), "")
                if raw_desc:
                    entry["Description"] = raw_desc
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
            entry = verify_and_correct_cvss(entry)
            entry = ensure_severity(entry)
            entry = recalculate_urgency_score(entry, raw_threat_data)
            entry = enhance_poc(entry)
            print(f"AFTER RECALC: {entry['CVE_ID']} -> score={entry['CVSS_Score']} vector={entry['CVSS_Vector']}")
            entry["References"] = build_verified_references(cve_id)
            
            with cache_lock:
                cache = load_cache()
                cache[cve_id] = entry
                save_cache(cache)
                
            return entry

        fixed_entries = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_entry = {executor.submit(process_entry, entry): entry for entry in parsed}
            for future in as_completed(future_to_entry):
                try:
                    result_entry = future.result()
                    fixed_entries.append(result_entry)
                except Exception as e:
                    print(f"Error processing entry: {e}")

        for entry in fixed_entries:
            if entry.get("CVSS_Severity") == "Unknown":
                entry = ensure_severity(entry)

        repo_to_cves = {}
        for entry in fixed_entries:
            if entry.get("PoC_Source") != "github_poc_repo":
                continue
            for line in entry.get("PoC", "").splitlines():
                stripped = line.strip()
                if stripped.startswith("- [https://github.com/](https://github.com/)"):
                    repo_url = stripped[2:].strip()
                    repo_to_cves.setdefault(repo_url, set()).add(entry["CVE_ID"])

        SUSPICIOUS_THRESHOLD = 2
        suspicious_repos = {url for url, cves in repo_to_cves.items() if len(cves) >= SUSPICIOUS_THRESHOLD}
        if suspicious_repos:
            print(f"DEBUG - Flagged {len(suspicious_repos)} likely aggregator repo(s) matched across multiple CVEs:")
            for url in suspicious_repos:
                print(f"   {url} -> matched {sorted(repo_to_cves[url])}")

        for entry in fixed_entries:
            if entry.get("PoC_Source") != "github_poc_repo":
                continue
            lines = entry.get("PoC", "").splitlines()
            kept_lines = []
            removed_any = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("- https://github.com/")and stripped[2:].strip() in suspicious_repos:
                    removed_any = True
                    continue
                kept_lines.append(line)
            if removed_any:
                remaining_refs = [l for l in kept_lines if l.strip().startswith("- [https://github.com/](https://github.com/)")]
                if remaining_refs:
                    entry["PoC"] = "\n".join(kept_lines)
                else:
                    header_idx = next(
                        (i for i, l in enumerate(kept_lines) if "Verified Exploit" in l), None
                    )
                    if header_idx is not None:
                        del kept_lines[max(header_idx - 2, 0):header_idx + 1]
                    entry["PoC"] = "\n".join(kept_lines).rstrip() + "\n\n**Theoretical Attack Vector (No Public Exploit Found)**"
                    entry["PoC_Source"] = "llm_only"
                    entry["_poc_gap"] = True
                    print(f"   ⚠️  {entry['CVE_ID']}: reverted to PoC gap — only match was an aggregator repo.")

        poc_gaps = []
        for entry in fixed_entries:
            if entry.pop("_poc_gap", False):
                poc_gaps.append(entry.get("CVE_ID"))

        gap_reports_dir = os.path.join(DATA_DIR, "PoC_Gap_Reports")
        os.makedirs(gap_reports_dir, exist_ok=True)
        gap_report_path = os.path.join(gap_reports_dir, f'PoC_Gap_Report_{today_date}.json')
        with open(gap_report_path, 'w', encoding='utf-8') as f:
            json.dump({
                "date": today_date,
                "total_cves": len(fixed_entries),
                "poc_gaps_count": len(poc_gaps),
                "poc_gaps_cve_ids": poc_gaps,
            }, f, indent=2, ensure_ascii=False)
        print(f"DEBUG - PoC gap report saved: {gap_report_path} ({len(poc_gaps)}/{len(fixed_entries)} unmatched)")

        triage_execution_time = time.time() - triage_start_time
        
        final_output = {
            "date": today_date,
            "report": fixed_entries,
            "metadata": {
                "execution_time": triage_execution_time
            }
        }

        with open(output_file_path, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False)
        print(f"Triage report saved: {output_file_path}")
        print(f"Total CVEs triaged: {len(fixed_entries)}")

    except json.JSONDecodeError as e:
        print(f"Warning: Could not parse output as clean JSON: {e}")
        print("Saving raw output as fallback...")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(raw_result)
        print(f"Raw output saved: {output_file_path}")

