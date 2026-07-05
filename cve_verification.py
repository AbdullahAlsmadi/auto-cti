"""
cve_verification.py

STANDALONE TEST SCRIPT (Step 1).

Purpose:
    Cross-check the CVSS score/vector we get from GitHub Advisory (the current
    fallback source in scout_agent.py) against two official, free sources:

        1) CVE Services API (cveawg.mitre.org) - the authoritative CNA
           Container data. Public GET requests, no API key required.
        2) OpenCVE.io API - aggregates CVSS data from multiple providers
           (MITRE, NVD, Vulnrichment, etc). Requires a free account
           (Basic Auth), no payment needed.

This script does NOT touch scout_agent.py yet. Run it manually first to
confirm the discrepancies you found on Tenable are visible here too, using
the same CVE IDs from your PDF report.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

OPENCVE_USERNAME = os.getenv("OPENCVE_USERNAME")
OPENCVE_PASSWORD = os.getenv("OPENCVE_PASSWORD")

CVE_SERVICES_BASE_URL = "https://cveawg.mitre.org/api/cve"
OPENCVE_BASE_URL = "https://app.opencve.io/api/cve"


def get_cna_record(cve_id: str) -> dict:
    """
    Fetch the official CNA Container record directly from the CVE Program's
    own database. This is the record as submitted by the CNA responsible for
    the CVE (e.g. GitHub, Erlef, Red Hat), and it is the ground-truth source
    that both NVD and GHSA are ultimately derived from.

    Returns a dict with score, vector, and severity, or an error message.
    """
    url = f"{CVE_SERVICES_BASE_URL}/{cve_id}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            return {"error": f"CVE Services returned status {response.status_code}"}

        data = response.json()
        cna_container = data.get("containers", {}).get("cna", {})
        metrics_list = cna_container.get("metrics", [])

        for metric_entry in metrics_list:
            # The CNA can report CVSS v3.1 or v3.0 metrics under different keys
            for cvss_key in ("cvssV3_1", "cvssV3_0"):
                cvss_data = metric_entry.get(cvss_key)
                if cvss_data:
                    return {
                        "source": "CVE_Services_CNA",
                        "cvss_score": cvss_data.get("baseScore"),
                        "cvss_vector": cvss_data.get("vectorString"),
                        "severity": cvss_data.get("baseSeverity"),
                    }

        return {"error": "No CVSS metrics found in CNA container for this CVE"}

    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}


def get_opencve_record(cve_id: str) -> dict:
    """
    Fetch the aggregated CVE record from OpenCVE, which cross-references
    MITRE, NVD, and Vulnrichment data in a single response. Used as a
    secondary, independent cross-check against the CNA record above.
    """
    if not OPENCVE_USERNAME or not OPENCVE_PASSWORD:
        return {"error": "OPENCVE_USERNAME / OPENCVE_PASSWORD missing in .env"}

    url = f"{OPENCVE_BASE_URL}/{cve_id}"
    try:
        response = requests.get(
            url,
            auth=(OPENCVE_USERNAME, OPENCVE_PASSWORD),
            timeout=15
        )
        if response.status_code != 200:
            return {"error": f"OpenCVE returned status {response.status_code}"}

        data = response.json()
        metrics = data.get("metrics", {})
        cvss_31 = metrics.get("cvssV3_1", {})
        cvss_data = cvss_31.get("data", {})

        if not cvss_data:
            return {"error": "No CVSS v3.1 data found in OpenCVE record"}

        return {
            "source": "OpenCVE",
            "cvss_score": cvss_data.get("score"),
            "cvss_vector": cvss_data.get("vector"),
            "provider": cvss_31.get("provider"),
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}


def compare_cvss(cve_id: str, github_score, github_vector: str = "N/A") -> dict:
    """
    Compares the score currently produced by the Scout Agent (from GitHub
    Advisory) against both official sources, and reports whether they agree.

    A discrepancy is flagged if the scores differ by more than 0.5 points,
    which is enough to shift a CVE into a different severity band.
    """
    cna_result = get_cna_record(cve_id)
    opencve_result = get_opencve_record(cve_id)

    result = {
        "CVE_ID": cve_id,
        "GitHub_Advisory_Score": github_score,
        "GitHub_Advisory_Vector": github_vector,
        "CNA_Official_Score": cna_result.get("cvss_score", "N/A"),
        "CNA_Official_Vector": cna_result.get("cvss_vector", "N/A"),
        "OpenCVE_Score": opencve_result.get("cvss_score", "N/A"),
        "CNA_Error": cna_result.get("error"),
        "OpenCVE_Error": opencve_result.get("error"),
    }

    scores_to_check = [
        s for s in (result["CNA_Official_Score"], result["OpenCVE_Score"])
        if isinstance(s, (int, float))
    ]

    if isinstance(github_score, (int, float)) and scores_to_check:
        max_diff = max(abs(github_score - s) for s in scores_to_check)
        result["Discrepancy_Detected"] = max_diff > 0.5
        result["Max_Score_Difference"] = round(max_diff, 2)
    else:
        result["Discrepancy_Detected"] = "Unable to compare (missing data)"
        result["Max_Score_Difference"] = None

    return result


if __name__ == "__main__":
    # Test cases taken directly from your PDF report — CVEs you flagged as
    # suspicious after checking Tenable manually.
    test_cases = [
        {"cve_id": "CVE-2026-50566", "github_score": 9.9, "github_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
        {"cve_id": "CVE-2026-48592", "github_score": 9.1, "github_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"},
        {"cve_id": "CVE-2026-49478", "github_score": 9.8, "github_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    ]

    print("=" * 70)
    print("CVSS VERIFICATION TEST — comparing GitHub Advisory vs official sources")
    print("=" * 70)

    for case in test_cases:
        result = compare_cvss(
            cve_id=case["cve_id"],
            github_score=case["github_score"],
            github_vector=case["github_vector"]
        )
        print(f"\n{result['CVE_ID']}")
        print(f"  GitHub Advisory Score : {result['GitHub_Advisory_Score']}")
        print(f"  CNA Official Score    : {result['CNA_Official_Score']}")
        print(f"  OpenCVE Score         : {result['OpenCVE_Score']}")
        print(f"  Discrepancy Detected  : {result['Discrepancy_Detected']}")
        if result.get("CNA_Error"):
            print(f"  [CNA Error]     {result['CNA_Error']}")
        if result.get("OpenCVE_Error"):
            print(f"  [OpenCVE Error] {result['OpenCVE_Error']}")