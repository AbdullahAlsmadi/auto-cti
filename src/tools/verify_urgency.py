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
# verify_urgency.py — Recomputes the Urgency Score of every triaged CVE and
# compares it with the stored value, to verify the deterministic formula.
#
# Usage:
#   python verify_urgency.py                  -> checks ~/.auto-cti/data
#   python verify_urgency.py "<runs folder>"  -> checks a folder of runs
#                                               (1th/, 2th/, ... each holding
#                                               cti_report.json + Triaged_Report_*.json)
import os
import re
import sys
import glob
import json

DEFAULT_ROOT = os.path.expanduser("~/.auto-cti/data")

def expected_urgency(cvss, severity, pulse_count):
    """Same formula as recalculate_urgency_score() in triage_agent.py."""
    base = min (90, cvss * 9)
    if pulse_count > 0:
          base += 10
    if severity in ("Low", "None"):
         base -= 5
    return max(1, min(100, int(round(base))))


def find_runs(root):
    """Return a list of (name, scout_json_path, triage_json_path)."""
    runs = []

    # Layout A: the installed system's data directory
    triage = glob.glob(os.path.join(root, "triage_agent_result", "Triaged_Report_*.json"))
    scout = os.path.join(root, "Scout_Agent_Results", "cti_report.json")
    if triage and os.path.exists(scout):
        runs.append(("latest run", scout, max(triage, key=os.path.getctime)))
        return runs

     # Layout B: a folder of runs (1th, 2th, ...)
    def natural_key(path):
        m = re.match(r"(\d+)", os.path.basename(path))
        return int(m.group(1)) if m else 0

    for sub in sorted(glob.glob(os.path.join(root, "*")), key=natural_key):
        triage = glob.glob(os.path.join(sub, "Triaged_Report_*.json"))
        scout = os.path.join(sub, "cti_report.json")
        if os.path.isdir(sub) and triage and os.path.exists(scout):
            runs.append((os.path.basename(sub), scout, triage[0]))
    return runs

def load_pulses(scout_path):
    """Map cve_id -> alienvault_pulse_count from the Scout output."""
    pulses = {}
    with open(scout_path, encoding="utf-8") as f:
        data = json.load(f)
    for day in data.values():
        for v in day.get("vulnerabilities", []):
            pulses[v.get("cve_id")] = v.get("alienvault_pulse_count", 0)
    return pulses

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ROOT
    runs = find_runs(root)
    if not runs:
        print(f"No runs found under: {root}")
        sys.exit(2)

    total, mismatches = 0, []
    for name, scout_path, triage_path in runs:
        pulses = load_pulses(scout_path)
        with open(triage_path, encoding="utf-8") as f:
            report = json.load(f)["report"]
        bad = 0
        for e in report:
            total += 1
            exp = expected_urgency(e["CVSS_Score"], e["CVSS_Severity"],
                                   pulses.get(e["CVE_ID"], 0))
            if exp != e["Urgency_Score"]:
                bad += 1
                mismatches.append((name, e["CVE_ID"], e["CVSS_Score"],
                                   e["Urgency_Score"], exp))
        print(f"{name}: {len(report)} CVEs, {bad} mismatches")

    print(f"\nTotal checked: {total}, mismatches: {len(mismatches)}")
    for m in mismatches:
        print("  run=%s %s cvss=%s stored=%s expected=%s" % m)
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()