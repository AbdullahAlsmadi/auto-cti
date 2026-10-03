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
#   auto-cti -v                       -> checks the accumulated triage cache
#                                        (all CVEs processed so far)
#   auto-cti -v /full/path/cache.json -> checks a specific cache file
#   auto-cti -v /full/path/runs_dir   -> checks a folder of archived runs
#                                        (each holding cti_report.json +
#                                        Triaged_Report_*.json)
import os
import re
import sys
import glob
import json

DATA_DIR = os.path.expanduser("~/.auto-cti/data")
CACHE_PATH = os.path.join(DATA_DIR, "MAMORE", "triage_cache.json")
SCOUT_PATH = os.path.join(DATA_DIR, "Scout_Agent_Results", "cti_report.json")


def expected_urgency(cvss, severity, pulse_count):
    """Same formula as recalculate_urgency_score() in triage_agent.py."""
    base = min(90, cvss * 9)            # base = CVSS x 9, capped at 90
    if pulse_count > 0:                 # +10 if AlienVault OTX pulses exist
        base += 10
    if severity in ("Low", "None"):     # -5 for Low / None severity
        base -= 5
    return max(1, min(100, int(round(base))))   # clamp to [1, 100]


def load_pulses(scout_path):
    """Map cve_id -> alienvault_pulse_count (empty dict if unavailable)."""
    pulses = {}
    try:
        with open(scout_path, encoding="utf-8") as f:
            data = json.load(f)
        for day in data.values():
            for v in day.get("vulnerabilities", []):
                pulses[v.get("cve_id")] = v.get("alienvault_pulse_count", 0)
    except (OSError, ValueError, AttributeError):
        pass
    return pulses


def check_entries(entries, pulses):
    """Compare stored vs recomputed Urgency for a list of triage entries.

    Returns (stats, mismatches). When the OTX pulse count of a CVE is
    unknown, a stored value is accepted if it matches the formula with or
    without the +10 pulse bonus, and is counted separately.
    """
    stats = {"exact": 0, "pulse_unknown_ok": 0,
             "pulse_unknown_bonus_only": 0, "skipped": 0}
    mismatches = []
    for e in entries:
        try:
            cve = e["CVE_ID"]
            cvss = float(e["CVSS_Score"])
            sev = e.get("CVSS_Severity", "")
            stored = int(e["Urgency_Score"])
        except (KeyError, TypeError, ValueError):
            stats["skipped"] += 1
            continue

        if cve in pulses:                       # pulse count known: exact check
            exp = expected_urgency(cvss, sev, pulses[cve])
            if stored == exp:
                stats["exact"] += 1
            else:
                mismatches.append((cve, cvss, stored, str(exp)))
        else:                                   # pulse count unknown
            without = expected_urgency(cvss, sev, 0)
            with_bonus = expected_urgency(cvss, sev, 1)
            if stored == without:
                stats["pulse_unknown_ok"] += 1
            elif stored == with_bonus:
                stats["pulse_unknown_bonus_only"] += 1
            else:
                mismatches.append((cve, cvss, stored, f"{without} or {with_bonus}"))
    return stats, mismatches


def load_cache_entries(path):
    """Read a triage cache file (dict cve_id -> entry, or a list of entries)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return list(data.values()) if isinstance(data, dict) else data


def find_runs(root):
    """Folder of runs: return [(name, scout_json, triage_json), ...]."""
    def natural_key(path):
        m = re.match(r"(\d+)", os.path.basename(path))
        return int(m.group(1)) if m else 0

    runs = []
    for sub in sorted(glob.glob(os.path.join(root, "*")), key=natural_key):
        triage = glob.glob(os.path.join(sub, "Triaged_Report_*.json"))
        scout = os.path.join(sub, "cti_report.json")
        if os.path.isdir(sub) and triage and os.path.exists(scout):
            runs.append((os.path.basename(sub), scout, triage[0]))
    return runs


def print_summary(label, stats, mismatches):
    total = sum(stats.values()) + len(mismatches)
    print(f"{label}: {total} CVEs checked")
    print(f"  exact match (pulse count known) : {stats['exact']}")
    print(f"  match, pulse count unknown      : {stats['pulse_unknown_ok']}")
    print(f"  match only WITH +10 bonus       : {stats['pulse_unknown_bonus_only']}"
          "  (needs OTX data to confirm)")
    print(f"  skipped (missing fields)        : {stats['skipped']}")
    print(f"  MISMATCHES                      : {len(mismatches)}")
    for m in mismatches:
        print("    %s cvss=%s stored=%s expected=%s" % m)


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None

    # Mode 1: folder of archived runs (exact pulse counts per run)
    if arg and os.path.isdir(arg):
        runs = find_runs(arg)
        if not runs:
            print(f"No runs found under: {arg}")
            sys.exit(2)
        all_mismatches = []
        for name, scout_path, triage_path in runs:
            with open(triage_path, encoding="utf-8") as f:
                report = json.load(f)["report"]
            stats, mism = check_entries(report, load_pulses(scout_path))
            print_summary(name, stats, mism)
            all_mismatches += mism
        print(f"\nTotal mismatches across {len(runs)} runs: {len(all_mismatches)}")
        sys.exit(1 if all_mismatches else 0)

    # Mode 2: accumulated triage cache (default) or a given cache file
    cache = arg if arg else CACHE_PATH
    if not os.path.isfile(cache):
        print(f"Cache file not found: {cache}")
        sys.exit(2)
    entries = load_cache_entries(cache)
    stats, mism = check_entries(entries, load_pulses(SCOUT_PATH))
    print_summary(os.path.basename(cache), stats, mism)
    sys.exit(1 if mism else 0)


if __name__ == "__main__":
    main()