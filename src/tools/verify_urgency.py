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
# The pulse count used by the formula is persisted with every cache entry
# under "OTX_Pulse_Count". The tool reads it directly from the cache, so
# verification is complete even when older Scout files are no longer
# available. As a fallback, it also scans the current Scout output and every
# archived run.
#
# Usage:
#   auto-cti -v                       -> checks the accumulated triage cache
#   auto-cti -v /full/path/cache.json -> checks a specific cache file
#   auto-cti -v /full/path/runs_dir   -> checks a folder of archived runs
import os
import re
import sys
import glob
import json

DATA_DIR = os.path.expanduser("~/.auto-cti/data")
CACHE_PATH = os.path.join(DATA_DIR, "MAMORE", "triage_cache.json")
SCOUT_PATH = os.path.join(DATA_DIR, "Scout_Agent_Results", "cti_report.json")
RUNS_DIR = os.path.join(DATA_DIR, "runs")


def expected_urgency(cvss, severity, pulse_count):
    """Same formula as recalculate_urgency_score() in triage_agent.py."""
    base = min(90, cvss * 9)
    if pulse_count > 0:
        base += 10
    if severity in ("Low", "None"):
        base -= 5
    return max(1, min(100, int(round(base))))


def load_pulses(scout_path):
    """Map cve_id -> alienvault_pulse_count (empty dict if unavailable)."""
    pulses = {}
    try:
        with open(scout_path, encoding="utf-8") as f:
            data = json.load(f)
        for day in data.values():
            for v in day.get("vulnerabilities", []):
                cve = v.get("cve_id")
                if cve:
                    pulses[cve] = v.get("alienvault_pulse_count", 0)
    except (OSError, ValueError, AttributeError):
        pass
    return pulses


def load_all_pulses():
    """Aggregate pulse counts from the current Scout output AND every archived
    run under ~/.auto-cti/data/runs/ (fallback only)."""
    pulses = {}
    pulses.update(load_pulses(SCOUT_PATH))
    if os.path.isdir(RUNS_DIR):
        for run_dir in sorted(glob.glob(os.path.join(RUNS_DIR, "*"))):
            scout = os.path.join(run_dir, "cti_report.json")
            if os.path.isfile(scout):
                pulses.update(load_pulses(scout))
    return pulses


def _pulse_from_entry(entry):
    """Return the pulse count stored with the entry, or None if absent."""
    if "OTX_Pulse_Count" not in entry:
        return None
    try:
        return int(entry["OTX_Pulse_Count"])
    except (TypeError, ValueError):
        return None


def check_entries(entries, pulses):
    """Compare stored vs recomputed Urgency for a list of triage entries.

    Priority for the pulse count:
      1. The "OTX_Pulse_Count" field persisted with the cache entry itself.
      2. The Scout-file lookup (current run + archives).

    If neither is available, the entry is counted as unverifiable rather than
    silently accepted.
    """
    stats = {
        "exact": 0,
        "mismatch": 0,
        "unverifiable": 0,
        "skipped": 0,
        "source_cache": 0,
        "source_scout": 0,
    }
    mismatches = []
    unverified = []

    for e in entries:
        try:
            cve = e["CVE_ID"]
            cvss = float(e["CVSS_Score"])
            sev = e.get("CVSS_Severity", "")
            stored = int(e["Urgency_Score"])
        except (KeyError, TypeError, ValueError):
            stats["skipped"] += 1
            continue

        pulse_count = _pulse_from_entry(e)
        source = None
        if pulse_count is not None:
            source = "cache"
        elif cve in pulses:
            pulse_count = pulses[cve]
            source = "scout"

        if pulse_count is None:
            stats["unverifiable"] += 1
            unverified.append(cve)
            continue

        exp = expected_urgency(cvss, sev, pulse_count)
        if stored == exp:
            stats["exact"] += 1
            stats[f"source_{source}"] += 1
        else:
            stats["mismatch"] += 1
            mismatches.append((cve, cvss, stored, str(exp), pulse_count, source))

    return stats, mismatches, unverified


def load_cache_entries(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return list(data.values()) if isinstance(data, dict) else data


def find_runs(root):
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


def print_summary(label, stats, mismatches, unverified):
    total = sum(stats.values()) - stats["source_cache"] - stats["source_scout"]
    print(f"{label}: {total} CVEs checked")
    print(f"  verified                          : {stats['exact']}")
    print(f"    · from cache OTX_Pulse_Count    : {stats['source_cache']}")
    print(f"    · from Scout file lookup        : {stats['source_scout']}")
    print(f"  UNVERIFIABLE                      : {stats['unverifiable']}")
    print(f"  MISMATCHES                        : {stats['mismatch']}")
    print(f"  skipped (missing fields)          : {stats['skipped']}")
    if mismatches:
        print("  --- mismatched entries ---")
        for cve, cvss, stored, expected, pulse, source in mismatches:
            print(f"    {cve}  cvss={cvss}  pulse={pulse}({source})  stored={stored}  expected={expected}")
    if unverified:
        preview = unverified[:8]
        tail = "" if len(unverified) <= 8 else f" (+{len(unverified) - 8} more)"
        print("  --- unverifiable CVEs ---")
        print(f"      {', '.join(preview)}{tail}")


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None

    if arg and os.path.isdir(arg):
        runs = find_runs(arg)
        if not runs:
            print(f"No runs found under: {arg}")
            sys.exit(2)
        all_mismatches = []
        all_unverified = []
        for name, scout_path, triage_path in runs:
            with open(triage_path, encoding="utf-8") as f:
                report = json.load(f)["report"]
            stats, mism, unver = check_entries(report, load_pulses(scout_path))
            print_summary(name, stats, mism, unver)
            all_mismatches += mism
            all_unverified += unver
        print(f"\nTotal mismatches across {len(runs)} runs: {len(all_mismatches)}")
        print(f"Total unverifiable across {len(runs)} runs: {len(all_unverified)}")
        sys.exit(1 if all_mismatches else 0)

    cache = arg if arg else CACHE_PATH
    if not os.path.isfile(cache):
        print(f"Cache file not found: {cache}")
        sys.exit(2)

    entries = load_cache_entries(cache)
    pulses = load_all_pulses()
    stats, mism, unver = check_entries(entries, pulses)
    print_summary(os.path.basename(cache), stats, mism, unver)
    sys.exit(1 if mism else 0)


if __name__ == "__main__":
    main()