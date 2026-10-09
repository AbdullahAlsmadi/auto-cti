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
# poc_breakdown.py — Splits the "PoC found" figure into honest categories:
# external PoC, patch-diff (LLM) analysis, non-PoC references, and no PoC.
#
# Usage:
#   auto-cti -b                       -> analyzes the accumulated triage cache
#   auto-cti -b /full/path/cache.json -> analyzes a specific cache file
#   auto-cti -b /full/path/runs_dir   -> analyzes a folder of runs
#                                        (each holding Triaged_Report_*.json)
#   add --list to print the plausible PoC links for manual verification
import os
import re
import sys
import glob
import json
import collections

CACHE_PATH = os.path.expanduser("~/.auto-cti/data/MAMORE/triage_cache.json")

# References that are NOT proof-of-concept material: CVE-keyed aggregator pages,
# NVD mirrors, advisories, source-code lines, commits, pull requests, search pages.
NON_POC = re.compile(
    r"trickest/cve|olbat/nvdcve|/advisories|/security/advisories|"
    r"/blob/|/commit/|/pull/|seebug\.org/search|"
    r"nvd\.nist\.gov|cve\.org|tenable\.com"
)


def poc_links(entry):
    """Links listed under 'Verified Exploit / Technical References' in the PoC text."""
    return [l[2:].strip() for l in entry.get("PoC", "").splitlines()
            if l.startswith("- http")]


def classify(entry):
    """Return (category, plausible_links)."""
    source = entry.get("PoC_Source", "llm_only")
    if source == "llm_only":
        return "no_poc", []
    if source == "patch_reverse_engineering":
        return "patch_analysis", []
    plausible = [l for l in poc_links(entry) if not NON_POC.search(l)]
    return ("external_plausible" if plausible else "external_non_poc"), plausible


def load_entries(arg):
    if arg and os.path.isdir(arg):
        entries = []
        for f in sorted(glob.glob(os.path.join(arg, "*", "Triaged_Report_*.json"))):
            with open(f, encoding="utf-8") as fh:
                entries += json.load(fh)["report"]
        return entries
    path = arg if arg else CACHE_PATH
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "report" in data:
        return data["report"]
    return list(data.values()) if isinstance(data, dict) else data


def main():
    args = [a for a in sys.argv[1:] if a != "--list"]
    show_list = "--list" in sys.argv[1:]
    target = args[0] if args else None
    try:
        entries = load_entries(target)
    except (OSError, ValueError, KeyError) as e:
        print(f"Cannot read input: {e}")
        sys.exit(2)
    if not entries:
        print("No entries found.")
        sys.exit(2)

    counts = collections.Counter()
    plausible_rows = []
    for e in entries:
        cat, links = classify(e)
        counts[cat] += 1
        if cat == "external_plausible":
            plausible_rows.append((e.get("CVE_ID", "?"), e.get("PoC_Source"), links))

    n = len(entries)
    rows = [
        ("external_plausible", "External PoC (plausible, verify manually)"),
        ("patch_analysis", "Patch-diff analysis (LLM narrative, not a PoC)"),
        ("external_non_poc", "Matched only non-PoC references (false positive)"),
        ("no_poc", "No PoC found"),
    ]
    print(f"CVEs analyzed: {n}\n")
    for key, label in rows:
        print(f"  {label:<52} {counts[key]:>5}  ({counts[key] / n * 100:5.1f}%)")
    legacy = counts["external_plausible"] + counts["patch_analysis"] + counts["external_non_poc"]
    print(f"\n  Legacy 'PoC found' figure (everything except no PoC): "
          f"{legacy} ({legacy / n * 100:.1f}%)")
    print("  Strict external PoC rate: "
          f"{counts['external_plausible'] / n * 100:.1f}%")

    if show_list:
        print("\nPlausible PoC links (open each one and confirm it is a real PoC):")
        for cve, source, links in plausible_rows:
            for l in links:
                print(f"  {cve}  [{source}]  {l}")


if __name__ == "__main__":
    main()
