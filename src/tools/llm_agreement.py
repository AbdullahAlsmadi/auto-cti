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
# llm_agreement.py — Reports how often the LLM's raw CVSS score agreed with
# the authoritative source (NVD, CNA, Tenable, OpenCVE, CVE.org).
#
# Usage:
#   auto-cti -g                       -> analyze the accumulated triage cache
#   auto-cti -g /full/path/cache.json -> analyze a specific cache file
import os
import sys
import json
import statistics
import collections

CACHE = os.path.expanduser("~/.auto-cti/data/MAMORE/triage_cache.json")


def load_entries(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return list(data.values()) if isinstance(data, dict) else data


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else CACHE
    if not os.path.isfile(path):
        print(f"Cache not found: {path}")
        sys.exit(2)

    entries = load_entries(path)
    total = len(entries)
    with_raw = [e for e in entries if e.get("LLM_CVSS_Score_Raw") is not None]
    comparable = [e for e in entries if e.get("LLM_vs_Authoritative_Delta") is not None]

    print(f"Cache                            : {os.path.basename(path)}")
    print(f"Total entries                    : {total}")
    print(f"With raw LLM score               : {len(with_raw)}")
    print(f"Comparable to authoritative      : {len(comparable)}")
    print()

    if not comparable:
        print("No comparable entries yet. Run a fresh Triage after patching")
        print("triage_agent.py so that LLM_CVSS_Score_Raw is recorded.")
        sys.exit(2)

    matches = [e for e in comparable if e.get("LLM_vs_Authoritative_Match")]
    deltas = [e["LLM_vs_Authoritative_Delta"] for e in comparable]
    abs_deltas = [abs(d) for d in deltas]

    rate = len(matches) / len(comparable) * 100
    print(f"Exact match rate                 : {len(matches)}/{len(comparable)}  ({rate:.1f}%)")
    print(f"Mean absolute delta              : {statistics.mean(abs_deltas):.2f}")
    print(f"Median absolute delta            : {statistics.median(abs_deltas):.2f}")
    print(f"Max absolute delta               : {max(abs_deltas):.2f}")
    print()

    bucket = collections.Counter()
    for d in deltas:
        a = abs(d)
        if a < 0.05:   bucket["exact"]    += 1
        elif a <= 0.5: bucket["±0.5"]     += 1
        elif a <= 1.0: bucket["±1.0"]     += 1
        elif a <= 2.0: bucket["±2.0"]     += 1
        elif a <= 4.0: bucket["±4.0"]     += 1
        else:          bucket["> 4.0"]    += 1

    print("Distribution of absolute deltas:")
    peak = max(bucket.values()) or 1
    for label in ["exact", "±0.5", "±1.0", "±2.0", "±4.0", "> 4.0"]:
        n = bucket.get(label, 0)
        bar = "█" * int(n / peak * 40)
        print(f"  {label:<6} {n:>4}  {bar}")


if __name__ == "__main__":
    main()