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
# archive_run.py — Snapshots the current pipeline outputs (Scout, Triage,
# Publisher JSON/PDF) into a numbered folder under ~/.auto-cti/data/runs/,
# together with the feature-toggle state, so every run is reproducible.
#
# Usage:
#   auto-cti -a               -> archive the current run
#   auto-cti -a cycle1_run1   -> archive with a label (folder name gets the label)
import os
import sys
import json
import shutil
import datetime
import glob

DATA = os.path.expanduser("~/.auto-cti/data")
RUNS = os.path.join(DATA, "runs")
os.makedirs(RUNS, exist_ok=True)

_label = sys.argv[1].strip() if len(sys.argv) > 1 else ""


def read_flags():
    """Feature toggles from ~/.auto-cti/.env (the archive tool does not load .env itself)."""
    try:
        from dotenv import dotenv_values
        env = dotenv_values(os.path.expanduser("~/.auto-cti/.env"))
    except Exception:
        env = {}
    keys = ["SCOUT_SKIP_NVD", "ENABLE_SPLOITUS", "ENABLE_VULNERS_LUCENE", "ENABLE_SEEBUG"]
    return {k: env.get(k) or os.getenv(k) or "false" for k in keys}


def read_version():
    try:
        with open(os.path.expanduser("~/.auto-cti/VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "unknown"


def next_index():
    dirs = [d for d in os.listdir(RUNS) if os.path.isdir(os.path.join(RUNS, d)) and d[:3].isdigit()]
    nums = [int(d[:3]) for d in dirs]
    return max(nums) + 1 if nums else 1


def latest(pattern):
    files = glob.glob(pattern)
    return max(files, key=os.path.getctime) if files else None


def copy(src, name):
    if src and os.path.exists(src):
        shutil.copy2(src, os.path.join(dest, name))
        return name
    return None


idx = next_index()
stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
safe_label = "".join(c if c.isalnum() or c in "_-" else "_" for c in _label)[:24]
suffix = f"_{safe_label}" if safe_label else ""
dest = os.path.join(RUNS, f"{idx:03d}{suffix}_{stamp}")
os.makedirs(dest, exist_ok=True)

copied = []
copied.append(copy(os.path.join(DATA, "Scout_Agent_Results", "cti_report.json"), "cti_report.json"))
copied.append(copy(latest(os.path.join(DATA, "triage_agent_result", "Triaged_Report_*.json")), "Triaged_Report.json"))
copied.append(copy(latest(os.path.join(DATA, "publisher_agent_result", "Executive_Briefing_*.json")), "Executive_Briefing.json"))

pdf_src = latest(os.path.join(DATA, "Reports", "*.pdf"))
if pdf_src:
    copied.append(copy(pdf_src, "AutoCTI_Report.pdf"))

meta = {
    "run": idx,
    "label": safe_label,
    "timestamp": stamp,
    "code_version": read_version(),
    "files": [c for c in copied if c],
    "toggles": read_flags(),
}
with open(os.path.join(dest, "run_meta.json"), "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2, ensure_ascii=False)

print(f"Archived run {idx:03d}{suffix} -> {dest}")