import os, json, shutil, datetime, glob

DATA = os.path.expanduser("~/.auto-cti/data")
RUNS = os.path.join(DATA, "runs")
os.makedirs(RUNS, exist_ok=True)

def next_index():
    dirs = [d for d in os.listdir(RUNS) if os.path.isdir(os.path.join(RUNS, d)) and d[:3].isdigit()]
    nums = [int(d[:3]) for d in dirs]
    return max(nums) + 1 if nums else 1

def latest(pattern):
    files = glob.glob(pattern)
    return max(files, key=os.path.getctime) if files else None

idx = next_index()
stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
dest = os.path.join(RUNS, f"{idx:03d}_{stamp}")
os.makedirs(dest, exist_ok=True)

def copy(src, name):
    if src and os.path.exists(src):
        shutil.copy2(src, os.path.join(dest, name))
        return name
    return None

copied = []
copied.append(copy(os.path.join(DATA, "Scout_Agent_Results", "cti_report.json"), "cti_report.json"))
copied.append(copy(latest(os.path.join(DATA, "triage_agent_result", "Triaged_Report_*.json")), "Triaged_Report.json"))
copied.append(copy(latest(os.path.join(DATA, "publisher_agent_result", "Executive_Briefing_*.json")), "Executive_Briefing.json"))
copied.append(copy(latest(os.path.join(DATA, "Reports", "*.pdf")), "AutoCTI_Report.pdf"))

meta = {
    "run": idx,
    "timestamp": stamp,
    "files": [c for c in copied if c],
    "toggles": {k: os.getenv(k) for k in [
        "SCOUT_SKIP_NVD", "ENABLE_SPLOITUS", "ENABLE_VULNERS_LUCENE", "ENABLE_SEEBUG"
    ]},
}
with open(os.path.join(dest, "run_meta.json"), "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2, ensure_ascii=False)

print(f"Archived run {idx:03d} -> {dest}")