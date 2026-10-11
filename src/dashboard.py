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
# dashboard.py — Streamlit SOC console for live pipeline monitoring,
# report history, tool execution, and PDF/JSON downloads.
import os
import sys
import json
import glob
import time
import datetime
import subprocess
import streamlit as st  # type: ignore
import pandas as pd
import streamlit.components.v1 as components  # type: ignore

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.secure_config import get_missing_keys, save_env, load_env

load_env()

st.set_page_config(page_title="Auto-CTI | SOC Console", layout="wide", initial_sidebar_state="collapsed")

CLASSIFICATION = "TLP:AMBER  —  FOR INTERNAL DISTRIBUTION ONLY"

THEMES = {
    "dark": {
        "BG": "#0a0e17", "CARD": "#111927", "BORDER": "#243248",
        "TEXT": "#e6edf7", "TEXT_DIM": "#7d8da3",
        "ACCENT_BLUE": "#3b82f6", "ACCENT_CYAN": "#22d3ee", "SUCCESS": "#10b981",
        "DANGER": "#ef4444", "WARN": "#f59e0b", "WHITE": "#ffffff",
    },
    "light": {
        "BG": "#eef2f8", "CARD": "#ffffff", "BORDER": "#d7dee8",
        "TEXT": "#0f172a", "TEXT_DIM": "#5b6b85",
        "ACCENT_BLUE": "#1d4ed8", "ACCENT_CYAN": "#0891b2", "SUCCESS": "#059669",
        "DANGER": "#dc2626", "WARN": "#d97706", "WHITE": "#0f172a",
    },
}

PIPELINE_STAGES = [
    {"name": "Scout", "script": "scout_agent.py"},
    {"name": "Triage", "script": "triage_agent.py"},
    {"name": "Publisher", "script": "publisher_agent.py"},
]

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.expanduser("~/.auto-cti/data")
os.makedirs(DATA_DIR, exist_ok=True)

RUNS_DIR = os.path.join(DATA_DIR, "runs")

# ---------------------------------------------------------------- theme + CSS

def get_theme():
    if "theme" not in st.session_state:
        st.session_state.theme = "dark"
    return THEMES[st.session_state.theme]

def inject_custom_css(T):
    st.markdown("""
    <style>
    .stApp { background: #0a0e17; color: #e6edf7; }
    [data-testid="stSidebar"] { display: none; }
    header { visibility: hidden; }
    #MainMenu { visibility: hidden; }
    .tlp-banner {
        background: #091018; border: 1px solid #243248; border-radius: 6px;
        padding: 0.4rem 1rem; text-align: center;
        font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
        font-weight: 600; letter-spacing: 0.08em;
        color: #22d3ee !important; margin-bottom: 1rem;
    }
    .tlp-banner * { color: #22d3ee !important; }
    .hero-wrap { text-align: center; padding: 0.8rem 0 1.2rem 0; }
    .hero-title {
        font-family: 'Inter', sans-serif; font-size: 2.2rem; font-weight: 800;
        background: linear-gradient(90deg, #ffffff 20%, #22d3ee 80%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        background-clip: text; color: #ffffff;
    }
    .metric-card {
        background: #111927; border: 1px solid #243248;
        border-radius: 10px; padding: 1rem;
    }
    .metric-value { font-size: 2rem; font-weight: 700; color: #ffffff !important; }
    .tool-card {
        background: #111927; border: 1px solid #243248; border-radius: 10px;
        padding: 1rem 1.1rem; min-height: 150px;
    }
    .tool-card-title {
        font-weight: 700; color: #ffffff; font-size: 1rem; margin-top: 0.4rem;
    }
    .tool-card-desc {
        font-size: 0.78rem; color: #7d8da3; line-height: 1.45; margin-top: 0.35rem;
    }
    .tool-card-code {
        font-family: 'JetBrains Mono', monospace; font-size: 0.7rem;
        color: #22d3ee; margin-top: 0.5rem;
    }
    .status-badge {
        display: inline-block; padding: 0.3rem 0.85rem; border-radius: 20px;
        font-size: 0.72rem; font-weight: 700; font-family: 'JetBrains Mono', monospace;
    }
    .status-online { background: #10b98122; color: #10b981 !important; border: 1px solid #10b98155; }
    .status-scanning { background: #f59e0b22; color: #f59e0b !important; border: 1px solid #f59e0b55; }
    .status-completed { background: #3b82f622; color: #3b82f6 !important; border: 1px solid #3b82f655; }
    .progress-track { background: #243248; border-radius: 100px; height: 7px; overflow: hidden; margin-top: 0.4rem; }
    .progress-fill {
        height: 100%; border-radius: 100px;
        background: linear-gradient(90deg, #3b82f6, #22d3ee);
        transition: width 0.5s ease;
    }
    .notice-box {
        border-radius: 8px; padding: 0.8rem 1rem; font-size: 0.9rem;
        background: #111927; color: #e6edf7 !important;
    }
    h3 { color: #ffffff !important; }
    .stButton > button {
        background-color: #111927 !important; color: #e6edf7 !important;
        border: 1px solid #243248 !important; border-radius: 8px !important;
    }
    .stButton > button:hover {
        border-color: #22d3ee !important; color: #22d3ee !important;
    }
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.4rem; background: #0f1623; border-radius: 10px;
        padding: 0.35rem; border: 1px solid #243248;
    }
    .stTabs [data-baseweb="tab"] {
        height: 42px; background-color: transparent; border-radius: 8px;
        padding: 0 1rem; color: #7d8da3 !important; font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background-color: #111927 !important; color: #22d3ee !important;
        border: 1px solid #243248 !important;
    }
    </style>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------------- shared helpers

def load_latest_json(directory, extension="*.json"):
    if not os.path.exists(directory):
        return None, None
    files = glob.glob(os.path.join(directory, extension))
    if not files:
        return None, None
    latest = max(files, key=os.path.getctime)
    try:
        with open(latest, "r", encoding="utf-8") as f:
            return json.load(f), latest
    except Exception:
        return None, latest

def run_tool(script_relative, args=None, timeout=180):
    """Run a src/tools script and capture its output."""
    cmd = [sys.executable, "-u", script_relative]
    if args:
        cmd.extend(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"},
            cwd=PROJECT_ROOT
        )
        combined = (result.stdout or "") + (result.stderr or "")
        return combined.strip(), result.returncode == 0
    except subprocess.TimeoutExpired:
        return f"Tool timed out after {timeout}s.", False
    except Exception as e:
        return f"Tool failed: {e}", False

def render_classification_banner():
    st.markdown(f'<div class="tlp-banner">{CLASSIFICATION}</div>', unsafe_allow_html=True)

def render_theme_toggle():
    label = "☀️ Light Mode" if st.session_state.theme == "dark" else "🌙 Dark Mode"
    if st.button(label, key="theme_toggle"):
        st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"
        st.rerun()

def render_notice(T, text, kind="info"):
    colors = {"info": "#22d3ee", "success": "#10b981", "warning": "#f59e0b", "error": "#ef4444"}
    icons = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "⛔"}
    c = colors.get(kind, "#22d3ee")
    st.markdown(f"""
    <div class="notice-box" style="border:1px solid {c}55; border-left:4px solid {c};">
        {icons.get(kind, '')}&nbsp; {text}
    </div>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------------- pipeline tab

def get_severity_stats():
    pub_data, _ = load_latest_json(os.path.join(DATA_DIR, "publisher_agent_result"))
    if pub_data and "severity_stats" in pub_data:
        s = pub_data["severity_stats"]
        return s.get("Total", "-"), s.get("Critical", "-"), s.get("High", "-"), s.get("Medium", "-")
    triage_data, _ = load_latest_json(os.path.join(DATA_DIR, "triage_agent_result"))
    if isinstance(triage_data, list) and triage_data:
        df = pd.DataFrame(triage_data)
        total = len(df)
        if "CVSS_Severity" in df.columns:
            sev = df["CVSS_Severity"].astype(str).str.lower()  # type: ignore
            return total, sev.eq("critical").sum(), sev.eq("high").sum(), sev.eq("medium").sum()
        return total, "-", "-", "-"
    return "-", "-", "-", "-"

def render_hero_header(T, status_text, status_class):
    st.markdown(f"""
    <div class="hero-wrap">
        <div class="hero-title">AUTO-CTI SECURITY OPERATIONS CONSOLE</div>
        <div style="font-size:0.8rem; color:#7d8da3; text-transform:uppercase; letter-spacing:0.06em;">
            AI-POWERED THREAT INTELLIGENCE &amp; TRIAGE
        </div>
        <div style="margin-top:0.6rem;">
            <span class="status-badge {status_class}">{status_text}</span>
            <span style="color:#7d8da3;"> &nbsp;•&nbsp; LIVE DATA PIPELINE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_executive_dashboard(T, agents_state):
    total_pct = sum(a['pct'] for a in agents_state) / len(agents_state) if agents_state else 0
    if total_pct == 100:
        status_text, status_class = "✅ ANALYSIS COMPLETE", "status-completed"
    elif total_pct > 0:
        status_text, status_class = "⏳ SCANNING IN PROGRESS", "status-scanning"
    else:
        status_text, status_class = "🟢 SYSTEM READY", "status-online"

    render_hero_header(T, status_text, status_class)
    total_cves, critical_count, high_count, medium_count = get_severity_stats()

    st.markdown(f"""
    <div style="margin-bottom:1.2rem;">
        <div style="display:flex; justify-content:space-between; font-size:0.75rem;
                    color:#7d8da3; font-family:'JetBrains Mono',monospace;">
            <span>PIPELINE PROGRESS</span><span>{round(total_pct)}%</span>
        </div>
        <div class="progress-track"><div class="progress-fill" style="width:{total_pct}%;"></div></div>
    </div>
    <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:1rem;">
        <div class="metric-card">
            <div style="color:#7d8da3; font-size:0.78rem;">Total CVEs</div>
            <div class="metric-value">{total_cves}</div>
        </div>
        <div class="metric-card">
            <div style="color:#7d8da3; font-size:0.78rem;">Critical</div>
            <div class="metric-value" style="color:#ef4444 !important;">{critical_count}</div>
        </div>
        <div class="metric-card">
            <div style="color:#7d8da3; font-size:0.78rem;">High</div>
            <div class="metric-value" style="color:#f59e0b !important;">{high_count}</div>
        </div>
        <div class="metric-card">
            <div style="color:#7d8da3; font-size:0.78rem;">Medium</div>
            <div class="metric-value" style="color:#22d3ee !important;">{medium_count}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def generate_agent_rings_html(T, agents_data):
    html = '<div style="display:flex; justify-content:center; gap:2.5rem; flex-wrap:wrap; margin:1rem 0;">'
    for agent in agents_data:
        pct = agent['pct']
        circumference = 2 * 3.14159 * 32
        offset = circumference - (pct / 100) * circumference
        color = '#10b981' if pct == 100 else ('#22d3ee' if pct > 0 else '#243248')
        html += f"""
        <div style="display:flex; flex-direction:column; align-items:center;">
            <div style="position:relative; width:78px; height:78px; display:flex; justify-content:center; align-items:center;">
                <svg width="78" height="78" style="position:absolute; top:0; left:0; transform:rotate(-90deg);">
                    <circle cx="39" cy="39" r="32" fill="none" stroke="#243248" stroke-width="6" />
                    <circle cx="39" cy="39" r="32" fill="none" stroke="{color}" stroke-width="6"
                            stroke-dasharray="{circumference}" stroke-dashoffset="{offset}"
                            style="transition: stroke-dashoffset 0.5s ease;" />
                </svg>
                <span style="font-size:1.05rem; font-weight:700; color:#ffffff; font-family:'JetBrains Mono',monospace;">{pct}%</span>
            </div>
            <span style="margin-top:0.5rem; font-size:0.7rem; font-weight:700; color:#7d8da3;
                         text-transform:uppercase; letter-spacing:0.05em;">{agent['name']}</span>
        </div>
        """
    html += '</div>'
    return html

def classify_log_line(line: str):
    noise_patterns = [
        "[CrewAIEventsBus]", "charmap", "codec can't encode",
        "character maps to <undefined>", "Sync handler error",
        "DeprecationWarning", "deprecated since", "has been renamed",
    ]
    for pattern in noise_patterns:
        if pattern in line:
            return None
    l = line.strip().lower()
    if any(k in l for k in ["[ok]", "successfully", "generated successfully", "saved at", "finished successfully", "complete"]):
        return ("✅", "#10b981", line.strip())
    if any(k in l for k in ["[failed]", "[exception]", "error:", "traceback", "exit code"]):
        return ("⛔", "#ef4444", line.strip())
    if any(k in l for k in ["warning", "warn:", "could not parse", "skipping"]):
        return ("⚠️", "#f59e0b", line.strip())
    if any(k in l for k in ["waking up", "compiling", "agent is", "publisher agent", "triage agent",
                              "scout agent", "kickoff", "task started", "starting"]):
        return ("🔄", "#22d3ee", line.strip())
    if any(k in l for k in ["api key", "loaded:", "base_url", "model:", "gemini", "ollama"]):
        return ("ℹ️", "#3b82f6", line.strip())
    if len(line.strip()) > 120:
        return ("💬", "#7d8da3", line.strip()[:160] + "…")
    if line.strip():
        return ("▸", "#7d8da3", line.strip())
    return None

def render_console(T, log_lines, height=300):
    rows_html = ""
    for line in log_lines[-500:]:
        result = classify_log_line(line)
        if result is None:
            continue
        icon, color, text = result
        safe_text = text.replace("<", "&lt;").replace(">", "&gt;")
        rows_html += (f'<div style="display:flex; gap:0.5rem; margin-bottom:0.3rem;">'
                      f'<span style="flex-shrink:0;">{icon}</span>'
                      f'<span style="color:{color}; word-break:break-word;">{safe_text}</span>'
                      f'</div>')
    if not rows_html:
        rows_html = '<span style="color:#7d8da3;">Waiting for agent output...</span>'
    html = f"""
    <div style="background:#000000; border:1px solid #243248; border-radius:10px; overflow:hidden; margin-top:0.5rem;">
        <div style="background:#091018; padding:0.45rem 0.9rem; display:flex; align-items:center; gap:0.4rem;
                    border-bottom:1px solid #243248; font-family:'JetBrains Mono',monospace;
                    font-size:0.7rem; color:#7d8da3;">
            <span style="width:9px;height:9px;border-radius:50%;background:#ef4444;display:inline-block;"></span>
            <span style="width:9px;height:9px;border-radius:50%;background:#f59e0b;display:inline-block;"></span>
            <span style="width:9px;height:9px;border-radius:50%;background:#10b981;display:inline-block;"></span>
            <span style="margin-left:0.5rem;">SYSTEM CONSOLE — Smart Feed</span>
        </div>
        <div id="smart-console"
             style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; padding:0.9rem 1rem;
                    height:{height}px; overflow-y:auto; line-height:1.65; background:#000000;">
            {rows_html}
        </div>
    </div>
    <script>
        const el1 = document.getElementById('smart-console');
        if (el1) {{ el1.scrollTop = el1.scrollHeight; }}
    </script>
    """
    components.html(html, height=height + 55, scrolling=False)

def run_agent_with_console(ring_placeholder, console_placeholder, T, agents_data, current_index, script_name):
    try:
        process = subprocess.Popen(
            [sys.executable, "-u", script_name],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True,
            encoding="utf-8", errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"},
            cwd=PROJECT_ROOT
        )
        progress = 0
        last_update_time = time.time()
        while True:
            assert process.stdout is not None
            line = process.stdout.readline()
            if line == "" and process.poll() is not None:
                break
            if line:
                st.session_state.console_log.append(line.rstrip())
                progress = min(progress + 4, 95)
                agents_data[current_index]['pct'] = progress
                if time.time() - last_update_time >= 0.5:
                    ring_placeholder.empty()
                    with ring_placeholder:
                        components.html(generate_agent_rings_html(T, agents_data), height=170, scrolling=False)
                    console_placeholder.empty()
                    with console_placeholder:
                        render_console(T, st.session_state.console_log)
                    last_update_time = time.time()
        if process.returncode == 0:
            agents_data[current_index]['pct'] = 100
            st.session_state.console_log.append(f"[OK] {script_name} finished successfully.")
            ring_placeholder.empty()
            with ring_placeholder:
                components.html(generate_agent_rings_html(T, agents_data), height=170, scrolling=False)
            console_placeholder.empty()
            with console_placeholder:
                render_console(T, st.session_state.console_log)
            return True
        else:
            st.session_state.console_log.append(f"[FAILED] {script_name} exited with code {process.returncode}.")
            st.error(f"⚠️ Agent '{script_name}' failed with return code {process.returncode}.")
            return False
    except Exception as e:
        st.session_state.console_log.append(f"[EXCEPTION] {e}")
        st.error(f"⚠️ Exception while running {script_name}: {e}")
        return False

def display_statistics(T):
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("<h3>📊 Detailed Vulnerability Findings</h3>", unsafe_allow_html=True)
    pub_data, _ = load_latest_json(os.path.join(DATA_DIR, "publisher_agent_result"))
    if pub_data and "cve_summary" in pub_data:
        df = pd.DataFrame(pub_data["cve_summary"])
    else:
        triage_data, _ = load_latest_json(os.path.join(DATA_DIR, "triage_agent_result"))
        df = pd.DataFrame(triage_data) if isinstance(triage_data, list) else pd.DataFrame()
    if not df.empty:
        rename_map = {
            "cve_id": "CVE ID", "description": "Description", "cvss_score": "CVSS Score",
            "severity": "Severity", "cwe_id": "CWE", "urgency_score": "Urgency Score",
            "mitre_mappings": "MITRE ATT&CK", "references": "References",
        }
        display_cols = [c for c in rename_map if c in df.columns]
        st.dataframe(df[display_cols].rename(columns=rename_map),  # type: ignore
                     use_container_width=True, hide_index=True)
    else:
        render_notice(T, "No vulnerability data found yet.", "info")

def display_console_tools(T):
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("<h3>🖥️ Console Tools</h3>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    report_dir = os.path.join(DATA_DIR, "Reports")
    pdf_files = glob.glob(os.path.join(report_dir, "*.pdf")) if os.path.exists(report_dir) else []
    with c1:
        if pdf_files:
            latest_pdf = max(pdf_files, key=os.path.getctime)
            with open(latest_pdf, "rb") as f:
                st.download_button("📥 Extract Latest PDF", data=f.read(),
                                   file_name=os.path.basename(latest_pdf),
                                   mime="application/pdf", use_container_width=True)
        else:
            st.button("📥 Extract Latest PDF", disabled=True, use_container_width=True)
    pub_data, pub_path = load_latest_json(os.path.join(DATA_DIR, "publisher_agent_result"))
    with c2:
        if pub_data:
            st.download_button("🗂️ Extract Latest JSON",
                               data=json.dumps(pub_data, indent=2, ensure_ascii=False),
                               file_name=os.path.basename(pub_path),  # type: ignore
                               mime="application/json", use_container_width=True)
        else:
            st.button("🗂️ Extract Latest JSON", disabled=True, use_container_width=True)
    with c3:
        if st.button("🧹 Clear Console Log", use_container_width=True):
            st.session_state.console_log = []
            st.rerun()
    with c4:
        noise_count = sum(1 for l in st.session_state.get("console_log", [])
                          if classify_log_line(l) is None)
        st.button(f"🔇 {noise_count} filtered", disabled=True, use_container_width=True,
                  help="Lines filtered from Smart Feed")
    if pub_data:
        with st.expander("🔍 View Raw Executive Briefing JSON"):
            st.json(pub_data)

def render_pipeline_tab(T):
    if "running" not in st.session_state:
        st.session_state.running = False
    if "console_log" not in st.session_state:
        st.session_state.console_log = []

    if not st.session_state.running:
        dummy_state = [{"name": s["name"], "pct": 0} for s in PIPELINE_STAGES]
        render_executive_dashboard(T, dummy_state)
        components.html(generate_agent_rings_html(T, dummy_state), height=170, scrolling=False)
        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2, c3 = st.columns([1, 2, 1])
        with c2:
            if st.button("🛡️ INITIALIZE SYSTEM", use_container_width=True):
                st.session_state.running = True
                st.session_state.console_log = []
                os.environ["PIPELINE_START_TIME"] = str(time.time())
                st.rerun()
    else:
        if "agents_state" not in st.session_state:
            st.session_state.agents_state = [{"name": s["name"], "pct": 0} for s in PIPELINE_STAGES]
        render_executive_dashboard(T, st.session_state.agents_state)
        ring_placeholder = st.empty()
        with ring_placeholder:
            components.html(generate_agent_rings_html(T, st.session_state.agents_state),
                            height=170, scrolling=False)
        console_placeholder = st.empty()
        with console_placeholder:
            render_console(T, st.session_state.console_log)
        last_stage_index = len(PIPELINE_STAGES) - 1
        if st.session_state.agents_state[last_stage_index]['pct'] < 100:
            for i, stage in enumerate(PIPELINE_STAGES):
                if st.session_state.agents_state[i]['pct'] < 100:
                    success = run_agent_with_console(
                        ring_placeholder, console_placeholder, T,
                        st.session_state.agents_state, i, stage["script"]
                    )
                    if not success:
                        st.error(f"{stage['name']} agent failed. Pipeline stopped.")
                        if st.button(f"🔄 Retry {stage['name']}"):
                            st.session_state.agents_state[i]['pct'] = 0
                            st.rerun()
                        st.stop()
                    st.rerun()
                    break
        else:
            ring_placeholder.empty()
            console_placeholder.empty()
            components.html(generate_agent_rings_html(T, st.session_state.agents_state),
                            height=170, scrolling=False)
            st.markdown("<br>", unsafe_allow_html=True)
            render_notice(T, "Pipeline completed successfully. Final report generated by the Publisher Agent.", "success")
            display_console_tools(T)
            display_statistics(T)
            st.markdown("<br>", unsafe_allow_html=True)
            c1, c2, c3 = st.columns([1, 2, 1])
            with c2:
                if st.button("🔄 RESET SYSTEM", use_container_width=True):
                    st.session_state.running = False
                    if "agents_state" in st.session_state:
                        del st.session_state.agents_state
                    st.session_state.console_log = []
                    st.rerun()

# ---------------------------------------------------------------- tools tab

TOOL_CARDS = [
    {
        "icon": "✓",
        "title": "Verify Urgency Score",
        "desc": "Recomputes every Urgency Score and compares it against the stored value.",
        "cmd": "auto-cti -v",
        "script": "src/tools/verify_urgency.py",
        "args": [],
        "key": "tool_verify",
    },
    {
        "icon": "📊",
        "title": "PoC Breakdown",
        "desc": "Splits the “PoC found” figure into external PoC, patch analysis, non-PoC refs, and no PoC.",
        "cmd": "auto-cti -b",
        "script": "src/tools/poc_breakdown.py",
        "args": [],
        "key": "tool_poc",
    },
    {
        "icon": "📦",
        "title": "Archive Current Run",
        "desc": "Snapshots the current Scout/Triage/Publisher outputs into a numbered folder.",
        "cmd": "auto-cti -a",
        "script": "src/tools/archive_run.py",
        "args": [],
        "key": "tool_archive",
    },
]

def render_tools_panel(T):
    st.markdown(
        "<h3 style='margin-bottom:0.2rem;'>🧰 Analysis Tools</h3>"
        "<p style='color:#7d8da3; font-size:0.88rem; margin-top:0;'>"
        "Run Auto-CTI's verification utilities directly from the console. "
        "Each tool reads the current data under <code>~/.auto-cti/data/</code>."
        "</p>",
        unsafe_allow_html=True
    )

    cols = st.columns(3)
    for col, card in zip(cols, TOOL_CARDS):
        with col:
            st.markdown(f"""
            <div class="tool-card">
                <div style="font-size:1.8rem; line-height:1;">{card['icon']}</div>
                <div class="tool-card-title">{card['title']}</div>
                <div class="tool-card-desc">{card['desc']}</div>
                <div class="tool-card-code">$ {card['cmd']}</div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("Run", key=card["key"], use_container_width=True):
                with st.spinner(f"Running {card['title']}..."):
                    output, ok = run_tool(card["script"], card["args"])
                st.session_state.tool_output = output
                st.session_state.tool_name = card["title"]
                st.session_state.tool_ok = ok

    if st.session_state.get("tool_output"):
        ok = st.session_state.get("tool_ok", True)
        icon = "✅" if ok else "⚠️"
        color = "#10b981" if ok else "#f59e0b"
        st.markdown(f"""
        <div style="margin-top:1.2rem; display:flex; align-items:center; gap:0.6rem;
                    border-top:1px solid #243248; padding-top:0.9rem;">
            <span style="font-size:1.15rem;">{icon}</span>
            <span style="font-weight:700; color:{color};">
                {st.session_state.get('tool_name', 'Tool')} — {'completed' if ok else 'finished with issues'}
            </span>
        </div>
        """, unsafe_allow_html=True)
        st.code(st.session_state.tool_output, language="text")
        c1, c2, _ = st.columns([1, 1, 4])
        with c1:
            if st.button("Clear output", key="clear_tool_output", use_container_width=True):
                st.session_state.tool_output = ""
                st.session_state.tool_name = ""
                st.rerun()

# ---------------------------------------------------------------- config tab

def render_config_panel(T):
    st.markdown(
        "<h3 style='margin-bottom:0.2rem;'>⚙️ Configuration</h3>"
        "<p style='color:#7d8da3; font-size:0.88rem; margin-top:0;'>"
        "Test your API keys against their providers and manage <code>~/.auto-cti/.env</code>."
        "</p>",
        unsafe_allow_html=True
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"""
        <div class="tool-card">
            <div style="font-size:1.8rem; line-height:1;">🔑</div>
            <div class="tool-card-title">Check API Keys</div>
            <div class="tool-card-desc">
                Live-tests every key against its provider (Gemini, NVD, GitHub, OTX). 
                Prints OK / FAIL with status codes, never the key itself.
            </div>
            <div class="tool-card-code">$ auto-cti -k</div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Run key check", key="cfg_check", use_container_width=True):
            with st.spinner("Testing API keys..."):
                output, ok = run_tool("src/tools/check_keys.py")
            st.session_state.tool_output = output
            st.session_state.tool_name = "Check API Keys"
            st.session_state.tool_ok = ok

    with c2:
        env_path = os.path.expanduser("~/.auto-cti/.env")
        env_exists = os.path.exists(env_path)
        st.markdown(f"""
        <div class="tool-card">
            <div style="font-size:1.8rem; line-height:1;">📝</div>
            <div class="tool-card-title">Edit .env</div>
            <div class="tool-card-desc">
                Open the configuration file in your terminal editor. 
                Or download a copy here to inspect it.
            </div>
            <div class="tool-card-code">$ auto-cti -e</div>
        </div>
        """, unsafe_allow_html=True)
        if env_exists:
            with open(env_path, "rb") as f:
                st.download_button("📥 Download .env", data=f.read(),
                                   file_name="auto-cti.env.txt", mime="text/plain",
                                   use_container_width=True)
        else:
            st.button("📥 Download .env", disabled=True, use_container_width=True)

    st.markdown(
        "<p style='color:#7d8da3; font-size:0.82rem; margin-top:1rem;'>"
        "For terminal editing, run <code>auto-cti -e</code> or edit "
        "<code>~/.auto-cti/.env</code> directly. File permissions should be <code>600</code>."
        "</p>",
        unsafe_allow_html=True
    )

    if st.session_state.get("tool_output") and st.session_state.get("tool_name") == "Check API Keys":
        ok = st.session_state.get("tool_ok", True)
        icon = "✅" if ok else "⚠️"
        color = "#10b981" if ok else "#f59e0b"
        st.markdown(f"""
        <div style="margin-top:1rem; display:flex; align-items:center; gap:0.6rem;
                    border-top:1px solid #243248; padding-top:0.9rem;">
            <span style="font-size:1.15rem;">{icon}</span>
            <span style="font-weight:700; color:{color};">API Key Status</span>
        </div>
        """, unsafe_allow_html=True)
        st.code(st.session_state.tool_output, language="text")

# ---------------------------------------------------------------- reports tab

def list_archived_runs():
    if not os.path.exists(RUNS_DIR):
        return []
    runs = []
    for d in sorted(os.listdir(RUNS_DIR)):
        full = os.path.join(RUNS_DIR, d)
        if not os.path.isdir(full):
            continue
        meta_path = os.path.join(full, "run_meta.json")
        meta = {}
        if os.path.exists(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                pass
        runs.append((d, full, meta))
    runs.sort(key=lambda x: x[0], reverse=True)
    return runs

def display_report_history(T):
    st.markdown("<h3>📄 Generated PDF Reports</h3>", unsafe_allow_html=True)
    report_dir = os.path.join(DATA_DIR, "Reports")
    if not os.path.exists(report_dir):
        render_notice(T, "No reports have been generated yet.", "info")
    else:
        pdf_files = glob.glob(os.path.join(report_dir, "*.pdf"))
        if not pdf_files:
            render_notice(T, "Report directory is empty.", "info")
        else:
            pdf_files.sort(key=os.path.getctime, reverse=True)
            for pdf_file in pdf_files:
                file_name = os.path.basename(pdf_file)
                creation_time = datetime.datetime.fromtimestamp(
                    os.path.getctime(pdf_file)
                ).strftime("%Y-%m-%d %H:%M:%S")
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(
                        f"📄 **{file_name}** "
                        f"<span style='color:#7d8da3;'>({creation_time})</span>",
                        unsafe_allow_html=True
                    )
                with col2:
                    with open(pdf_file, "rb") as f:
                        st.download_button("📥 Download", data=f.read(),
                                           file_name=file_name, mime="application/pdf",
                                           key=pdf_file, use_container_width=True)

    st.markdown("<h3 style='margin-top:1.5rem;'>📦 Archived Runs</h3>", unsafe_allow_html=True)
    runs = list_archived_runs()
    if not runs:
        render_notice(T, "No archived runs yet. Use auto-cti -a or the Tools tab to archive.", "info")
        return
    for name, path, meta in runs:
        ts = meta.get("timestamp", "")
        files = meta.get("files", [])
        toggles = meta.get("toggles", {})
        active_toggles = [k for k, v in toggles.items() if str(v).lower() == "true"]
        with st.expander(f"📁 {name}  —  {len(files)} file(s)"):
            st.markdown(f"**Path:** `{path}`")
            if ts:
                st.markdown(f"**Timestamp:** `{ts}`")
            if active_toggles:
                st.markdown(f"**Active toggles:** {', '.join(active_toggles)}")
            else:
                st.markdown("**Active toggles:** _none_")
            st.markdown(f"**Files:** {', '.join(files) if files else '_none_'}")

# ---------------------------------------------------------------- main

def main():
    T = get_theme()
    inject_custom_css(T)

    # Session state init
    if "running" not in st.session_state:
        st.session_state.running = False
    if "console_log" not in st.session_state:
        st.session_state.console_log = []
    if "tool_output" not in st.session_state:
        st.session_state.tool_output = ""
    if "tool_name" not in st.session_state:
        st.session_state.tool_name = ""

    # API key gate
    missing = get_missing_keys()
    if missing:
        st.warning("🔑 A required API key is missing. Please enter it below to enable the pipeline.")
        with st.form("api_keys_form"):
            new_env = {}
            for key, url in missing.items():
                st.markdown(f"**{key}** ([get it here]({url}))")
                val = st.text_input(f"Enter {key}", type="password", key=f"key_{key}")
                new_env[key] = val
            submitted = st.form_submit_button("💾 Save Keys")
            if submitted:
                current = load_env()
                for k, v in new_env.items():
                    if v:
                        current[k] = v
                save_env(current)
                st.success("✅ Keys saved! Reloading…")
                st.rerun()
        st.stop()

    # Header bar
    top_l, top_r = st.columns([6, 1])
    with top_l:
        render_classification_banner()
    with top_r:
        render_theme_toggle()

    # Tabs
    tab_pipeline, tab_tools, tab_config, tab_reports = st.tabs([
        "🛡️  Pipeline", "🧰  Analysis Tools", "⚙️  Configuration", "📂  Reports"
    ])
    with tab_pipeline:
        render_pipeline_tab(T)
    with tab_tools:
        render_tools_panel(T)
    with tab_config:
        render_config_panel(T)
    with tab_reports:
        display_report_history(T)

if __name__ == "__main__":
    main()