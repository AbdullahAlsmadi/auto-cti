import os
import sys
import json
import glob
import datetime
import subprocess
import streamlit as st
import pandas as pd
import streamlit.components.v1 as components

st.set_page_config(page_title="Auto-CTI | SOC Console", layout="wide", initial_sidebar_state="collapsed")

CLASSIFICATION = "TLP:AMBER  —  FOR INTERNAL DISTRIBUTION ONLY"

THEMES = {
    "dark": {
        "BG": "#0a0e17", "BG_GRADIENT": "radial-gradient(circle at top, #0f1623 0%, #060a12 100%)",
        "CARD": "#111927", "BORDER": "#243248", "TEXT": "#e6edf7", "TEXT_DIM": "#7d8da3",
        "ACCENT_BLUE": "#3b82f6", "ACCENT_CYAN": "#22d3ee", "SUCCESS": "#10b981",
        "DANGER": "#ef4444", "WARN": "#f59e0b", "WHITE": "#ffffff",
        "CONSOLE_BG": "#000000", "CONSOLE_TEXT": "#22d3ee", "BANNER_BG": "#091018",
    },
    "light": {
        "BG": "#eef2f8", "BG_GRADIENT": "linear-gradient(180deg, #f4f7fb 0%, #e8edf5 100%)",
        "CARD": "#ffffff", "BORDER": "#d7dee8", "TEXT": "#0f172a", "TEXT_DIM": "#5b6b85",
        "ACCENT_BLUE": "#1d4ed8", "ACCENT_CYAN": "#0891b2", "SUCCESS": "#059669",
        "DANGER": "#dc2626", "WARN": "#d97706", "WHITE": "#0f172a",
        "CONSOLE_BG": "#f8fafc", "CONSOLE_TEXT": "#1e40af", "BANNER_BG": "#0f1c2e",
    },
}

PIPELINE_STAGES = [
    {"name": "Scout", "script": "scout_agent.py"},
    {"name": "Triage", "script": "triage_agent.py"},
    {"name": "Publisher", "script": "publisher_agent.py"},
]

def get_theme():
    if "theme" not in st.session_state:
        st.session_state.theme = "dark"
    return THEMES[st.session_state.theme]

def inject_custom_css(T):
    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    .stApp {{
        background: {T['BG_GRADIENT']};
        background-color: {T['BG']};
        color: {T['TEXT']};
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }}
    [data-testid="stSidebar"] {{ display: none; }}
    header {{ visibility: hidden; }}
    #MainMenu {{ visibility: hidden; }}
    footer {{ visibility: hidden; }}

    .stApp, .stApp p, .stApp span, .stApp div, .stApp label {{
        color: {T['TEXT']};
    }}
 
    .tlp-banner {{
        background: {T['BANNER_BG']};
        border: 1px solid {T['BORDER']};
        border-radius: 6px;
        padding: 0.4rem 1rem;
        text-align: center;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        color: {T['ACCENT_CYAN']} !important;
        margin-bottom: 1rem;
    }}
    .tlp-banner * {{ color: {T['ACCENT_CYAN']} !important; }}

    .hero-wrap {{ text-align: center; padding: 0.8rem 0 1.6rem 0; }}
    .hero-icon {{ font-size: 1.6rem; margin-bottom: 0.3rem; }}
    .hero-title {{
        font-family: 'Inter', sans-serif; font-size: 2.5rem; font-weight: 800;
        letter-spacing: 0.01em; line-height: 1.15;
        background: linear-gradient(90deg, {T['WHITE']} 20%, {T['ACCENT_CYAN']} 80%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        background-clip: text; color: {T['WHITE']};
    }}
    .hero-subtitle {{
        font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; letter-spacing: 0.14em;
        color: {T['TEXT_DIM']} !important; text-transform: uppercase; margin-top: 0.5rem;
    }}
    .hero-meta {{
        margin-top: 0.9rem; display: flex; justify-content: center; align-items: center; gap: 0.8rem;
        font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: {T['TEXT_DIM']} !important;
    }}

    .metric-card {{
        background: {T['CARD']}; border: 1px solid {T['BORDER']}; border-radius: 10px;
        padding: 1.1rem 1rem; box-shadow: 0 4px 10px -4px rgba(0,0,0,0.3);
        transition: all 0.2s;
    }}
    .metric-card:hover {{ border-color: {T['ACCENT_CYAN']}; }}
    .metric-label {{
        font-size: 0.72rem; font-weight: 600; color: {T['TEXT_DIM']} !important;
        text-transform: uppercase; letter-spacing: 0.06em;
    }}
    .metric-value {{ font-size: 2rem; font-weight: 700; color: {T['WHITE']} !important; margin-top: 0.2rem; }}
    .metric-sub {{ font-size: 0.72rem; color: {T['TEXT_DIM']} !important; margin-top: 0.2rem; }}

    .status-badge {{
        display: inline-block; padding: 0.3rem 0.85rem; border-radius: 20px;
        font-size: 0.72rem; font-weight: 700; letter-spacing: 0.03em;
        font-family: 'JetBrains Mono', monospace;
    }}
    .status-online {{ background: {T['SUCCESS']}22; color: {T['SUCCESS']} !important; border: 1px solid {T['SUCCESS']}55; }}
    .status-scanning {{ background: {T['WARN']}22; color: {T['WARN']} !important; border: 1px solid {T['WARN']}55; }}
    .status-completed {{ background: {T['ACCENT_BLUE']}22; color: {T['ACCENT_BLUE']} !important; border: 1px solid {T['ACCENT_BLUE']}55; }}

    .progress-track {{ background: {T['BORDER']}; border-radius: 100px; height: 7px; width: 100%; overflow: hidden; margin-top: 0.4rem; }}
    .progress-fill {{
        height: 100%; border-radius: 100px;
        background: linear-gradient(90deg, {T['ACCENT_BLUE']}, {T['ACCENT_CYAN']});
        transition: width 0.5s ease; width: 0%;
    }}

    .console-wrap {{
        background: {T['CONSOLE_BG']}; border: 1px solid {T['BORDER']}; border-radius: 10px;
        overflow: hidden; margin-top: 0.5rem;
    }}
    .console-header {{
        background: {T['BANNER_BG']}; padding: 0.5rem 0.9rem; display: flex; align-items: center; gap: 0.4rem;
        border-bottom: 1px solid {T['BORDER']};
        font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: {T['TEXT_DIM']};
    }}
    .dot {{ width: 9px; height: 9px; border-radius: 50%; display: inline-block; }}
    .dot-red {{ background: #ef4444; }} .dot-yellow {{ background: #f59e0b; }} .dot-green {{ background: #10b981; }}
    .console-body {{
        font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: {T['CONSOLE_TEXT']};
        padding: 0.8rem 1rem; height: 230px; overflow-y: auto; white-space: pre-wrap; line-height: 1.5;
    }}

    .notice-box {{
        border-radius: 8px; padding: 0.8rem 1rem; font-size: 0.9rem;
        background: {T['CARD']}; color: {T['TEXT']} !important;
    }}
    .notice-box * {{ color: {T['TEXT']} !important; }}

    hr {{ border-color: {T['BORDER']}; margin: 1.4rem 0; }}

    .stButton > button, .stDownloadButton > button {{
        background-color: {T['CARD']} !important;
        color: {T['TEXT']} !important;
        border: 1px solid {T['BORDER']} !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
    }}
    .stButton > button p, .stDownloadButton > button p,
    .stButton > button span, .stDownloadButton > button span {{
        color: {T['TEXT']} !important;
    }}
    .stButton > button:hover, .stDownloadButton > button:hover {{
        border-color: {T['ACCENT_CYAN']} !important;
        color: {T['ACCENT_CYAN']} !important;
    }}
    .stButton > button:hover p, .stDownloadButton > button:hover p {{
        color: {T['ACCENT_CYAN']} !important;
    }}

    [data-testid="stAlert"], .stAlert {{
        background-color: {T['CARD']} !important;
        color: {T['TEXT']} !important;
        border: 1px solid {T['BORDER']} !important;
        border-radius: 8px !important;
    }}
    [data-testid="stAlert"] * {{ color: {T['TEXT']} !important; }}

    [data-testid="stExpander"] {{
        background-color: {T['CARD']} !important;
        border: 1px solid {T['BORDER']} !important;
        border-radius: 8px !important;
    }}
    [data-testid="stExpander"] * {{ color: {T['TEXT']} !important; }}

    [data-testid="stDataFrame"] {{
        border: 1px solid {T['BORDER']} !important;
        border-radius: 8px !important;
    }}

    [data-testid="stCode"] pre, .stCodeBlock, .stCodeBlock pre {{
        background-color: {T['CONSOLE_BG']} !important;
        color: {T['CONSOLE_TEXT']} !important;
        border: 1px solid {T['BORDER']} !important;
        border-radius: 8px !important;
    }}

    [data-testid="stDownloadButton"] > button p,
    [data-testid="stDownloadButton"] > button span,
    [data-testid="stDownloadButton"] > button {{
        color: {T['TEXT']} !important;
        font-size: 0.85rem !important;
    }}

    h3 {{ color: {T['WHITE']} !important; }}

    [data-testid="stDataFrame"] th {{
        background-color: {T['BANNER_BG']} !important;
        color: #ffffff !important;
    }}
    [data-testid="stDataFrame"] td {{
        color: {T['TEXT']} !important;
        background-color: {T['CARD']} !important;
    }}

    [data-testid="stExpander"] summary p,
    [data-testid="stExpander"] summary span {{
        color: {T['TEXT']} !important;
    }}
    </style>
    """, unsafe_allow_html=True)

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

def get_severity_stats():
    pub_data, _ = load_latest_json(os.path.join("JoFile", "publisher_agent_result"))
    if pub_data and "severity_stats" in pub_data:
        s = pub_data["severity_stats"]
        return s.get("Total", "-"), s.get("Critical", "-"), s.get("High", "-"), s.get("Medium", "-")

    triage_data, _ = load_latest_json(os.path.join("JoFile", "triage_agent_result"))
    if isinstance(triage_data, list) and triage_data:
        df = pd.DataFrame(triage_data)
        total = len(df)
        if "CVSS_Severity" in df.columns:
            sev = df["CVSS_Severity"].astype(str).str.lower()
            return total, sev.eq("critical").sum(), sev.eq("high").sum(), sev.eq("medium").sum()
        return total, "-", "-", "-"
    return "-", "-", "-", "-"

def render_classification_banner():
    st.markdown(f'<div class="tlp-banner">{CLASSIFICATION}</div>', unsafe_allow_html=True)

def render_theme_toggle():
    label = "☀️ Light Mode" if st.session_state.theme == "dark" else "🌙 Dark Mode"
    if st.button(label, key="theme_toggle"):
        st.session_state.theme = "light" if st.session_state.theme == "dark" else "dark"
        st.rerun()

def render_notice(T, text, kind="info"):
    colors = {"info": T['ACCENT_CYAN'], "success": T['SUCCESS'], "warning": T['WARN'], "error": T['DANGER']}
    icons = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "⛔"}
    c = colors.get(kind, T['ACCENT_CYAN'])
    st.markdown(f"""
    <div class="notice-box" style="border:1px solid {c}55; border-left:4px solid {c};">
        {icons.get(kind, '')}&nbsp; {text}
    </div>
    """, unsafe_allow_html=True)

def render_hero_header(T, status_text, status_class):
    st.markdown(f"""
    <div class="hero-wrap">
        <div class="hero-icon">🛡️</div>
        <div class="hero-title">AUTO-CTI SECURITY OPERATIONS CONSOLE</div>
        <div class="hero-subtitle">Automated Threat Intelligence &amp; Executive Reporting Pipeline</div>
        <div class="hero-meta">
            <span>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</span>
            <span style="opacity:0.5;">•</span>
            <span class="status-badge {status_class}">{status_text}</span>
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

    html = f"""
    <div style="margin-bottom:1.4rem;">
        <div style="display:flex; justify-content:space-between; font-size:0.75rem; color:{T['TEXT_DIM']}; font-family:'JetBrains Mono',monospace;">
            <span>PIPELINE PROGRESS</span><span>{round(total_pct)}%</span>
        </div>
        <div class="progress-track"><div class="progress-fill" style="width:{total_pct}%;"></div></div>
    </div>

    <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:0.5rem;">
        <div class="metric-card">
            <div class="metric-label">Total CVEs</div><div class="metric-value">{total_cves}</div>
            <div class="metric-sub">Identified vulnerabilities</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Critical</div><div class="metric-value" style="color:{T['DANGER']} !important;">{critical_count}</div>
            <div class="metric-sub">Immediate action required</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">High</div><div class="metric-value" style="color:{T['WARN']} !important;">{high_count}</div>
            <div class="metric-sub">High priority</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Medium</div><div class="metric-value" style="color:{T['ACCENT_CYAN']} !important;">{medium_count}</div>
            <div class="metric-sub">Standard priority</div>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)

def generate_agent_rings_html(T, agents_data):
    html = '<div style="display:flex; justify-content:center; align-items:center; gap:2.5rem; flex-wrap:wrap; margin:1.3rem 0;">'
    for agent in agents_data:
        pct = agent['pct']
        circumference = 2 * 3.14159 * 32
        offset = circumference - (pct / 100) * circumference
        color = T['SUCCESS'] if pct == 100 else (T['ACCENT_CYAN'] if pct > 0 else T['BORDER'])
        html += f"""
        <div style="display:flex; flex-direction:column; align-items:center;">
            <div style="position:relative; width:78px; height:78px; display:flex; justify-content:center; align-items:center;">
                <svg width="78" height="78" style="position:absolute; top:0; left:0; transform:rotate(-90deg);">
                    <circle cx="39" cy="39" r="32" fill="none" stroke="{T['BORDER']}" stroke-width="6" />
                    <circle cx="39" cy="39" r="32" fill="none" stroke="{color}" stroke-width="6"
                            stroke-dasharray="{circumference}" stroke-dashoffset="{offset}"
                            style="transition: stroke-dashoffset 0.5s ease;" />
                </svg>
                <span style="font-size:1.05rem; font-weight:700; color:{T['WHITE']}; font-family:'JetBrains Mono',monospace;">{pct}%</span>
            </div>
            <span style="margin-top:0.5rem; font-size:0.7rem; font-weight:700; color:{T['TEXT_DIM']}; text-transform:uppercase; letter-spacing:0.05em;">{agent['name']}</span>
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
        rows_html += f'<div style="display:flex; gap:0.5rem; margin-bottom:0.3rem;">' \
                     f'<span style="flex-shrink:0;">{icon}</span>' \
                     f'<span style="color:{color}; word-break:break-word;">{safe_text}</span>' \
                     f'</div>'

    if not rows_html:
        rows_html = '<span style="color:#7d8da3;">Waiting for agent output...</span>'

    html = f"""
    <div style="background:{T['CONSOLE_BG']}; border:1px solid {T['BORDER']};
                border-radius:10px; overflow:hidden; margin-top:0.5rem;">
        <div style="background:{T['BANNER_BG']}; padding:0.45rem 0.9rem;
                    display:flex; align-items:center; gap:0.4rem;
                    border-bottom:1px solid {T['BORDER']};
                    font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:{T['TEXT_DIM']};">
            <span style="width:9px;height:9px;border-radius:50%;background:#ef4444;display:inline-block;"></span>
            <span style="width:9px;height:9px;border-radius:50%;background:#f59e0b;display:inline-block;"></span>
            <span style="width:9px;height:9px;border-radius:50%;background:#10b981;display:inline-block;"></span>
            <span style="margin-left:0.5rem;">SYSTEM CONSOLE — Smart Feed</span>
        </div>
        <div id="smart-console"
             style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;
                    padding:0.9rem 1rem; height:{height}px; overflow-y:auto;
                    line-height:1.65; background:{T['CONSOLE_BG']};">
            {rows_html}
        </div>
    </div>
    <script>
        var el = document.getElementById('smart-console');
        if (el) el.scrollTop = el.scrollHeight;
    </script>
    """
    components.html(html, height=height + 55, scrolling=False)

    if log_lines:
        with st.expander("🔍 Raw Agent Log (debug)", expanded=False):
            raw_text = "\n".join(log_lines[-300:])
            safe_raw = (raw_text
                        .replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace("\n", "<br>"))
            st.markdown(f"""
            <div style="
                background: {T['CONSOLE_BG']};
                color: {T['CONSOLE_TEXT']} !important;
                font-family: 'JetBrains Mono', 'Courier New', monospace;
                font-size: 0.75rem;
                line-height: 1.6;
                padding: 0.9rem 1rem;
                border-radius: 8px;
                border: 1px solid #243248;
                max-height: 260px;
                overflow-y: auto;
                white-space: pre-wrap;
                word-break: break-all;
            ">{safe_raw}</div>
            """, unsafe_allow_html=True)

def run_agent_with_console(ring_placeholder, console_placeholder, T, agents_data, current_index, script_name):
    try:
        process = subprocess.Popen(
            [sys.executable, "-u", script_name],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True,
            encoding="utf-8", errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
        )

        progress = 0
        while True:
            line = process.stdout.readline() # type: ignore
            if line == "" and process.poll() is not None:
                break
            if line:
                st.session_state.console_log.append(line.rstrip())
                progress = min(progress + 4, 95)
                agents_data[current_index]['pct'] = progress

                ring_placeholder.empty()
                with ring_placeholder:
                    components.html(generate_agent_rings_html(T, agents_data), height=170, scrolling=False)

                console_placeholder.empty()
                with console_placeholder:
                    render_console(T, st.session_state.console_log)

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
    st.markdown(f"<h3 style='font-weight:700; color:{T['WHITE']};'>📊 Detailed Vulnerability Findings</h3>", unsafe_allow_html=True)

    pub_data, _ = load_latest_json(os.path.join("JoFile", "publisher_agent_result"))
    if pub_data and "cve_summary" in pub_data:
        df = pd.DataFrame(pub_data["cve_summary"])
    else:
        triage_data, _ = load_latest_json(os.path.join("JoFile", "triage_agent_result"))
        df = pd.DataFrame(triage_data) if isinstance(triage_data, list) else pd.DataFrame()

    if not df.empty:
        rename_map = {
            "cve_id": "CVE ID",
            "description": "Description",
            "cvss_score": "CVSS Score",
            "severity": "Severity",
            "cwe_id": "CWE",
            "urgency_score": "Urgency Score",
            "mitre_mappings": "MITRE ATT&CK",
            "references": "References",
        }
        display_cols = [c for c in rename_map if c in df.columns]
        st.dataframe(
            df[display_cols].rename(columns=rename_map),
            use_container_width=True,
            hide_index=True
        )

    else:
        render_notice(T, "No vulnerability data found yet.", "info")

def display_console_tools(T):
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown(f"<h3 style='font-weight:700; color:{T['WHITE']};'>🖥️ Console Tools</h3>", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)

    report_dir = os.path.join("JoFile", "Reports")
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

    pub_data, pub_path = load_latest_json(os.path.join("JoFile", "publisher_agent_result"))
    with c2:
        if pub_data:
            st.download_button("🗂️ Extract Latest JSON", data=json.dumps(pub_data, indent=2, ensure_ascii=False),
                                file_name=os.path.basename(pub_path), mime="application/json", # type: ignore
                                use_container_width=True)
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
                  help="Lines filtered from Smart Feed (CrewAI internal noise, encoding errors)")

    if pub_data:
        with st.expander("🔍 View Raw Executive Briefing JSON"):
            st.json(pub_data)

def display_report_history(T):
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown(f"<h3 style='font-weight:700; color:{T['WHITE']};'>📂 Report History</h3>", unsafe_allow_html=True)

    report_dir = os.path.join("JoFile", "Reports")
    if not os.path.exists(report_dir):
        render_notice(T, "No reports have been generated yet.", "info")
        return
    pdf_files = glob.glob(os.path.join(report_dir, "*.pdf"))
    if not pdf_files:
        render_notice(T, "Report directory is empty.", "info")
        return

    pdf_files.sort(key=os.path.getctime, reverse=True)
    for pdf_file in pdf_files:
        file_name = os.path.basename(pdf_file)
        creation_time = datetime.datetime.fromtimestamp(os.path.getctime(pdf_file)).strftime("%Y-%m-%d %H:%M:%S")
        col1, col2 = st.columns([4, 1])
        with col1:
            st.markdown(f"📄 **{file_name}** <span style='color:{T['TEXT_DIM']};'>({creation_time})</span>", unsafe_allow_html=True)
        with col2:
            with open(pdf_file, "rb") as f:
                st.download_button(
                    "📥 Download", data=f.read(),
                    file_name=file_name, mime="application/pdf",
                    key=pdf_file, use_container_width=True
                )

def main():
    T = get_theme()
    inject_custom_css(T)

    if "running" not in st.session_state:
        st.session_state.running = False
    if "console_log" not in st.session_state:
        st.session_state.console_log = []

    top_l, top_r = st.columns([6, 1])
    with top_l:
        render_classification_banner()
    with top_r:
        render_theme_toggle()

    if not st.session_state.running:
        dummy_state = [{"name": s["name"], "pct": 0} for s in PIPELINE_STAGES]
        render_executive_dashboard(T, dummy_state)
        components.html(generate_agent_rings_html(T, dummy_state), height=170, scrolling=False)

        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2, c3 = st.columns([1, 2, 1])
        with c2:
            if st.button("🚀  INITIALIZE SYSTEM", use_container_width=True):
                st.session_state.running = True
                st.session_state.console_log = []
                st.rerun()

        display_report_history(T)

    if st.session_state.running:
        if "agents_state" not in st.session_state:
            st.session_state.agents_state = [{"name": s["name"], "pct": 0} for s in PIPELINE_STAGES]

        render_executive_dashboard(T, st.session_state.agents_state)

        ring_placeholder = st.empty()
        with ring_placeholder:
            components.html(generate_agent_rings_html(T, st.session_state.agents_state), height=170, scrolling=False)

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

            components.html(
                generate_agent_rings_html(T, st.session_state.agents_state),
                height=170, scrolling=False
            )

            st.markdown("<br>", unsafe_allow_html=True)
            render_notice(T, "Pipeline completed successfully. Final report generated by the Publisher Agent.", "success")
            display_console_tools(T)
            display_statistics(T)
            display_report_history(T)

            st.markdown("<br>", unsafe_allow_html=True)
            c1, c2, c3 = st.columns([1, 2, 1])
            with c2:
                if st.button("🔄 RESET SYSTEM", use_container_width=True):
                    st.session_state.running = False
                    if "agents_state" in st.session_state:
                        del st.session_state.agents_state
                    st.session_state.console_log = []
                    st.rerun()

if __name__ == "__main__":
    main()

run_agent_with_console