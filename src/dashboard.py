import os
import sys
import json
import glob
import time
import datetime
import subprocess
import streamlit as st
import pandas as pd
import streamlit.components.v1 as components

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.secure_config import init_config

init_config()

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

DATA_DIR = os.path.expanduser("~/.auto-cti/data")
os.makedirs(DATA_DIR, exist_ok=True)

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
    pub_data, _ = load_latest_json(os.path.join(DATA_DIR, "publisher_agent_result"))
    if pub_data and "severity_stats" in pub_data:
        s = pub_data["severity_stats"]
        return s.get("Total", "-"), s.get("Critical", "-"), s.get("High", "-"), s.get("Medium", "-")
    triage_data, _ = load_latest_json(os.path.join(DATA_DIR, "triage_agent_result"))
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
        <div class