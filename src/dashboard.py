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
# dashboard.py — Auto-CTI Threat Console.
import os
import sys
import json
import glob
import time
import datetime
import subprocess
import streamlit as st  # type: ignore
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.secure_config import get_missing_keys, save_env, load_env

load_env()

st.set_page_config(
    page_title="Auto-CTI · Threat Console",
    layout="wide",
    initial_sidebar_state="collapsed",
)

CLASSIFICATION = "TLP:AMBER · FOR INTERNAL DISTRIBUTION ONLY"
ENV_PATH = os.path.expanduser("~/.auto-cti/.env")

PIPELINE_STAGES = [
    {"name": "Scout",     "script": "scout_agent.py",     "desc": "Collection", "num": "01"},
    {"name": "Triage",    "script": "triage_agent.py",    "desc": "Analysis",   "num": "02"},
    {"name": "Publisher", "script": "publisher_agent.py", "desc": "Report",     "num": "03"},
]

TOGGLES = [
    ("SCOUT_SKIP_NVD",        "Skip NVD",       "Begin collection from GitHub Advisory instead of NVD."),
    ("ENABLE_SPLOITUS",       "Sploitus",       "Exploit aggregator. Frequently returns HTTP 403."),
    ("ENABLE_VULNERS_LUCENE", "Vulners Lucene", "Requires a paid Vulners subscription."),
    ("ENABLE_SEEBUG",         "Seebug",         "Chinese exploit index. Disabled by default."),
]

KEY_GROUPS = [
    ("Required", [
        ("GEMINI_API_KEY", "Google Gemini API key", True),
    ]),
    ("Recommended", [
        ("NVD_API_KEY",  "NIST NVD API key",      True),
        ("GITHUB_TOKEN", "GitHub Personal Token", True),
        ("OTX_API_KEY",  "AlienVault OTX key",    True),
    ]),
    ("Optional", [
        ("VULNERS_API_KEY",       "Vulners API key",       True),
        ("OPENCVE_USERNAME",      "OpenCVE username",      False),
        ("OPENCVE_PASSWORD",      "OpenCVE password",      True),
        ("GOOGLE_SEARCH_API_KEY", "Google Search API key", True),
        ("GOOGLE_SEARCH_CX",      "Google Search CX ID",   False),
    ]),
]

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.expanduser("~/.auto-cti/data")
os.makedirs(DATA_DIR, exist_ok=True)
RUNS_DIR = os.path.join(DATA_DIR, "runs")

# ---------------------------------------------------------------- html helper

def compact(html: str) -> str:
    return "".join(line.strip() for line in html.splitlines())

# ---------------------------------------------------------------- env helpers

def set_env_var(key: str, value: str) -> None:
    os.makedirs(os.path.dirname(ENV_PATH), exist_ok=True)
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
    found = False
    new_lines = []
    for line in lines:
        if line.strip().startswith(f"{key}="):
            new_lines.append(f"{key}={value}\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines.append("\n")
        new_lines.append(f"{key}={value}\n")
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    try:
        os.chmod(ENV_PATH, 0o600)
    except Exception:
        pass
    os.environ[key] = value

def read_env_values():
    """Parse ~/.auto-cti/.env into a dict without touching os.environ."""
    values = {}
    if not os.path.exists(ENV_PATH):
        return values
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            values[k.strip()] = v.strip()
    return values

def write_env_file(merged: dict) -> None:
    """Rewrite ~/.auto-cti/.env with a stable, grouped layout."""
    os.makedirs(os.path.dirname(ENV_PATH), exist_ok=True)
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write("# ============================================================\n")
        f.write("# Auto-CTI Environment Configuration\n")
        f.write("# ============================================================\n\n")
        for group_name, fields in KEY_GROUPS:
            f.write(f"# ---------- {group_name} ----------\n")
            for key, _label, _sec in fields:
                f.write(f"{key}={merged.get(key, '')}\n")
            f.write("\n")
        f.write("# ---------- Feature Toggles ----------\n")
        for tk in ["SCOUT_SKIP_NVD", "ENABLE_SPLOITUS",
                   "ENABLE_VULNERS_LUCENE", "ENABLE_SEEBUG"]:
            f.write(f"{tk}={merged.get(tk, 'false')}\n")
    try:
        os.chmod(ENV_PATH, 0o600)
    except Exception:
        pass

# ---------------------------------------------------------------- CSS

def inject_custom_css():
    st.markdown("""
    <style>
    /* ============================================================
       THREAT CONSOLE — soft navy, cool blues
       ============================================================ */

    .stApp {
        background:
            radial-gradient(1400px 800px at 50% -10%, #142a5c 0%, transparent 60%),
            linear-gradient(180deg, #0a1535 0%, #0e1a3f 50%, #0a1430 100%);
        color: #f8fafc;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-feature-settings: "ss01" 1, "cv11" 1;
        -webkit-font-smoothing: antialiased;
        min-height: 100vh;
    }
    [data-testid="stSidebar"] { display: none; }
    header { visibility: hidden; }
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1080px;
        margin: 0 auto;
    }

    /* ---- Streamlit buttons ---- */
    button[kind="primary"],
    button[data-testid="baseButton-primary"],
    [data-testid="stBaseButton-primary"] {
        background: linear-gradient(180deg, #3b82f6, #2563eb) !important;
        border: 1px solid #3b82f6 !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        box-shadow: 0 4px 18px rgba(59, 130, 246, 0.35) !important;
    }
    button[kind="primary"]:hover,
    button[data-testid="baseButton-primary"]:hover,
    [data-testid="stBaseButton-primary"]:hover {
        background: linear-gradient(180deg, #60a5fa, #3b82f6) !important;
        box-shadow: 0 6px 22px rgba(59, 130, 246, 0.5) !important;
        color: #ffffff !important;
    }
    button[kind="secondary"],
    button[data-testid="baseButton-secondary"],
    [data-testid="stBaseButton-secondary"] {
        background: rgba(19, 35, 72, 0.6) !important;
        border: 1px solid #1e3268 !important;
        color: #8b95c2 !important;
    }
    button[kind="secondary"]:hover,
    button[data-testid="baseButton-secondary"]:hover,
    [data-testid="stBaseButton-secondary"]:hover {
        border-color: #3b82f6 !important;
        color: #60a5fa !important;
        background: rgba(59, 130, 246, 0.08) !important;
    }
    .stButton > button {
        border-radius: 8px !important;
        font-family: 'Inter', sans-serif !important;
        font-size: 0.8rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.03em !important;
        padding: 0.65rem 1.2rem !important;
        min-height: 42px !important;
        transition: all 0.18s ease !important;
    }

    /* ---- Streamlit toggle: green when ON, red when OFF ---- */
    div[data-testid="stToggle"] {
        padding: 0.4rem 0;
    }
    div[data-testid="stToggle"] [role="switch"] {
        transition: all 0.2s ease !important;
        border: 1px solid #1e3268 !important;
    }
    div[data-testid="stToggle"] [role="switch"][aria-checked="true"] {
        background-color: #22c55e !important;
        border-color: #22c55e !important;
        box-shadow: 0 0 12px rgba(34, 197, 94, 0.4) !important;
    }
    div[data-testid="stToggle"] [role="switch"][aria-checked="false"] {
        background-color: #b91c1c !important;
        border-color: #b91c1c !important;
        box-shadow: 0 0 12px rgba(185, 28, 28, 0.35) !important;
    }
    div[data-testid="stToggle"] label,
    div[data-testid="stToggle"] p {
        font-family: 'Inter', sans-serif !important;
        font-size: 0.82rem !important;
        color: #cbd3ec !important;
        font-weight: 500 !important;
    }

    /* ---- text inputs (for the key editor) ---- */
    .stTextInput input {
        background-color: rgba(19, 35, 72, 0.6) !important;
        border: 1px solid #1e3268 !important;
        border-radius: 8px !important;
        color: #f8fafc !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.82rem !important;
        padding: 0.55rem 0.75rem !important;
    }
    .stTextInput input:focus {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2) !important;
    }
    .stTextInput label p {
        font-family: 'Inter', sans-serif !important;
        font-size: 0.78rem !important;
        color: #8b95c2 !important;
        font-weight: 500 !important;
    }

    /* ---- top bar ---- */
    .rb-top {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 1.4rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid #1e3268;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.62rem;
        letter-spacing: 0.28em;
        text-transform: uppercase;
        color: #6b7ba8;
        margin-bottom: 1.6rem;
    }
    .rb-top .cls { color: #60a5fa; }
    .rb-top .sep { color: #1e3268; }

    /* ---- tabs ---- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.4rem;
        background: transparent;
        border-bottom: 1px solid #1e3268;
        padding: 0;
        margin-bottom: 1.8rem;
        justify-content: center !important;
        display: flex !important;
    }
    .stTabs [data-baseweb="tab"] {
        height: 42px;
        border-radius: 0;
        padding: 0 1.4rem;
        color: #6b7ba8 !important;
        font-family: 'Inter', sans-serif;
        font-size: 0.82rem;
        font-weight: 500;
        letter-spacing: 0.02em;
        background: transparent !important;
        border-bottom: 2px solid transparent !important;
        border-left: none !important;
        border-top: none !important;
        border-right: none !important;
    }
    .stTabs [aria-selected="true"] {
        color: #ffffff !important;
        border-bottom: 2px solid #3b82f6 !important;
        background: transparent !important;
    }
    .stTabs [data-baseweb="tab-highlight"] { background: transparent !important; }
    .stTabs [data-baseweb="tab-border"] { background: transparent !important; }

    /* ---- hero ---- */
    .hero {
        text-align: center;
        padding-bottom: 2rem;
        margin-bottom: 1.6rem;
        border-bottom: 1px solid #1e3268;
    }
    .hero .eyebrow {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.66rem;
        letter-spacing: 0.36em;
        text-transform: uppercase;
        color: #6b7ba8;
        margin-bottom: 1.4rem;
    }
    .hero h1 {
        font-family: 'Inter', sans-serif;
        font-size: 3rem;
        font-weight: 800;
        letter-spacing: -0.035em;
        line-height: 1.05;
        color: #ffffff;
        margin: 0 0 1rem 0;
    }
    .hero h1 em {
        font-style: normal;
        color: #60a5fa;
        font-weight: 800;
    }
    .hero .lede {
        font-size: 1rem;
        line-height: 1.6;
        color: #8b95c2;
        max-width: 620px;
        margin: 0 auto 1.6rem;
    }
    .hero .state-row {
        display: inline-flex;
        align-items: center;
        gap: 0.7rem;
        padding: 0.55rem 1.2rem;
        border-radius: 999px;
        background: rgba(19, 35, 72, 0.7);
        border: 1px solid #1e3268;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        letter-spacing: 0.2em;
        text-transform: uppercase;
        font-weight: 600;
    }
    .state-dot {
        width: 8px; height: 8px; border-radius: 50%;
        background: currentColor;
        display: inline-block;
        box-shadow: 0 0 12px currentColor;
    }
    .state-ready { color: #22c55e; }
    .state-run   { color: #60a5fa; }
    .state-done  { color: #3b82f6; }
    .state-err   { color: #ef4444; }
    .state-run .state-dot { animation: pulse 1.4s ease-in-out infinite; }
    @keyframes pulse {
        0%,100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.4; transform: scale(0.85); }
    }
    .state-sep { color: #1e3268; }

    /* ---- section head ---- */
    .rb-sec {
        text-align: center;
        padding: 0.5rem 0 1rem;
        margin: 1.4rem 0 1rem;
    }
    .rb-sec .num {
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
        color: #60a5fa;
        font-size: 0.7rem;
        letter-spacing: 0.24em;
        font-weight: 700;
        margin-right: 0.8rem;
    }
    .rb-sec .ttl {
        display: inline-block;
        font-family: 'Inter', sans-serif;
        font-size: 0.82rem;
        letter-spacing: 0.24em;
        text-transform: uppercase;
        color: #8b95c2;
        font-weight: 600;
    }
    .rb-sec::after {
        content: "";
        display: block;
        width: 40px;
        height: 2px;
        background: #3b82f6;
        margin: 0.7rem auto 0;
        border-radius: 2px;
    }

    /* ---- stats ---- */
    .stats {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1rem;
        margin-bottom: 0.5rem;
    }
    .stat {
        background: linear-gradient(180deg, #132348 0%, #0e1a3d 100%);
        border: 1px solid #1e3268;
        border-radius: 12px;
        padding: 1.4rem 1rem 1.3rem;
        text-align: center;
        position: relative;
        transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
    }
    .stat:hover {
        transform: translateY(-3px);
        border-color: #2a3f7a;
        box-shadow: 0 12px 32px rgba(0,0,0,0.3);
    }
    .stat .lbl {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.62rem;
        letter-spacing: 0.24em;
        text-transform: uppercase;
        color: #6b7ba8;
        margin-bottom: 0.6rem;
    }
    .stat .val {
        font-family: 'Inter', sans-serif;
        font-size: 2.6rem;
        font-weight: 700;
        line-height: 1;
        letter-spacing: -0.03em;
        color: #ffffff;
        font-variant-numeric: tabular-nums;
    }
    .stat .val.crit  { color: #a78bfa; }
    .stat .val.high  { color: #60a5fa; }
    .stat .val.med   { color: #38bdf8; }
    .stat .ft {
        margin-top: 0.7rem;
        font-size: 0.72rem;
        color: #6b7ba8;
        letter-spacing: 0.02em;
    }
    .stat .stripe {
        position: absolute;
        top: 0; left: 50%;
        transform: translateX(-50%);
        width: 44px; height: 3px;
        border-radius: 0 0 3px 3px;
        background: var(--c, #3b82f6);
    }

    /* ---- toggles note ---- */
    .tgl-note {
        text-align: center;
        font-size: 0.78rem;
        color: #6b7ba8;
        margin: 0.3rem 0 1rem;
    }
    .tgl-note code {
        background: rgba(19, 35, 72, 0.6);
        border: 1px solid #1e3268;
        padding: 0.15rem 0.45rem;
        border-radius: 4px;
        color: #60a5fa;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
    }

    /* ---- agents ---- */
    .agents {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin-bottom: 0.5rem;
    }
    .agent {
        background: linear-gradient(180deg, #132348 0%, #0e1a3d 100%);
        border: 1px solid #1e3268;
        border-radius: 12px;
        padding: 1.4rem 1.2rem;
        text-align: center;
        position: relative;
        transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
    }
    .agent:hover {
        transform: translateY(-3px);
        border-color: #2a3f7a;
        box-shadow: 0 12px 32px rgba(0,0,0,0.3);
    }
    .agent .num {
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.62rem;
        letter-spacing: 0.22em;
        color: #6b7ba8;
        margin-bottom: 0.5rem;
    }
    .agent .nm {
        font-family: 'Inter', sans-serif;
        font-size: 1.35rem;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: -0.015em;
    }
    .agent .ds {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.6rem;
        letter-spacing: 0.26em;
        text-transform: uppercase;
        color: #6b7ba8;
        margin-top: 0.3rem;
    }
    .agent .bar {
        height: 3px;
        background: #1e3268;
        border-radius: 3px;
        margin: 1rem 0 0.75rem;
        position: relative;
        overflow: hidden;
    }
    .agent .bar .fill {
        position: absolute;
        top: 0; left: 0; bottom: 0;
        background: linear-gradient(90deg, #2563eb, #60a5fa);
        border-radius: 3px;
        transition: width 0.4s ease;
    }
    .agent .ft {
        display: flex;
        justify-content: center;
        gap: 1rem;
        align-items: baseline;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.62rem;
        letter-spacing: 0.2em;
        text-transform: uppercase;
    }
    .agent .ft .st { color: #6b7ba8; font-weight: 600; }
    .agent .ft .st.on   { color: #60a5fa; }
    .agent .ft .st.done { color: #22c55e; }
    .agent .ft .pc {
        color: #ffffff;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0;
    }

    /* ---- progress ---- */
    .pline {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.62rem;
        letter-spacing: 0.24em;
        text-transform: uppercase;
        color: #6b7ba8;
        margin: 1.4rem 0.2rem 0.6rem;
    }
    .pline .pc { color: #60a5fa; font-weight: 700; }
    .ptrack {
        height: 4px;
        background: #132348;
        border-radius: 4px;
        overflow: hidden;
        position: relative;
    }
    .pfill {
        position: absolute;
        top: 0; left: 0; bottom: 0;
        background: linear-gradient(90deg, #2563eb, #60a5fa);
        border-radius: 4px;
        transition: width 0.4s ease;
        box-shadow: 0 0 16px rgba(96, 165, 250, 0.5);
    }

    /* ---- console ---- */
    .con {
        background: #0a1535;
        border: 1px solid #1e3268;
        border-radius: 12px;
        overflow: hidden;
        margin-top: 1rem;
    }
    .con .hd {
        padding: 0.65rem 1rem;
        border-bottom: 1px solid #1e3268;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.6rem;
        letter-spacing: 0.26em;
        text-transform: uppercase;
        color: #6b7ba8;
        background: rgba(19, 35, 72, 0.4);
    }
    .con .hd .rr { color: #4d5a85; letter-spacing: 0.18em; }
    .con .bd {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.76rem;
        line-height: 1.7;
        padding: 0.9rem 1.1rem;
        overflow-y: auto;
        background: #08112b;
        scrollbar-width: thin;
        scrollbar-color: #1e3268 #08112b;
    }
    .con .bd::-webkit-scrollbar { width: 8px; }
    .con .bd::-webkit-scrollbar-thumb { background: #1e3268; border-radius: 4px; }
    .con .bd::-webkit-scrollbar-thumb:hover { background: #3b82f6; }
    .con .ln { display: flex; gap: 0.65rem; margin-bottom: 0.12rem; }
    .con .g { flex-shrink: 0; width: 0.85rem; text-align: center; }
    .con .t { word-break: break-word; }

    /* ---- notice ---- */
    .nt {
        border-radius: 12px;
        background: rgba(19, 35, 72, 0.6);
        border: 1px solid #1e3268;
        border-left: 4px solid #3b82f6;
        padding: 1rem 1.2rem;
        font-size: 0.92rem;
        color: #cbd3ec;
        line-height: 1.55;
        text-align: center;
    }
    .nt.success { border-left-color: #22c55e; }
    .nt.warning { border-left-color: #facc15; }
    .nt.error   { border-left-color: #ef4444; }
    .nt.info    { border-left-color: #3b82f6; }
    .nt .cap {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.6rem;
        letter-spacing: 0.26em;
        text-transform: uppercase;
        color: #8b95c2;
        display: block;
        margin-bottom: 0.4rem;
        font-weight: 700;
    }

    /* ---- tool card ---- */
    .tc {
        background: linear-gradient(180deg, #132348 0%, #0e1a3d 100%);
        border: 1px solid #1e3268;
        border-radius: 12px;
        padding: 1.5rem 1.3rem;
        height: 100%;
        text-align: center;
        transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
    }
    .tc:hover {
        transform: translateY(-3px);
        border-color: #2a3f7a;
        box-shadow: 0 12px 32px rgba(0,0,0,0.3);
    }
    .tc .num {
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
        color: #60a5fa;
        font-size: 0.68rem;
        letter-spacing: 0.24em;
        font-weight: 700;
        margin-bottom: 0.6rem;
    }
    .tc .tt {
        font-family: 'Inter', sans-serif;
        font-size: 1.2rem;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: -0.01em;
    }
    .tc .dd {
        font-size: 0.86rem;
        color: #8b95c2;
        line-height: 1.55;
        margin-top: 0.6rem;
    }
    .tc .cm {
        display: inline-block;
        margin-top: 1rem;
        padding: 0.32rem 0.7rem;
        background: rgba(10, 21, 53, 0.7);
        border: 1px solid #1e3268;
        border-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        color: #60a5fa;
        letter-spacing: 0.04em;
    }

    /* ---- code / dataframe ---- */
    .stCode, pre {
        background: #08112b !important;
        border: 1px solid #1e3268 !important;
        border-radius: 8px !important;
    }
    [data-testid="stDataFrame"] {
        border: 1px solid #1e3268;
        border-radius: 8px;
        overflow: hidden;
    }

    /* ---- expander ---- */
    .streamlit-expanderHeader, details summary {
        font-family: 'Inter', sans-serif !important;
        font-size: 0.82rem !important;
        color: #cbd3ec !important;
    }

    /* ---- tighten Streamlit wrappers ---- */
    [data-testid="stVerticalBlock"] > [style*="flex-direction: column"] > [data-testid="stVerticalBlock"] {
        gap: 0.5rem;
    }
    [data-testid="stHorizontalBlock"] { gap: 0.7rem; }
    </style>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------------- helpers

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
    # script_relative looks like "src/tools/check_keys.py", but PROJECT_ROOT
    # is already ~/.auto-cti/src/, so strip the leading "src/" to avoid
    # producing ~/.auto-cti/src/src/...
    rel = script_relative[4:] if script_relative.startswith("src/") else script_relative
    script_path = os.path.join(PROJECT_ROOT, rel)

    cmd = [sys.executable, "-u", script_path]
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

def get_severity_stats():
    pub_data, _ = load_latest_json(os.path.join(DATA_DIR, "publisher_agent_result"))
    if pub_data and "severity_stats" in pub_data:
        s = pub_data["severity_stats"]
        return s.get("Total", 0), s.get("Critical", 0), s.get("High", 0), s.get("Medium", 0)
    return 0, 0, 0, 0

def get_last_report_time():
    report_dir = os.path.join(DATA_DIR, "Reports")
    if not os.path.exists(report_dir):
        return None
    files = glob.glob(os.path.join(report_dir, "*.pdf"))
    if not files:
        return None
    return datetime.datetime.fromtimestamp(os.path.getctime(max(files, key=os.path.getctime)))

def render_notice(text, kind="info", caption="Notice"):
    st.markdown(compact(f"""
        <div class="nt {kind}">
            <span class="cap">{caption}</span>
            {text}
        </div>
    """), unsafe_allow_html=True)

def render_top_bar():
    st.markdown(compact(f"""
        <div class="rb-top">
            <span class="cls">{CLASSIFICATION}</span>
            <span class="sep">/</span>
            <span>AUTO-CTI · THREAT CONSOLE · REV 3</span>
        </div>
    """), unsafe_allow_html=True)

def render_hero(running, done):
    if running:
        cls, txt = "state-run", "Scanning in progress"
    elif done:
        cls, txt = "state-done", "Last analysis complete"
    else:
        cls, txt = "state-ready", "System ready"

    st.markdown(compact(f"""
        <div class="hero">
            <div class="eyebrow">Autonomous Cyber Threat Intelligence</div>
            <h1>Auto-<em>CTI</em> Threat Console</h1>
            <p class="lede">
                A multi-agent pipeline for the collection, triage, and publication
                of publicly disclosed vulnerabilities. Every score is cross-verified
                against authoritative records and reported with full provenance.
            </p>
            <div class="state-row {cls}">
                <span class="state-dot"></span>
                <span>{txt}</span>
                <span class="state-sep">/</span>
                <span style="color:#6b7ba8;">v3.0</span>
            </div>
        </div>
    """), unsafe_allow_html=True)

def render_stats():
    total, crit, high, med = get_severity_stats()
    st.markdown(compact(f"""
        <div class="stats">
            <div class="stat" style="--c:#60a5fa;">
                <div class="stripe"></div>
                <div class="lbl">Total CVEs</div>
                <div class="val">{total}</div>
                <div class="ft">Identified vulnerabilities</div>
            </div>
            <div class="stat" style="--c:#a78bfa;">
                <div class="stripe"></div>
                <div class="lbl">Critical</div>
                <div class="val crit">{crit}</div>
                <div class="ft">Immediate action required</div>
            </div>
            <div class="stat" style="--c:#3b82f6;">
                <div class="stripe"></div>
                <div class="lbl">High</div>
                <div class="val high">{high}</div>
                <div class="ft">Priority queue</div>
            </div>
            <div class="stat" style="--c:#38bdf8;">
                <div class="stripe"></div>
                <div class="lbl">Medium</div>
                <div class="val med">{med}</div>
                <div class="ft">Standard priority</div>
            </div>
        </div>
    """), unsafe_allow_html=True)

def render_section(num, title):
    st.markdown(compact(f"""
        <div class="rb-sec">
            <span class="num">{num}</span>
            <span class="ttl">{title}</span>
        </div>
    """), unsafe_allow_html=True)

def render_toggles():
    st.markdown(compact("""
        <div class="tgl-note">
            Feature toggles — click to write directly to <code>~/.auto-cti/.env</code>.
            Green means enabled, red means disabled.
        </div>
    """), unsafe_allow_html=True)
    cols = st.columns(len(TOGGLES))
    for col, (key, label, hint) in zip(cols, TOGGLES):
        with col:
            current = os.getenv(key, "false").lower() == "true"
            new_val = st.toggle(label, value=current, key=f"tgl_{key}", help=hint)
            if new_val != current:
                set_env_var(key, "true" if new_val else "false")
                st.rerun()

def render_agents(agents_state):
    cards = ""
    for i, stage in enumerate(PIPELINE_STAGES):
        pct = agents_state[i]["pct"]
        if pct == 100:
            st_cls, st_txt = "done", "Complete"
        elif pct > 0:
            st_cls, st_txt = "on", "Running"
        else:
            st_cls, st_txt = "", "Idle"

        cards += (
            f'<div class="agent">'
            f'<div class="num">{stage["num"]}</div>'
            f'<div class="nm">{stage["name"]}</div>'
            f'<div class="ds">{stage["desc"]}</div>'
            f'<div class="bar"><div class="fill" style="width:{pct}%;"></div></div>'
            f'<div class="ft"><span class="st {st_cls}">{st_txt}</span>'
            f'<span class="pc">{pct}%</span></div>'
            f'</div>'
        )
    st.markdown(f'<div class="agents">{cards}</div>', unsafe_allow_html=True)

def render_progress(pct):
    st.markdown(compact(f"""
        <div class="pline">
            <span>Pipeline progress</span>
            <span class="pc">{round(pct)}%</span>
        </div>
        <div class="ptrack"><div class="pfill" style="width:{pct}%;"></div></div>
    """), unsafe_allow_html=True)

# ---------------------------------------------------------------- console

def classify_log_line(line: str):
    noise = ["[CrewAIEventsBus]", "charmap", "codec can't encode",
             "character maps to <undefined>", "Sync handler error",
             "DeprecationWarning", "deprecated since", "has been renamed"]
    for p in noise:
        if p in line:
            return None
    l = line.strip().lower()
    if any(k in l for k in ["[ok]", "successfully", "generated successfully", "saved at", "finished successfully", "complete"]):
        return ("✓", "#22c55e", line.strip())
    if any(k in l for k in ["[failed]", "[exception]", "error:", "traceback", "exit code"]):
        return ("✕", "#ef4444", line.strip())
    if any(k in l for k in ["warning", "warn:", "could not parse", "skipping"]):
        return ("▲", "#facc15", line.strip())
    if any(k in l for k in ["waking up", "compiling", "agent is", "publisher agent",
                             "triage agent", "scout agent", "kickoff", "task started", "starting"]):
        return ("◆", "#60a5fa", line.strip())
    if any(k in l for k in ["api key", "loaded:", "base_url", "model:", "gemini", "ollama"]):
        return ("·", "#6b7ba8", line.strip())
    if line.strip():
        return ("·", "#cbd3ec", line.strip()[:180])
    return None

def render_console(log_lines, height=340):
    rows = ""
    for line in log_lines[-400:]:
        r = classify_log_line(line)
        if r is None:
            continue
        icon, color, text = r
        safe = text.replace("<", "&lt;").replace(">", "&gt;")
        rows += (f'<div class="ln">'
                 f'<span class="g" style="color:{color};">{icon}</span>'
                 f'<span class="t" style="color:{color};">{safe}</span>'
                 f'</div>')
    if not rows:
        rows = '<span style="color:#6b7ba8;">Awaiting agent output…</span>'
    html = compact(f"""
        <div class="con">
            <div class="hd">
                <span>Live Agent Console</span>
                <span class="rr">Stream · Tail · 400 lines</span>
            </div>
            <div class="bd" style="max-height:{height}px;">
                {rows}
            </div>
        </div>
    """)
    st.markdown(html, unsafe_allow_html=True)

# ---------------------------------------------------------------- pipeline tab

def run_agent_with_console(agents_ph, console_ph, agents_data, current_index, script_name):
    try:
        proc = subprocess.Popen(
            [sys.executable, "-u", script_name],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True,
            encoding="utf-8", errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"},
            cwd=PROJECT_ROOT
        )
        progress = 0
        last = time.time()
        while True:
            assert proc.stdout is not None
            line = proc.stdout.readline()
            if line == "" and proc.poll() is not None:
                break
            if line:
                st.session_state.console_log.append(line.rstrip())
                progress = min(progress + 4, 95)
                agents_data[current_index]["pct"] = progress
                if time.time() - last >= 0.5:
                    with agents_ph:
                        render_agents(agents_data)
                    with console_ph:
                        render_console(st.session_state.console_log)
                    last = time.time()
        if proc.returncode == 0:
            agents_data[current_index]["pct"] = 100
            st.session_state.console_log.append(f"[OK] {script_name} finished successfully.")
            with agents_ph:
                render_agents(agents_data)
            with console_ph:
                render_console(st.session_state.console_log)
            return True
        else:
            st.session_state.console_log.append(f"[FAILED] {script_name} exit {proc.returncode}.")
            st.error(f"Agent '{script_name}' failed with return code {proc.returncode}.")
            return False
    except Exception as e:
        st.session_state.console_log.append(f"[EXCEPTION] {e}")
        st.error(f"Exception while running {script_name}: {e}")
        return False

def render_pipeline_tab():
    if "running" not in st.session_state:
        st.session_state.running = False
    if "console_log" not in st.session_state:
        st.session_state.console_log = []

    done = get_last_report_time() is not None
    render_hero(st.session_state.running, done)

    if not st.session_state.running:
        render_section("01", "Statistical summary")
        render_stats()

        render_section("02", "Configuration")
        render_toggles()

        c1, c2, c3 = st.columns([1.5, 1, 1.5])
        with c2:
            if st.button("Initiate pipeline", use_container_width=True, type="primary"):
                st.session_state.running = True
                st.session_state.console_log = []
                os.environ["PIPELINE_START_TIME"] = str(time.time())
                st.rerun()

        last = get_last_report_time()
        if last:
            st.markdown(
                f"<p style='text-align:center; color:#6b7ba8; "
                f"font-family:JetBrains Mono,monospace; font-size:0.62rem; "
                f"letter-spacing:0.24em; text-transform:uppercase; "
                f"margin-top:1rem;'>"
                f"Last report · {last.strftime('%d %b %Y · %H:%M')}</p>",
                unsafe_allow_html=True
            )
        return

    # ---- running ----
    if "agents_state" not in st.session_state:
        st.session_state.agents_state = [{"name": s["name"], "pct": 0} for s in PIPELINE_STAGES]

    render_section("01", "Statistical summary")
    render_stats()

    total_pct = sum(a["pct"] for a in st.session_state.agents_state) / len(PIPELINE_STAGES)
    render_progress(total_pct)

    render_section("02", "Agent execution")
    agents_ph = st.empty()
    with agents_ph:
        render_agents(st.session_state.agents_state)

    console_ph = st.empty()
    with console_ph:
        render_console(st.session_state.console_log)

    for i, stage in enumerate(PIPELINE_STAGES):
        if st.session_state.agents_state[i]["pct"] < 100:
            ok = run_agent_with_console(
                agents_ph, console_ph,
                st.session_state.agents_state, i, stage["script"]
            )
            if not ok:
                st.error(f"{stage['name']} agent failed. Pipeline stopped.")
                c1, c2, c3 = st.columns([1.5, 1, 1.5])
                with c2:
                    if st.button(f"Retry {stage['name']}", use_container_width=True):
                        st.session_state.agents_state[i]["pct"] = 0
                        st.rerun()
                st.stop()

    all_done = all(a["pct"] == 100 for a in st.session_state.agents_state)
    if all_done:
        with agents_ph:
            render_agents(st.session_state.agents_state)

        st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)
        render_notice("Pipeline completed. The final briefing has been published by the Publisher Agent.",
                      "success", "Status")

        render_section("03", "Outputs & artifacts")
        render_console_tools()
        render_detailed_stats()

        c1, c2, c3 = st.columns([1.5, 1, 1.5])
        with c2:
            if st.button("Reset system", use_container_width=True):
                st.session_state.running = False
                if "agents_state" in st.session_state:
                    del st.session_state.agents_state
                st.session_state.console_log = []
                st.rerun()

def render_console_tools():
    c1, c2, c3 = st.columns(3)
    report_dir = os.path.join(DATA_DIR, "Reports")
    pdfs = glob.glob(os.path.join(report_dir, "*.pdf")) if os.path.exists(report_dir) else []
    with c1:
        if pdfs:
            latest = max(pdfs, key=os.path.getctime)
            with open(latest, "rb") as f:
                st.download_button("Download PDF briefing", data=f.read(),
                                   file_name=os.path.basename(latest),
                                   mime="application/pdf", use_container_width=True)
        else:
            st.button("Download PDF briefing", disabled=True, use_container_width=True)
    pub, path = load_latest_json(os.path.join(DATA_DIR, "publisher_agent_result"))
    with c2:
        if pub:
            st.download_button("Download JSON feed",
                               data=json.dumps(pub, indent=2, ensure_ascii=False),
                               file_name=os.path.basename(path),
                               mime="application/json", use_container_width=True)
        else:
            st.button("Download JSON feed", disabled=True, use_container_width=True)
    with c3:
        if st.button("Clear console log", use_container_width=True):
            st.session_state.console_log = []
            st.rerun()

def render_detailed_stats():
    st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)
    pub, _ = load_latest_json(os.path.join(DATA_DIR, "publisher_agent_result"))
    if pub and "cve_summary" in pub:
        df = pd.DataFrame(pub["cve_summary"])
    else:
        tri, _ = load_latest_json(os.path.join(DATA_DIR, "triage_agent_result"))
        df = pd.DataFrame(tri) if isinstance(tri, list) else pd.DataFrame()
    if not df.empty:
        rename = {"cve_id":"CVE ID","description":"Description","cvss_score":"CVSS",
                  "severity":"Severity","cwe_id":"CWE","urgency_score":"Urgency",
                  "mitre_mappings":"MITRE","references":"References"}
        cols = [c for c in rename if c in df.columns]
        st.dataframe(df[cols].rename(columns=rename),
                     use_container_width=True, hide_index=True)
    else:
        render_notice("No vulnerability data is available yet.", "info", "Notice")

# ---------------------------------------------------------------- tools

TOOL_CARDS = [
    {"num": "01",
     "ttl": "Verify Urgency",
     "dsc": "Recompute each Urgency Score against the deterministic formula and report any drift.",
     "cmd": "auto-cti -v",
     "script": "src/tools/verify_urgency.py", "key": "t_verify"},
    {"num": "02",
     "ttl": "PoC Breakdown",
     "dsc": "Classify every CVE by PoC provenance: external, patch-derived, non-PoC, or absent.",
     "cmd": "auto-cti -b",
     "script": "src/tools/poc_breakdown.py", "key": "t_poc"},
    {"num": "03",
     "ttl": "Archive Run",
     "dsc": "Snapshot the current pipeline outputs into a numbered run directory for reproducibility.",
     "cmd": "auto-cti -a",
     "script": "src/tools/archive_run.py", "key": "t_archive"},
]

def render_tools_panel():
    st.markdown(
        "<p style='text-align:center; font-size:0.92rem; color:#8b95c2; "
        "line-height:1.55; max-width:620px; margin:0 auto 1.8rem;'>"
        "Verification utilities that operate on the current data directory "
        "<code style='color:#60a5fa; font-family:\"JetBrains Mono\",monospace; "
        "background:rgba(19,35,72,0.6); padding:0.12rem 0.4rem; "
        "border:1px solid #1e3268; border-radius:4px;'>~/.auto-cti/data/</code>."
        "</p>",
        unsafe_allow_html=True
    )
    cols = st.columns(3)
    for col, card in zip(cols, TOOL_CARDS):
        with col:
            st.markdown(compact(f"""
                <div class="tc">
                    <div class="num">{card['num']}</div>
                    <div class="tt">{card['ttl']}</div>
                    <div class="dd">{card['dsc']}</div>
                    <div class="cm">$ {card['cmd']}</div>
                </div>
            """), unsafe_allow_html=True)
            if st.button("Execute", key=card["key"], use_container_width=True):
                with st.spinner(f"Running {card['ttl']}…"):
                    out, ok = run_tool(card["script"])
                st.session_state.tool_output = out
                st.session_state.tool_name = card["ttl"]
                st.session_state.tool_ok = ok

    if st.session_state.get("tool_output"):
        ok = st.session_state.get("tool_ok", True)
        render_section("·", st.session_state.get("tool_name", "Tool") +
                       (" — completed" if ok else " — finished with issues"))
        st.code(st.session_state.tool_output, language="text")
        if st.button("Clear output", key="clear_tool_output"):
            st.session_state.tool_output = ""
            st.session_state.tool_name = ""
            st.rerun()

# ---------------------------------------------------------------- config

def render_config_panel():
    st.markdown(
        "<p style='text-align:center; font-size:0.92rem; color:#8b95c2; "
        "line-height:1.55; max-width:620px; margin:0 auto 1.8rem;'>"
        "Manage your API keys below. Values are written to "
        "<code style='color:#60a5fa; font-family:\"JetBrains Mono\",monospace; "
        "background:rgba(19,35,72,0.6); padding:0.12rem 0.4rem; "
        "border:1px solid #1e3268; border-radius:4px;'>~/.auto-cti/.env</code> "
        "with file mode 600."
        "</p>",
        unsafe_allow_html=True
    )

    # -------- Key editor --------
    render_section("01", "API key editor")

    current = read_env_values()

    with st.form("keys_form", clear_on_submit=False):
        new_values = {}

        for group_name, fields in KEY_GROUPS:
            st.markdown(
                f"<div style='font-family:\"JetBrains Mono\",monospace; "
                f"font-size:0.66rem; letter-spacing:0.22em; text-transform:uppercase; "
                f"color:#6b7ba8; margin:1rem 0 0.4rem;'>{group_name}</div>",
                unsafe_allow_html=True
            )
            cols = st.columns(2)
            for idx, (key, label, is_secret) in enumerate(fields):
                col = cols[idx % 2]
                with col:
                    existing = current.get(key, "")
                    val = st.text_input(
                        label,
                        value="" if is_secret else existing,
                        placeholder=f"paste {key}" if is_secret else "",
                        type="password" if is_secret else "default",
                        key=f"kf_{key}",
                        help=f"Environment variable: {key}"
                    )
                    new_values[key] = val

        submitted = st.form_submit_button("Save all keys", use_container_width=True, type="primary")

    if submitted:
        merged = dict(current)
        for k, v in new_values.items():
            v = (v or "").strip()
            if v:
                merged[k] = v
        write_env_file(merged)
        load_env()
        st.success("✅ Keys saved to ~/.auto-cti/.env")
        st.rerun()

    # -------- Diagnostics --------
    render_section("02", "Diagnostics")

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(compact("""
            <div class="tc">
                <div class="num">I.</div>
                <div class="tt">Check API Keys</div>
                <div class="dd">Live-test every configured key against its provider. Prints OK or FAIL with status codes; never reveals the key.</div>
                <div class="cm">$ auto-cti -k</div>
            </div>
        """), unsafe_allow_html=True)
        if st.button("Run key check", key="cfg_check", use_container_width=True):
            with st.spinner("Testing API keys…"):
                out, ok = run_tool("src/tools/check_keys.py")
            st.session_state.tool_output = out
            st.session_state.tool_name = "Check API Keys"
            st.session_state.tool_ok = ok

    with c2:
        st.markdown(compact("""
            <div class="tc">
                <div class="num">II.</div>
                <div class="tt">Download .env</div>
                <div class="dd">Download a copy of the current environment file for archival or inspection on another machine.</div>
                <div class="cm">backup</div>
            </div>
        """), unsafe_allow_html=True)
        if os.path.exists(ENV_PATH):
            with open(ENV_PATH, "rb") as f:
                st.download_button("Download .env", data=f.read(),
                                   file_name="auto-cti.env.txt", mime="text/plain",
                                   use_container_width=True)
        else:
            st.button("Download .env", disabled=True, use_container_width=True)

    if st.session_state.get("tool_output") and st.session_state.get("tool_name") == "Check API Keys":
        ok = st.session_state.get("tool_ok", True)
        render_section("·", "API key status" + (" — all pass" if ok else " — attention required"))
        st.code(st.session_state.tool_output, language="text")

# ---------------------------------------------------------------- reports

def list_archived_runs():
    if not os.path.exists(RUNS_DIR):
        return []
    runs = []
    for d in sorted(os.listdir(RUNS_DIR), reverse=True):
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
    return runs

def render_reports_panel():
    render_section("01", "Published briefings")
    report_dir = os.path.join(DATA_DIR, "Reports")
    if not os.path.exists(report_dir):
        render_notice("No briefings have been generated yet.", "info", "Notice")
    else:
        pdfs = sorted(glob.glob(os.path.join(report_dir, "*.pdf")),
                      key=os.path.getctime, reverse=True)
        if not pdfs:
            render_notice("The reports directory is empty.", "info", "Notice")
        else:
            for pdf_file in pdfs:
                name = os.path.basename(pdf_file)
                ts = datetime.datetime.fromtimestamp(
                    os.path.getctime(pdf_file)
                ).strftime("%d %b %Y · %H:%M")
                c1, c2 = st.columns([4, 1])
                with c1:
                    st.markdown(
                        f"<div style='padding:0.85rem 0; border-bottom:1px solid #1e3268; "
                        f"font-size:0.94rem; color:#f8fafc; font-weight:500;'>"
                        f"{name}<span style='color:#6b7ba8; font-family:\"JetBrains Mono\",monospace; "
                        f"font-size:0.68rem; letter-spacing:0.08em; margin-left:1rem;'>{ts}</span></div>",
                        unsafe_allow_html=True
                    )
                with c2:
                    with open(pdf_file, "rb") as f:
                        st.download_button("Download", data=f.read(),
                                           file_name=name, mime="application/pdf",
                                           key=pdf_file, use_container_width=True)

    render_section("02", "Archived runs")
    runs = list_archived_runs()
    if not runs:
        render_notice("No archived runs yet. Use the Archive tool to snapshot the current state.",
                      "info", "Notice")
        return
    for name, path, meta in runs:
        ts = meta.get("timestamp", "")
        files = meta.get("files", [])
        toggles = meta.get("toggles", {})
        active = [k for k, v in toggles.items() if str(v).lower() == "true"]
        with st.expander(f"{name} · {len(files)} file(s)"):
            st.markdown(f"**Path** · `{path}`")
            if ts:
                st.markdown(f"**Timestamp** · `{ts}`")
            st.markdown(f"**Active toggles** · {', '.join(active) if active else '_none_'}")
            st.markdown(f"**Files** · {', '.join(files) if files else '_none_'}")

# ---------------------------------------------------------------- main

def main():
    inject_custom_css()

    if "running" not in st.session_state:
        st.session_state.running = False
    if "console_log" not in st.session_state:
        st.session_state.console_log = []
    if "tool_output" not in st.session_state:
        st.session_state.tool_output = ""
    if "tool_name" not in st.session_state:
        st.session_state.tool_name = ""

    missing = get_missing_keys()
    if missing:
        st.warning("A required API key is missing. Please enter it below to enable the pipeline.")
        with st.form("api_keys_form"):
            new_env = {}
            for key, url in missing.items():
                st.markdown(f"**{key}** ([get it here]({url}))")
                new_env[key] = st.text_input(f"Enter {key}", type="password", key=f"key_{key}")
            if st.form_submit_button("Save keys"):
                current = load_env()
                for k, v in new_env.items():
                    if v:
                        current[k] = v
                save_env(current)
                st.success("Keys saved. Reloading…")
                st.rerun()
        st.stop()

    render_top_bar()

    tab_pipeline, tab_tools, tab_config, tab_reports = st.tabs([
        "Pipeline", "Analysis Tools", "Configuration", "Reports"
    ])
    with tab_pipeline:
        render_pipeline_tab()
    with tab_tools:
        render_tools_panel()
    with tab_config:
        render_config_panel()
    with tab_reports:
        render_reports_panel()

if __name__ == "__main__":
    main()