# 🛡️ Auto-CTI — Autonomous Cyber Threat Intelligence Triage & Reporting Network

> **TLP:AMBER** — For internal distribution only.  
> An academic internship project demonstrating a production-grade, multi-agent AI pipeline for automated cybersecurity threat intelligence.

**Author:** Abdullah Al Smadi  
**Supervisor:** Dr. Ahmet Albayrak

---

## 📋 Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Agent Descriptions](#agent-descriptions)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Running the System](#running-the-system)
- [Output & Reports](#output--reports)
- [Data Sources & Standards](#data-sources--standards)
- [References](#references)

---

## Overview

**Auto-CTI** is an autonomous, multi-agent Cyber Threat Intelligence (CTI) pipeline built with the [CrewAI](https://github.com/joaomdmoura/crewAI) framework. It is designed to simulate a real-world Security Operations Center (SOC) workflow by automatically:

1. **Collecting** the latest CVEs from official sources (NIST NVD, GitHub Advisory Database, AlienVault OTX).
2. **Triaging** threats using real CVSS v3.1 scores, CWE classification, MITRE ATT&CK mapping, and proof-of-concept analysis.
3. **Publishing** structured executive briefings as both JSON feeds and professional PDF reports.

The system is fully automated — a single command runs the entire pipeline end-to-end. A Streamlit-based SOC dashboard provides live monitoring and report download capabilities.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Auto-CTI Pipeline                        │
│                                                             │
│   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐  │
│   │             │    │              │    │              │  │
│   │  Scout      │───▶│  Triage      │───▶│  Publisher   │  │
│   │  Agent      │    │  Agent       │    │  Agent       │  │
│   │             │    │              │    │              │  │
│   │  Gemini     │    │  Gemini      │    │  Gemini      │  │
│   │  Flash Lite │    │  Flash Lite  │    │  Flash Lite  │  │
│   │  (Cloud)    │    │  (Cloud)     │    │  (Cloud)     │  │
│   └─────────────┘    └──────────────┘    └──────────────┘  │
│          │                  │                   │           │
│   NIST NVD +           CVSS v3.1 +         JSON Feed +      │
│   GitHub Advisory      CWE + MITRE         PDF Report       │
│   AlienVault OTX       ATT&CK + PoC                         │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Streamlit SOC     │
                    │  Dashboard         │
                    │  (dashboard.py)    │
                    └────────────────────┘
```

The pipeline is orchestrated by `main_system.py` using **CrewAI Flow**, which enforces sequential execution with dependency checks between stages.

---

## Agent Descriptions

### 1. Scout Agent (`scout_agent.py`)
**Role:** Data Collector  
**LLM:** `gemini/gemini-3.1-flash-lite` via Google Gemini API (cloud)

Fetches the most recent CVEs from multiple authoritative sources with automatic fallback. For each CVE found, it extracts:
- Official CVE ID and English description
- Real **CVSS v3.1** base score and severity label (Critical / High / Medium / Low)
- **CWE** (Common Weakness Enumeration) ID — the root cause category of the vulnerability
- Active threat pulse data from **AlienVault OTX**

All data is saved to `JoFile/Scout_Agent_Results/cti_report.json`, keyed by date.

**Data Sources (with automatic fallback):**
1. [NIST NVD CVE API v2.0](https://nvd.nist.gov/developers/vulnerabilities) — primary source
2. [GitHub Advisory Database (GraphQL)](https://github.com/advisories) — primary fallback
3. [OSV.dev API](https://osv.dev/) — secondary fallback

---

### 2. Triage Agent (`triage_agent.py`)
**Role:** Threat Analyst  
**LLM:** `gemini/gemini-3.1-flash-lite` via Google Gemini API (cloud)

The most intelligence-intensive agent in the pipeline. It processes the Scout's raw data and produces a structured, actionable threat assessment for each CVE:

| Field | Description |
|---|---|
| `CVE_ID` | Official CVE identifier |
| `Finding_Name` | Short human-readable title (3–8 words) |
| `Description` | Concise, analyst-grade 2–3 sentence description |
| `CVSS_Score` | Numeric base score from CVSS v3.1 (e.g., 9.8) |
| `CVSS_Severity` | Severity label (Critical / High / Medium / Low) |
| `CVSS_Vector` | Full CVSS v3.1 vector string (e.g., CVSS:3.1/AV:N/AC:L/...) |
| `CVSS_Breakdown` | Human-readable values for all 8 base metrics |
| `CWE_ID` | Root cause weakness (e.g., CWE-79, CWE-89) |
| `MITRE_Mappings` | Relevant ATT&CK technique codes (e.g., T1190) |
| `Urgency_Score` | Custom 1–100 score based on CVSS + active exploitation signals |
| `PoC` | 2–4 sentence proof-of-concept describing realistic exploitation |
| `References` | Verifiable NVD and CVE.org URLs for the CVE |

**Standards Used:**
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CWE Database](https://cwe.mitre.org/)

---

### 3. Publisher Agent (`publisher_agent.py`)
**Role:** Reporter  
**LLM:** `gemini/gemini-3.1-flash-lite` via Google Gemini API (cloud)

Compiles the triaged data into two professional outputs:

- **JSON Feed** — Structured machine-readable report suitable for SIEM ingestion (`JoFile/publisher_agent_result/`)
- **PDF Briefing** — Executive-ready PDF with TLP:AMBER classification, severity statistics, executive summary, critical action list, CVE quick-reference table, and detailed findings per CVE including CVSS v3.1 scoring criteria tables and proof-of-concept blocks (`JoFile/Reports/`)

PDF generation is handled directly in Python using [`fpdf2`](https://py-pdf.github.io/fpdf2/) without relying on the LLM for data enumeration, ensuring accuracy and completeness.

---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Agent Framework | [CrewAI](https://github.com/joaomdmoura/crewAI) | Multi-agent orchestration |
| Pipeline Orchestration | CrewAI Flow | Sequential stage control |
| LLM (All Agents) | `gemini/gemini-3.1-flash-lite` via [Google Gemini API](https://ai.google.dev/) | Cloud inference for all three agents |
| CVE Data Source (Primary) | [NIST NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities) | Official vulnerability database |
| CVE Data Source (Fallback) | [GitHub Advisory Database](https://github.com/advisories) | GraphQL API, always available |
| Threat Intel Source | [AlienVault OTX API](https://otx.alienvault.com/api) | Active threat pulse data |
| PDF Generation | [fpdf2](https://py-pdf.github.io/fpdf2/) | Professional report rendering |
| Dashboard | [Streamlit](https://streamlit.io/) | SOC monitoring interface |
| Environment Management | [python-dotenv](https://pypi.org/project/python-dotenv/) | Secure API key handling |

---

## Project Structure

```
Auto-CTI/
│
├── scout_agent.py          # Stage 1: CVE collection from NIST / GitHub Advisory / OTX
├── triage_agent.py         # Stage 2: CVSS/CWE/MITRE/PoC analysis via Gemini
├── publisher_agent.py      # Stage 3: JSON + PDF report generation
├── main_system.py          # Pipeline orchestrator (CrewAI Flow)
├── dashboard.py            # Streamlit SOC dashboard
│
├── .env                    # API keys (NOT committed to version control)
├── .env.example            # Template for required environment variables
├── requirements.txt        # Python dependencies
│
└── JoFile/                 # Runtime output directory (auto-created)
    ├── Scout_Agent_Results/
    │   └── cti_report.json                 # Raw CVE data keyed by date
    ├── triage_agent_result/
    │   └── Triaged_Report_<date>.json      # Analyzed CVE list
    ├── publisher_agent_result/
    │   └── Executive_Briefing_<date>.json  # Full briefing with stats
    └── Reports/
        └── AutoCTI_Report_<timestamp>.pdf  # Final PDF report
```

---

## Prerequisites

Before running Auto-CTI, ensure the following are available:

- **Python 3.10+** — [python.org](https://www.python.org/downloads/)
- **A Google Gemini API key** — [aistudio.google.com](https://aistudio.google.com/) (free tier available)
- **An AlienVault OTX API key** — [otx.alienvault.com](https://otx.alienvault.com/) (free registration)
- **An NVD API key** (optional but recommended to avoid rate limits) — [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

> No local model or GPU is required. All inference runs via the Gemini cloud API.

---

## Installation & Setup

**1. Clone the repository**
```bash
git clone https://github.com/your-username/auto-cti.git
cd auto-cti
```

**2. Create and activate a virtual environment**
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Linux / macOS:
source venv/bin/activate
```

**3. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**4. Configure environment variables**
```bash
cp .env.example .env
# Then edit .env and fill in your API keys (see Configuration section)
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```env
# .env

# Google Gemini API Key — used by all three agents (Scout, Triage, Publisher)
# Get yours at: https://aistudio.google.com/
GEMINI_API_KEY=your_gemini_api_key_here

# AlienVault OTX API Key — used by the Scout Agent for active threat pulses
# Get yours at: https://otx.alienvault.com/ (free account)
OTX_API_KEY=your_otx_api_key_here

# NIST NVD API Key — optional, but reduces rate limiting on the primary CVE source
# Get yours at: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your_nvd_api_key_here
```

> ⚠️ **Never commit your `.env` file to version control.** It is already listed in `.gitignore`.

---

## Running the System

### Option A — Streamlit Dashboard (Recommended)

The dashboard provides a live SOC console with real-time agent logs, progress rings, and one-click report download.

```bash
streamlit run dashboard.py
```

Then open your browser at `http://localhost:8501` and click **INITIALIZE SYSTEM**.

### Option B — Command Line (Full Pipeline)

Runs all three agents sequentially via CrewAI Flow:

```bash
python main_system.py
```

### Option C — Run Agents Individually

```bash
python scout_agent.py      # Step 1: Fetch CVEs
python triage_agent.py     # Step 2: Analyze threats (requires scout output)
python publisher_agent.py  # Step 3: Generate reports (requires triage output)
```

---

## Output & Reports

After a successful pipeline run, two report files are generated:

### JSON Feed (`JoFile/publisher_agent_result/`)
Machine-readable structured data suitable for SIEM integration:
```json
{
  "report_date": "June 29, 2026",
  "executive_summary": "...",
  "critical_actions": ["..."],
  "severity_stats": { "Critical": 2, "High": 4, "Medium": 3, "Total": 9 },
  "cve_summary": [
    {
      "cve_id": "CVE-2026-XXXX",
      "finding_name": "Remote Code Execution in Example Component",
      "description": "...",
      "cvss_score": 9.8,
      "severity": "Critical",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvss_breakdown": {
        "Attack_Vector": "Network",
        "Attack_Complexity": "Low",
        "Privileges_Required": "None",
        "User_Interaction": "None",
        "Scope": "Unchanged",
        "Confidentiality": "High",
        "Integrity": "High",
        "Availability": "High"
      },
      "cwe_id": "CWE-89",
      "mitre_mappings": ["T1190"],
      "urgency_score": 97,
      "poc": "An unauthenticated attacker can exploit this by...",
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXX",
        "https://www.cve.org/CVERecord?id=CVE-2026-XXXX"
      ]
    }
  ]
}
```

### PDF Briefing (`JoFile/Reports/`)
A TLP:AMBER classified PDF containing:
- **Section 1** — Risk statistics summary table (Critical / High / Medium / Low / Total)
- **Section 2** — Executive summary (CISO/board level)
- **Section 3** — Critical action list (ordered by urgency score)
- **Section 4** — Quick reference CVE table with Finding Name column
- **Section 5** — Detailed vulnerability findings per CVE, including:
  - CVSS v3.1 Scoring Criteria two-column table with color-coded metric values
  - CVSS vector string
  - Description, Proof of Concept block, MITRE ATT&CK mappings, and verifiable references
- **Section 6** — Methodology and data sources

---

## Data Sources & Standards

| Standard / Source | Description | Reference |
|---|---|---|
| NIST NVD | Official U.S. government CVE database (primary) | https://nvd.nist.gov/ |
| GitHub Advisory Database | Google-backed advisory DB, GraphQL API (fallback) | https://github.com/advisories |
| AlienVault OTX | Open Threat Exchange — active threat pulses | https://otx.alienvault.com/ |
| CVSS v3.1 | Common Vulnerability Scoring System | https://www.first.org/cvss/ |
| CWE | Common Weakness Enumeration | https://cwe.mitre.org/ |
| MITRE ATT&CK | Adversary tactics & techniques framework | https://attack.mitre.org/ |
| TLP | Traffic Light Protocol (data sharing classification) | https://www.cisa.gov/tlp |

---

## References

- CrewAI Documentation — https://docs.crewai.com/
- Google Gemini API — https://ai.google.dev/
- NIST NVD API v2.0 Documentation — https://nvd.nist.gov/developers/vulnerabilities
- GitHub Advisory Database GraphQL API — https://docs.github.com/en/graphql
- MITRE ATT&CK Navigator — https://mitre-attack.github.io/attack-navigator/
- CVSS v3.1 Calculator — https://www.first.org/cvss/calculator/3.1
- fpdf2 Documentation — https://py-pdf.github.io/fpdf2/
- Streamlit Documentation — https://docs.streamlit.io/

---

<div align="center">

**Auto-CTI** · Autonomous Cyber Threat Intelligence Pipeline  
Built with CrewAI · Google Gemini · NIST NVD · MITRE ATT&CK

---

**Developed by:** Abdullah Al Smadi  
**Supervisor:** Dr. Ahmet Albayrak  

*Internship Project — For Academic and Demonstration Purposes*

</div>
