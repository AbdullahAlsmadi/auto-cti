# 🛡️ Auto-CTI — Autonomous Cyber Threat Intelligence Triage & Reporting Network

> **TLP:AMBER** — For internal distribution only.
> An academic internship project demonstrating a production-grade, multi-agent AI pipeline for automated cybersecurity threat intelligence.

**Author:** Abdullah Al Smadi
**Supervisor:** Dr. Ahmet Albayrak

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Agent Descriptions](#agent-descriptions)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Running the System](#running-the-system)
- [Output & Reports](#output--reports)
- [Validation Metrics](#validation-metrics)
- [Data Sources & Standards](#data-sources--standards)
- [Limitations & Future Enhancements](#limitations--future-enhancements)
- [References](#references)

---

## Overview

**Auto-CTI** is an autonomous, multi-agent Cyber Threat Intelligence (CTI) pipeline built with the [CrewAI](https://github.com/joaomdmoura/crewAI) framework. It is designed to simulate a real-world Security Operations Center (SOC) workflow by automatically:

1. **Collecting** the latest CVEs from official sources (NIST NVD, GitHub Advisory Database, OSV.dev, AlienVault OTX).
2. **Triaging** threats using real CVSS v3.1 scores, CWE classification, MITRE ATT&CK mapping, and proof-of-concept enrichment from 8+ exploit databases.
3. **Publishing** structured executive briefings as both JSON feeds and professional PDF reports with clickable reference hyperlinks.

The system is fully automated — a single command runs the entire pipeline end-to-end. A Streamlit-based SOC dashboard provides live monitoring, progress tracking, and report download capabilities.

---

## Key Features

- ✅ **Fully automated pipeline** — from data collection to executive report generation
- ✅ **100% CVSS score verification** — all scores cross-verified against NVD, CVE.org, and Tenable
- ✅ **8+ PoC/exploit sources** — NVD, GitHub (curated + general), Vulners, Packet Storm, inTheWild, Sploitus, 0day.today, Exploit-DB
- ✅ **Professional PDF reports** — TLP:AMBER classified, with clickable hyperlinks to official references
- ✅ **Secure API key storage** — keys stored in `~/.auto-cti/config/.env` with `600` permissions
- ✅ **Interactive first-run setup** — prompts for missing API keys with direct sign-up URLs
- ✅ **Terminal dashboard** — live SOC console with agent progress rings and smart log filtering
- ✅ **One-command installation** — `curl | bash` for Linux systems
- ✅ **Cross-platform** — works on Linux (primary), macOS, and Windows (WSL recommended)

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         Auto-CTI Pipeline                                    │
│                                                                              │
│   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│   │             │    │              │    │              │    │            │ │
│   │  Scout      │───▶│  Triage      │───▶│  Publisher   │───▶│ Dashboard  │ │
│   │  Agent      │    │  Agent       │    │  Agent       │    │ (Streamlit)│ │
│   │             │    │              │    │              │    │            │ │
│   │  Gemini     │    │  Gemini      │    │  Gemini      │    │  Live      │ │
│   │  Flash Lite │    │  Flash Lite  │    │  Flash Lite  │    │  Console   │ │
│   │  (Cloud)    │    │  (Cloud)     │    │  (Cloud)     │    │  Reports   │ │
│   └─────────────┘    └──────────────┘    └──────────────┘    └────────────┘ │
│          │                  │                   │                           │
│   NIST NVD +           CVSS v3.1 +         JSON Feed +                     │
│   GitHub Advisory      CWE + MITRE         PDF Report                      │
│   OSV.dev              ATT&CK + PoC        Clickable Links                 │
│   AlienVault OTX       (8 sources)                                         │
└──────────────────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  ~/.auto-cti/data/ │
                    │  (Secure Storage)  │
                    └────────────────────┘
```

The pipeline is orchestrated by `main_system.py` using **CrewAI Flow**, which enforces sequential execution with dependency checks between stages.

---

## Agent Descriptions

### 1. Scout Agent (`scout_agent.py`)
**Role:** Data Collector
**LLM:** `gemini/gemini-3.5-flash-lite` via Google Gemini API (cloud)

Fetches the most recent CVEs from multiple authoritative sources with automatic fallback. For each CVE found, it extracts:
- Official CVE ID and English description
- Real **CVSS v3.1** base score and severity label (Critical / High / Medium / Low)
- **CWE** (Common Weakness Enumeration) ID — the root cause category of the vulnerability
- Active threat pulse data from **AlienVault OTX**

**Data Sources (with automatic fallback):**
1. [NIST NVD CVE API v2.0](https://nvd.nist.gov/developers/vulnerabilities) — primary source
2. [GitHub Advisory Database (GraphQL)](https://github.com/advisories) — primary fallback
3. [OSV.dev API](https://osv.dev/) — secondary fallback

**Deduplication:** Uses **MAMORE** (cross-run tracking of seen CVE IDs) to ensure no CVE is ever reported twice across different daily runs.

---

### 2. Triage Agent (`triage_agent.py`)
**Role:** Threat Analyst
**LLM:** `gemini/gemini-3.5-flash-lite` via Google Gemini API (cloud)

The most intelligence-intensive agent in the pipeline. It processes the Scout's raw data and produces a structured, actionable threat assessment for each CVE:

| Field | Description |
|---|---|
| `CVE_ID` | Official CVE identifier |
| `Finding_Name` | Short human-readable title (3–8 words) |
| `Description` | Concise, analyst-grade 3-sentence description |
| `CVSS_Score` | Numeric base score from CVSS v3.1 (e.g., 9.8) |
| `CVSS_Severity` | Severity label (Critical / High / Medium / Low / None) |
| `CVSS_Vector` | Full CVSS v3.1 vector string |
| `CVSS_Breakdown` | Human-readable values for all 8 base metrics |
| `CWE_ID` | Root cause weakness (e.g., CWE-79, CWE-89) |
| `MITRE_Mappings` | Relevant ATT&CK technique codes (e.g., T1190) |
| `Urgency_Score` | Custom 1–100 score based on CVSS + active exploitation signals |
| `PoC` | 4-sentence technical proof-of-concept describing realistic exploitation |
| `References` | Verifiable NVD, CVE.org, and Tenable URLs |

**PoC Enrichment Sources (8 sources):**
1. NVD / CVE.org tagged exploit references
2. GitHub curated repositories (`nomi-sec/PoC-in-GitHub`, `trickest/cve`, etc.)
3. GitHub general repository search
4. Vulners aggregated exploit index
5. Packet Storm Security
6. inTheWild.io
7. Sploitus (aggregator)
8. Exploit-DB

**Standards Used:**
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CWE Database](https://cwe.mitre.org/)

---

### 3. Publisher Agent (`publisher_agent.py`)
**Role:** Reporter
**LLM:** `gemini/gemini-3.5-flash-lite` via Google Gemini API (cloud)

Compiles the triaged data into two professional outputs:

- **JSON Feed** — Structured machine-readable report suitable for SIEM ingestion (`~/.auto-cti/data/publisher_agent_result/`)
- **PDF Briefing** — Executive-ready PDF with TLP:AMBER classification, severity statistics, executive summary, critical action list, CVE quick-reference table, and detailed findings per CVE including:
  - CVSS v3.1 scoring criteria tables with color-coded metric values
  - Clickable hyperlinks to NVD, CVE.org, and Tenable references
  - Proof-of-concept blocks
  - PoC Discovery Summary, CVSS Score Validation, System Performance Metrics, and Limitations & Future Enhancements sections

PDF generation is handled directly in Python using [`fpdf2`](https://py-pdf.github.io/fpdf2/) without relying on the LLM for data enumeration, ensuring accuracy and completeness.

---

### 4. Dashboard (`dashboard.py`)
**Role:** SOC Monitoring Console
**Technology:** Streamlit

The dashboard provides a live SOC console with:
- Progress rings for each agent (Scout, Triage, Publisher)
- Real-time agent logs with smart filtering (removes CrewAI internal noise, encoding errors)
- Metric cards showing total CVEs and severity breakdown (Critical / High / Medium)
- One-click report download for PDF and JSON
- Report history with download buttons for all previous reports
- Dark/Light theme toggle
- TLP:AMBER classification banner

---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Agent Framework | [CrewAI](https://github.com/joaomdmoura/crewAI) | Multi-agent orchestration |
| Pipeline Orchestration | CrewAI Flow | Sequential stage control |
| LLM (All Agents) | `gemini/gemini-3.5-flash-lite` via [Google Gemini API](https://ai.google.dev/) | Cloud inference for all three agents |
| CVE Data Source (Primary) | [NIST NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities) | Official vulnerability database |
| CVE Data Source (Fallback) | [GitHub Advisory Database](https://github.com/advisories) | GraphQL API, always available |
| CVE Data Source (Secondary) | [OSV.dev API](https://osv.dev/) | Open Source Vulnerabilities |
| Threat Intel Source | [AlienVault OTX API](https://otx.alienvault.com/api) | Active threat pulse data |
| PoC/Exploit Sources | 8 sources (NVD, GitHub, Vulners, Packet Storm, inTheWild, Sploitus, 0day.today, Exploit-DB) | Comprehensive exploit coverage |
| PDF Generation | [fpdf2](https://py-pdf.github.io/fpdf2/) | Professional report rendering with hyperlinks |
| Dashboard | [Streamlit](https://streamlit.io/) | SOC monitoring interface |
| Secure Config | python-dotenv + custom secure storage | API keys in `~/.auto-cti/config/.env` with `600` permissions |
| Terminal Dashboard | Rich | Live terminal-based SOC console |

---

## Project Structure

```
Auto-CTI/
│
├── src/
│   ├── __init__.py
│   ├── utils/
│   │   ├── __init__.py
│   │   └── secure_config.py          # Secure API key management
│   ├── scout_agent.py                # Stage 1: CVE collection
│   ├── triage_agent.py               # Stage 2: CVSS/CWE/MITRE/PoC analysis
│   ├── publisher_agent.py            # Stage 3: JSON + PDF report generation
│   └── dashboard.py                  # Streamlit SOC dashboard
│
├── install.sh                        # One-command Linux installer
├── uninstall.sh                       # Clean removal script
├── requirements.txt                  # Python dependencies
├── README.md
├── LICENSE
├── .gitignore
└── .env.example                      # Template for environment variables
```

**Runtime Data (auto-created in `~/.auto-cti/`):**

```
~/.auto-cti/
├── config/
│   └── .env                          # Secure API keys (600 permissions)
└── data/
    ├── Scout_Agent_Results/
    │   └── cti_report.json                  # Raw CVE data keyed by date
    ├── triage_agent_result/
    │   └── Triaged_Report_<date>.json       # Analyzed CVE list
    ├── publisher_agent_result/
    │   └── Executive_Briefing_<date>.json   # Full briefing with stats
    ├── Reports/
    │   └── AutoCTI_Report_<timestamp>.pdf   # Final PDF report
    ├── PoC_Gap_Reports/
    │   └── PoC_Gap_Report_<date>.json       # PoC gap analysis
    └── MAMORE/
        └── seen_cve_ids.json                # Deduplication tracking
```

---

## Prerequisites

Before running Auto-CTI, ensure the following are available:

- **Python 3.9+** — [python.org](https://www.python.org/downloads/)
- **A Google Gemini API key** — [aistudio.google.com](https://aistudio.google.com/) (free tier available)
- **An NVD API key** (recommended) — [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
- **A GitHub Personal Access Token** (recommended) — [github.com/settings/tokens](https://github.com/settings/tokens)
- **A Vulners API key** (optional) — [vulners.com/register](https://vulners.com/register)
- **An AlienVault OTX API key** (optional) — [otx.alienvault.com](https://otx.alienvault.com/) (free registration)
- **OpenCVE credentials** (optional) — [www.opencve.io/register](https://www.opencve.io/register)

> No local model or GPU is required. All inference runs via the Gemini cloud API. On first run, the system will prompt for any missing API keys with direct sign-up URLs.

---

## Installation & Setup

### Linux (One-Command Installation)

```bash
curl -sSL https://raw.githubusercontent.com/your-username/Auto-CTI/main/install.sh | bash
```

This installs everything to `~/.auto-cti/` and creates the `auto-cti` command in `~/.local/bin`.

### Manual Installation (All Platforms)

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

**4. Configure environment variables (optional — first run will prompt for keys)**
```bash
cp .env.example .env
# Then edit .env and fill in your API keys (see Configuration section)
```

---

## Configuration

On first run, the system will interactively prompt for any missing API keys with sign-up URLs. Alternatively, you can manually create `~/.auto-cti/config/.env`:

```env
# Google Gemini API Key — used by all three agents
GEMINI_API_KEY=your_gemini_api_key_here

# NIST NVD API Key — reduces rate limiting on the primary CVE source
NVD_API_KEY=your_nvd_api_key_here

# GitHub Personal Access Token — increases GitHub API rate limit
GITHUB_TOKEN=your_github_token_here

# Vulners API Key — for exploit enrichment
VULNERS_API_KEY=your_vulners_api_key_here

# AlienVault OTX API Key — for active threat pulses
OTX_API_KEY=your_otx_api_key_here

# OpenCVE credentials (optional)
OPENCVE_USERNAME=your_opencve_username
OPENCVE_PASSWORD=your_opencve_password
```

> ⚠️ **Never commit your `.env` file to version control.** The system stores keys securely in `~/.auto-cti/config/.env` with `600` permissions.

---

## Running the System

### Option A — Streamlit Dashboard (Recommended)

The dashboard provides a live SOC console with real-time agent logs, progress rings, and one-click report download.

```bash
streamlit run src/dashboard.py

# Or after installation:
auto-cti dashboard
```

Then open your browser at `http://localhost:8501` and click **INITIALIZE SYSTEM**.

### Option B — Command Line (Full Pipeline)

Runs all three agents sequentially:

```bash
# After installation:
auto-cti full

# Or manually:
python src/scout_agent.py && python src/triage_agent.py && python src/publisher_agent.py
```

### Option C — Run Agents Individually

```bash
auto-cti scout      # Step 1: Fetch CVEs
auto-cti triage     # Step 2: Analyze threats (requires scout output)
auto-cti publish    # Step 3: Generate reports (requires triage output)
```

---

## Output & Reports

After a successful pipeline run, all reports are stored in `~/.auto-cti/data/`.

### JSON Feed (`~/.auto-cti/data/publisher_agent_result/`)

Machine-readable structured data suitable for SIEM integration:

```json
{
  "report_date": "July 24, 2026",
  "executive_summary": "...",
  "critical_actions": ["..."],
  "severity_stats": { "Critical": 16, "High": 48, "Medium": 33, "Low": 3, "Total": 100 },
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
      "urgency_score": 88,
      "poc": "An unauthenticated attacker can exploit this by...",
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXX",
        "https://www.cve.org/CVERecord?id=CVE-2026-XXXX",
        "https://www.tenable.com/cve/CVE-2026-XXXX"
      ]
    }
  ]
}
```

### PDF Briefing (`~/.auto-cti/data/Reports/`)

A TLP:AMBER classified PDF containing:

- **Section 1** — Risk statistics summary table (Critical / High / Medium / Low / Total)
- **Section 2** — Executive summary (CISO/board level)
- **Section 3** — Critical action list (ordered by urgency score)
- **Section 4** — Quick reference CVE table with Finding Name column
  - **Section 4.1** — PoC Discovery Summary (success rate analysis)
  - **Section 4.2** — CVSS Score Validation (verification statistics)
  - **Section 4.3** — System Performance Metrics
  - **Section 4.4** — Limitations and Future Enhancements
- **Section 5** — Detailed vulnerability findings per CVE, including:
  - CVSS v3.1 Scoring Criteria two-column table with color-coded metric values
  - CVSS vector string
  - Description, Proof of Concept block, MITRE ATT&CK mappings
  - Clickable hyperlinks to NVD, CVE.org, and Tenable references
- **Section 6** — Methodology and data sources

---

## Validation Metrics

The system automatically computes and reports the following validation metrics in every PDF report:

| Metric | Description | Typical Value |
|---|---|---|
| PoC Discovery Rate | Percentage of CVEs with external exploit/PoC references | 25–65% (higher for older CVEs) |
| CVSS Verification Rate | Percentage of scores confirmed against authoritative sources | 100% (all verified) |
| Total Processing Time | Time from start to finish | ~2–3 minutes for 100 CVEs |
| Sources Queried | Number of PoC/exploit sources checked | 8 sources |

---

## Data Sources & Standards

| Standard / Source | Description | Reference |
|---|---|---|
| NIST NVD | Official U.S. government CVE database (primary) | https://nvd.nist.gov/ |
| GitHub Advisory Database | Google-backed advisory DB, GraphQL API (fallback) | https://github.com/advisories |
| OSV.dev | Open Source Vulnerabilities database | https://osv.dev/ |
| AlienVault OTX | Open Threat Exchange — active threat pulses | https://otx.alienvault.com/ |
| CVSS v3.1 | Common Vulnerability Scoring System | https://www.first.org/cvss/ |
| CWE | Common Weakness Enumeration | https://cwe.mitre.org/ |
| MITRE ATT&CK | Adversary tactics & techniques framework | https://attack.mitre.org/ |
| TLP | Traffic Light Protocol (data sharing classification) | https://www.cisa.gov/tlp |
| Exploit-DB | Official exploit database | https://www.exploit-db.com/ |
| Vulners | Aggregated vulnerability database | https://vulners.com/ |
| Packet Storm | Security exploit archive | https://packetstormsecurity.com/ |
| Sploitus | Exploit aggregator | https://sploitus.com/ |
| inTheWild.io | Active exploitation tracking | https://inthewild.io/ |

---

## Limitations & Future Enhancements

### Current Limitations
- PoC gaps exist for brand-new CVEs — expected and normal (public exploits take time to develop)
- Vulners free plan — limited to 100 credits/day (402 errors handled gracefully)
- Scraping-based sources (Packet Storm, Sploitus) — may break if HTML structure changes
- No caching mechanism — re-fetches all data each run
- Sequential processing — no parallelism between agents (future enhancement)

### Planned Improvements
- Local result cache — reduce redundant API calls
- Parallel processing — reduce total runtime
- Additional exploit databases — Rapid7, Seebug, CXSecurity
- Fine-tuned LLM — custom model for threat intelligence
- REST API — expose pipeline as a service
- Docker container — for easier deployment

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