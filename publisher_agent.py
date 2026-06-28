import os
import json
import datetime
import re
import sys
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv
from fpdf import FPDF
from fpdf.enums import XPos, YPos

sys.stdout.reconfigure(encoding='utf-8')  # type: ignore

load_dotenv()

today_date = datetime.datetime.now().strftime("%B %d, %Y")

triage_dir = os.path.join("JoFile", "triage_agent_result")
list_of_files = [os.path.join(triage_dir, f) for f in os.listdir(triage_dir) if f.endswith(".json")]

if not list_of_files:
    print("Error: No Triage Report found. Please run triage_agent.py first.")
    exit()

latest_file = max(list_of_files, key=os.path.getctime)

try:
    with open(latest_file, 'r', encoding='utf-8') as f:
        file_content = f.read()
        if not file_content.strip():
            print(f"Error: The file {latest_file} is empty. Please run triage_agent.py again.")
            exit()
        triage_data = json.loads(file_content)
        if isinstance(triage_data, list):
            report_date = today_date
        else:
            report_date = triage_data.get("date", today_date)
            triage_data = triage_data.get("report", [])
            if isinstance(triage_data, str):
                triage_data = json.loads(triage_data)
except json.JSONDecodeError:
    print(f"Error: The file {latest_file} contains invalid JSON. Please run triage_agent.py again.")
    exit()

if not isinstance(triage_data, list):
    print("Error: Triage data is not a list of CVE objects. Cannot build report.")
    exit()

output_dir = os.path.join("JoFile", "publisher_agent_result")
os.makedirs(output_dir, exist_ok=True)

reports_dir = os.path.join("JoFile", "Reports")
os.makedirs(reports_dir, exist_ok=True)


def build_cve_summary(data: list) -> list:
    seen = set()
    normalized = []
    for entry in data:
        cve_id = entry.get("CVE_ID", "N/A")
        if cve_id in seen:
            continue
        seen.add(cve_id)
        try:
            urgency = int(entry.get("Urgency_Score", 0))
        except (ValueError, TypeError):
            urgency = 0
        normalized.append({
            "cve_id":         cve_id,
            "description":    entry.get("Description", "No description available."),
            "cvss_score":     entry.get("CVSS_Score", "N/A"),
            "severity":       entry.get("CVSS_Severity", "Unknown"),
            "cwe_id":         entry.get("CWE_ID", "N/A"),
            "mitre_mappings": entry.get("MITRE_Mappings", []),
            "urgency_score":  urgency,
            "references":     entry.get("References", []),
        })
    return sorted(normalized, key=lambda x: x["urgency_score"], reverse=True)


def compute_severity_stats(data: list) -> dict:
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    seen  = set()
    for entry in data:
        cid = entry.get("CVE_ID", "")
        if cid in seen:
            continue
        seen.add(cid)
        sev = str(entry.get("CVSS_Severity", "Unknown")).strip().capitalize()
        if sev not in stats:
            sev = "Unknown"
        stats[sev] += 1
    stats["Total"] = len(seen)
    return stats


cve_summary    = build_cve_summary(triage_data)
severity_stats = compute_severity_stats(triage_data)

publisher_llm = LLM(
    model="gemini/gemini-3.1-flash-lite",
    api_key=os.getenv("GEMINI_API_KEY"),
    max_retries=5  # type: ignore
)

publisher_agent = Agent(
    role='Senior Security Communications Officer',
    goal='Compile analyzed threat data into a formal, authoritative executive briefing.',
    backstory=(
        'You are a senior security communications officer responsible for producing '
        'formal cyber threat intelligence briefings for executive leadership and the board. '
        'Your writing is precise, professional, and free of casual language. You write with the '
        'authority and rigor expected of a formal organizational security document.'
    ),
    verbose=True,
    llm=publisher_llm,
    allow_delegation=False
)

safe_date        = report_date.replace(", ", "_").replace(" ", "_")
json_output_path = os.path.join(output_dir, f'Executive_Briefing_{safe_date}.json')

publish_task = Task(
    description=f'''You are a Senior Security Communications Officer producing a formal
    Cyber Threat Intelligence Executive Briefing for {report_date}.

    SEVERITY BREAKDOWN — use these exact numbers, do not recalculate:
    Critical: {severity_stats['Critical']}
    High:     {severity_stats['High']}
    Medium:   {severity_stats['Medium']}
    Low:      {severity_stats['Low']}
    Total Vulnerabilities Analyzed: {severity_stats['Total']}

    TOP CVEs BY URGENCY (for context — do NOT enumerate these in your output):
    {json.dumps([{"cve_id": c["cve_id"], "severity": c["severity"], "urgency_score": c["urgency_score"], "description": c["description"][:120]} for c in cve_summary[:5]], indent=2)}

    YOUR TASK — produce TWO sections only:

    SECTION 1 — Executive Summary (4-6 sentences):
    - State the date and total vulnerability count
    - Reference the exact severity breakdown numbers above
    - Describe the overall organizational risk posture using CVSS v3.1 terminology
    - Name the single most critical threat by CVE ID and explain why it is the top priority
    - State the recommended immediate response posture (e.g. emergency patching, isolation)
    - Keep the tone formal, authoritative, and board-level

    SECTION 2 — Critical Action List:
    - Write one action item per High or Critical CVE
    - Each action must be a formal imperative directive with a specific timeframe
    - Order from most urgent (highest Urgency Score) to least urgent
    - Include only CVEs with severity High or Critical

    CRITICAL OUTPUT RULES — you MUST follow these exactly:
    1. Output ONLY a valid JSON object. No markdown. No code fences. No extra text.
    2. The "executive_summary" value MUST be a single plain string on one line — no newlines inside it.
    3. Use exactly this structure:
    {{
      "report_date": "{report_date}",
      "executive_summary": "single plain string with no newlines",
      "critical_actions": ["action 1", "action 2", "action 3"]
    }}''',
    expected_output='A single valid JSON object with keys: report_date, executive_summary, critical_actions.',
    agent=publisher_agent,
    output_file=json_output_path
)

publisher_crew = Crew(
    agents=[publisher_agent],
    tasks=[publish_task],
    verbose=True
)


def sanitize_text(text) -> str:
    if not isinstance(text, str):
        return str(text)
    text = text.strip()
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    elif text.startswith('{') and text.endswith('}') and '"executive_summary"' not in text:
        text = text[1:-1]
    return text.strip()


def clean_for_pdf(text: str) -> str:
    replacements = {
        '\u201c': '"', '\u201d': '"', '\u2018': "'", '\u2019': "'",
        '\u2013': '-', '\u2014': '-', '\u2026': '...',
        '\u2022': '-', '\u00b7': '-',
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text.encode('latin-1', 'replace').decode('latin-1')


def severity_color(severity: str):
    s = (severity or "").strip().lower()
    if s == "critical": return (185, 28, 28)
    if s == "high":     return (217, 119, 6)
    if s == "medium":   return (8, 145, 178)
    if s == "low":      return (75, 85, 99)
    return (100, 116, 139)


def collapse_string_newlines(text: str) -> str:
    result_chars = []
    inside_string = False
    escape_next   = False
    for ch in text:
        if escape_next:
            result_chars.append(ch)
            escape_next = False
            continue
        if ch == '\\':
            escape_next = True
            result_chars.append(ch)
            continue
        if ch == '"':
            inside_string = not inside_string
        if inside_string and ch == '\n':
            result_chars.append(' ')
            continue
        result_chars.append(ch)
    return ''.join(result_chars)


CLASSIFICATION = "TLP:AMBER - FOR INTERNAL DISTRIBUTION ONLY"


class CTIReportPDF(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 9, 'F')
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", 'B', 8)
        self.set_y(2)
        self.cell(0, 5, CLASSIFICATION, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.ln(9)

    def footer(self):
        self.set_y(-15)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Helvetica", 'I', 7)
        self.set_text_color(120, 120, 120)
        self.set_y(-12)
        self.cell(
            0, 6,
            f"{CLASSIFICATION}  |  Auto-CTI Automated Threat Intelligence System  |  Page {self.page_no()}",
            new_x=XPos.RIGHT, new_y=YPos.TOP, align='C'
        )


def section_header(pdf: FPDF, number: str, title: str):
    pdf.set_font("Helvetica", 'B', 13)
    pdf.set_text_color(15, 23, 42)
    pdf.set_fill_color(235, 240, 248)
    pdf.cell(0, 9, text=f"{number}. {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
    pdf.ln(2)


def generate_pdf_briefing(briefing: dict, cve_list: list, stats: dict, output_path: str) -> None:
    pdf = CTIReportPDF()
    pdf.set_auto_page_break(auto=True, margin=22)
    pdf.add_page()

    pdf.set_font("Helvetica", 'B', 20)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 12, text="Cyber Threat Intelligence", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.cell(0, 12, text="Executive Briefing",        new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

    pdf.set_font("Helvetica", '', 10)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, text=clean_for_pdf(f"Report Date: {briefing.get('report_date', today_date)}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.cell(0, 6, text=f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} UTC  |  Classification: TLP:AMBER",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.cell(0, 6, text="Prepared by: Auto-CTI Autonomous Threat Intelligence Pipeline",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(6)

    pdf.set_draw_color(15, 23, 42)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    section_header(pdf, "1", "Risk Statistics Summary")
    pdf.set_font("Helvetica", 'B', 10)
    col_w  = 38
    labels = ["Critical", "High", "Medium", "Low", "Total"]
    for label in labels:
        color = severity_color(label) if label != "Total" else (15, 23, 42)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(*color)
        pdf.cell(col_w, 9, text=label, border=0, fill=True, align='C',
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.ln(9)
    pdf.set_font("Helvetica", 'B', 12)
    pdf.set_text_color(15, 23, 42)
    for label in labels:
        value = stats.get(label, 0)
        pdf.set_fill_color(243, 244, 246)
        pdf.cell(col_w, 10, text=str(value), border=1, fill=True, align='C',
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.ln(14)

    section_header(pdf, "2", "Executive Summary")
    pdf.set_font("Helvetica", '', 11)
    pdf.set_text_color(30, 30, 30)
    summary = clean_for_pdf(sanitize_text(briefing.get("executive_summary", "Not available.")))
    pdf.multi_cell(0, 6.5, text=summary, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)

    section_header(pdf, "3", "Critical Action List")
    pdf.set_font("Helvetica", '', 11)
    pdf.set_text_color(30, 30, 30)
    actions = briefing.get("critical_actions", [])
    if actions:
        for i, action in enumerate(actions, start=1):
            clean_action = clean_for_pdf(sanitize_text(action))
            pdf.set_font("Helvetica", 'B', 10)
            pdf.set_text_color(185, 28, 28)
            pdf.cell(8, 6, text=f"{i}.", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", '', 10)
            pdf.set_text_color(30, 30, 30)
            pdf.multi_cell(0, 6, text=clean_action, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
    else:
        pdf.cell(0, 6, text="No critical actions identified.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    section_header(pdf, "4", "Quick Reference: All Identified Vulnerabilities")
    pdf.set_font("Helvetica", 'B', 9)
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(55, 8, text="CVE ID",     border=1, fill=True, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(25, 8, text="CVSS Score", border=1, fill=True, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(30, 8, text="Severity",   border=1, fill=True, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(25, 8, text="Urgency",    border=1, fill=True, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(0,  8, text="CWE",        border=1, fill=True, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", '', 9)
    for entry in cve_list:
        r, g, b = severity_color(entry["severity"])
        pdf.set_text_color(0, 0, 0)
        pdf.cell(55, 7, text=clean_for_pdf(entry["cve_id"]),            border=1, align='L',  new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(25, 7, text=str(entry.get("cvss_score", "N/A")),       border=1, align='C',  new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_text_color(r, g, b)
        pdf.cell(30, 7, text=clean_for_pdf(entry["severity"]),          border=1, align='C',  new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(25, 7, text=str(entry["urgency_score"]) + "/100",      border=1, align='C',  new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(0,  7, text=clean_for_pdf(entry.get("cwe_id", "N/A")), border=1, align='C',  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if not cve_list:
        pdf.cell(0, 8, text="No CVE entries found.", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(8)

    section_header(pdf, "5", "Detailed Vulnerability Findings")
    pdf.ln(2)

    for entry in cve_list:
        r, g, b = severity_color(entry["severity"])

        pdf.set_font("Helvetica", 'B', 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 7, text=clean_for_pdf(entry["cve_id"]),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", 'B', 9)
        pdf.set_text_color(r, g, b)
        pdf.cell(0, 6, text=clean_for_pdf(
            f"CVSS v3.1 Score: {entry.get('cvss_score', 'N/A')}  |  "
            f"Severity: {entry['severity']}  |  "
            f"Urgency Score: {entry['urgency_score']}/100  |  "
            f"CWE: {entry.get('cwe_id', 'N/A')}"
        ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        mitre = entry.get("mitre_mappings", [])
        if mitre:
            pdf.set_font("Helvetica", 'I', 9)
            pdf.set_text_color(70, 100, 160)
            pdf.cell(0, 6, text=clean_for_pdf("MITRE ATT&CK: " + ", ".join(mitre)),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", '', 10)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(0, 5.5, text=clean_for_pdf(entry["description"]),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        refs = entry.get("references", [])
        if refs:
            pdf.set_font("Helvetica", 'I', 8)
            pdf.set_text_color(100, 116, 139)
            for ref in refs:
                pdf.multi_cell(0, 5, text=clean_for_pdf(f"  Ref: {ref}"),
                               new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_draw_color(210, 218, 230)
        pdf.ln(2)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

    section_header(pdf, "6", "Methodology & Data Sources")
    pdf.set_font("Helvetica", '', 10)
    pdf.set_text_color(30, 30, 30)
    methodology = (
        "This report was generated by the Auto-CTI Autonomous Cyber Threat Intelligence Pipeline, "
        "an automated multi-agent system designed to simulate a real-world Security Operations Center (SOC) workflow. "
        "The pipeline operates in three sequential stages: (1) the Scout Agent collects the latest CVE disclosures "
        "from the GitHub Advisory Database and cross-references active threat pulses via AlienVault OTX; "
        "(2) the Triage Agent performs structured analysis using the CVSS v3.1 scoring standard, assigns CWE root-cause "
        "classifications, maps each vulnerability to relevant MITRE ATT&CK techniques, and computes a composite "
        "Urgency Score; (3) the Publisher Agent synthesizes the triaged data into this executive briefing. "
        "All CVE identifiers, CVSS scores, and CWE mappings are sourced directly from official databases and "
        "are verifiable via the references provided in Section 5. "
        "Severity classification follows the CVSS v3.1 standard: Critical (9.0-10.0), High (7.0-8.9), "
        "Medium (4.0-6.9), Low (0.1-3.9)."
    )
    pdf.multi_cell(0, 6, text=clean_for_pdf(methodology), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.set_font("Helvetica", 'B', 9)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, text="Primary Data Sources:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", '', 9)
    pdf.set_text_color(30, 30, 30)
    sources = [
        "GitHub Advisory Database  --  https://github.com/advisories",
        "NIST National Vulnerability Database (NVD)  --  https://nvd.nist.gov/",
        "AlienVault Open Threat Exchange (OTX)  --  https://otx.alienvault.com/",
        "MITRE ATT&CK Framework  --  https://attack.mitre.org/",
        "CVSS v3.1 Specification  --  https://www.first.org/cvss/v3.1/specification-document",
        "Common Weakness Enumeration (CWE)  --  https://cwe.mitre.org/",
        "CVE Program  --  https://www.cve.org/",
    ]
    for src in sources:
        pdf.cell(0, 6, text=clean_for_pdf(f"  - {src}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output(output_path)


if __name__ == "__main__":
    print(f"Publisher Agent is compiling the formal executive briefing for: {report_date}...")
    result = publisher_crew.kickoff()

    raw_result = str(result).strip()

    if raw_result.startswith("```json"):
        raw_result = raw_result[7:]
    if raw_result.startswith("```"):
        raw_result = raw_result[3:]
    if raw_result.endswith("```"):
        raw_result = raw_result[:-3]
    raw_result = raw_result.strip()

    match = re.search(r'\{.*\}', raw_result, re.DOTALL)
    if match:
        raw_result = match.group(0)

    raw_result = collapse_string_newlines(raw_result)

    try:
        parsed = json.loads(raw_result)

        parsed["cve_summary"]    = cve_summary
        parsed["severity_stats"] = severity_stats

        with open(json_output_path, 'w', encoding='utf-8') as f:
            json.dump(parsed, f, indent=4, ensure_ascii=False)

        print("\n================================================")
        print("Executive Briefing (JSON) Generated Successfully!")
        print("================================================")
        print(f"JSON Report saved at: {json_output_path}")
        print(f"Total CVEs included in report: {len(cve_summary)}")

        timestamp       = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_output_path = os.path.join(reports_dir, f"AutoCTI_Report_{timestamp}.pdf")
        generate_pdf_briefing(parsed, cve_summary, severity_stats, pdf_output_path)
        print(f"PDF Report saved at: {pdf_output_path}")

    except json.JSONDecodeError as e:
        print(f"\nWarning: Could not parse LLM output as clean JSON: {e}")
        print("PDF generation was skipped.")
        print(f"Raw output preview:\n{raw_result[:500]}")