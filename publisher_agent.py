import os
import json
import datetime
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv
from fpdf import FPDF

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
            triage_content = json.dumps(triage_data, indent=2)
        else:
            report_date = triage_data.get("date", today_date)
            triage_content = triage_data.get("report", str(triage_data))
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
    normalized = []
    for entry in data:
        try:
            urgency = int(entry.get("Urgency_Score", 0))
        except (ValueError, TypeError):
            urgency = 0
        normalized.append({
            "cve_id": entry.get("CVE_ID", "N/A"),
            "description": entry.get("Description", "No description available."),
            "cvss_score": entry.get("CVSS_Score", "N/A"),
            "severity": entry.get("CVSS_Severity", "Unknown"),
            "cwe_id": entry.get("CWE_ID", "N/A"),
            "mitre_mappings": entry.get("MITRE_Mappings", []),
            "urgency_score": urgency,
        })
    return sorted(normalized, key=lambda x: x["urgency_score"], reverse=True)

def compute_severity_stats(data: list) -> dict:
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for entry in data:
        sev = str(entry.get("CVSS_Severity", "Unknown")).strip().capitalize()
        if sev not in stats:
            sev = "Unknown"
        stats[sev] += 1
    stats["Total"] = len(data)
    return stats

cve_summary = build_cve_summary(triage_data)
severity_stats = compute_severity_stats(triage_data)

publisher_llm = LLM(
    model="ollama/qwen2.5",
    base_url="http://localhost:11434"
)

publisher_agent = Agent(
    role='Senior Security Communications Officer',
    goal='Compile analyzed threat data into a formal, authoritative executive briefing.',
    backstory='''You are a senior security communications officer responsible for producing
    formal cyber threat intelligence briefings for executive leadership and the board.
    Your writing is precise, professional, and free of casual language. You write with the
    authority and rigor expected of a formal organizational security document.''',
    verbose=True,
    llm=publisher_llm,
    allow_delegation=False
)

safe_date = report_date.replace(", ", "_").replace(" ", "_")
json_output_path = os.path.join(output_dir, f'Executive_Briefing_{safe_date}.json')

publish_task = Task(
    description=f'''Read the following Triage Analysis statistics and CVE data for {report_date}
    and produce ONLY a formal Executive Summary and a Critical Action List.
    Do NOT attempt to enumerate or copy individual CVE entries — that is handled separately.

    SEVERITY BREAKDOWN (use these exact numbers, do not recalculate):
    Critical: {severity_stats['Critical']}, High: {severity_stats['High']},
    Medium: {severity_stats['Medium']}, Low: {severity_stats['Low']},
    Total Vulnerabilities Analyzed: {severity_stats['Total']}

    RAW CVE CONTEXT (for understanding the nature of the threats only):
    {json.dumps(cve_summary, indent=2)}

    INSTRUCTIONS:
    1. Write a formal, authoritative Executive Summary (3-5 sentences) for a CISO/board audience.
       State the organization's overall risk posture, reference the exact severity numbers above,
       and identify the single most urgent concern by name. Use precise, professional,
       security-industry terminology. Do NOT use casual phrasing.
    2. Write a Critical Action List: each item must be a formal, imperative directive
       (e.g. "Apply vendor-issued patches for CVE-XXXX-XXXX within 24 hours."),
       ordered from most to least urgent. Base actions only on the Critical and High
       severity items provided above.

    CRITICAL FORMATTING INSTRUCTIONS (MUST FOLLOW):
    1. Output EXCLUSIVELY a valid JSON object. No markdown, no code fences, no extra text.
    2. The value of "executive_summary" MUST be a single plain string — do NOT wrap it
       in extra curly braces {{}} or additional quotation marks.
    3. Use exactly this structure:
       {{
         "report_date": "{report_date}",
         "executive_summary": "...",
         "critical_actions": ["...", "..."]
       }}''',
    expected_output='A single valid JSON object with only "report_date", "executive_summary", and "critical_actions".',
    agent=publisher_agent,
    output_file=json_output_path
)

publisher_crew = Crew(
    agents=[publisher_agent],
    tasks=[publish_task],
    verbose=True
)

def sanitize_text_field(text) -> str:
    if not isinstance(text, str):
        return str(text)
    text = text.strip()
    if text.startswith('{"') and text.endswith('"}'):
        text = text[2:-2]
    elif text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    elif text.startswith('{') and text.endswith('}'):
        text = text[1:-1]
    return text.strip()

def clean_text_for_pdf(text: str) -> str:
    replacements = {
        '\u201c': '"', '\u201d': '"', '\u2018': "'", '\u2019': "'",
        '\u2013': '-', '\u2014': '-', '\u2026': '...',
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text.encode('latin-1', 'replace').decode('latin-1')

def severity_color(severity: str):
    severity = (severity or "").strip().lower()
    if severity == "critical":
        return (185, 28, 28)
    elif severity == "high":
        return (217, 119, 6)
    elif severity == "medium":
        return (8, 145, 178)
    elif severity == "low":
        return (75, 85, 99)
    return (100, 116, 139)

CLASSIFICATION = "TLP:AMBER - FOR INTERNAL DISTRIBUTION ONLY"

class CTIReportPDF(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 9, 'F')
        self.set_text_color(255, 255, 255)
        self.set_font("Arial", 'B', 8)
        self.set_y(2)
        self.cell(0, 5, CLASSIFICATION, 0, 0, 'C') # type: ignore
        self.ln(14)

    def footer(self):
        self.set_y(-15)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Arial", 'I', 7)
        self.set_text_color(120, 120, 120)
        self.set_y(-12)
        self.cell(0, 6, f"{CLASSIFICATION}  |  Auto-CTI Automated Threat Intelligence System  |  Page {self.page_no()}", 0, 0, 'C') # type: ignore

def generate_pdf_briefing(briefing: dict, cve_list: list, stats: dict, output_path: str) -> None:
    pdf = CTIReportPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.set_font("Arial", 'B', 18)
    pdf.set_text_color(15, 23, 42) 
    pdf.cell(0, 10, txt="Cyber Threat Intelligence Executive Briefing", ln=True, align='C') # type: ignore
    pdf.set_font("Arial", '', 10)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, txt=clean_text_for_pdf(f"Report Date: {briefing.get('report_date', today_date)}"), ln=True, align='C') # type: ignore
    pdf.cell(0, 6, txt=f"Document Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} UTC", ln=True, align='C') # type: ignore
    pdf.ln(6)

    pdf.set_font("Arial", 'B', 13)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 9, txt="1. Risk Statistics Summary", ln=True) # type: ignore
    pdf.set_font("Arial", 'B', 10)
    col_w = 38
    labels = ["Critical", "High", "Medium", "Low", "Total"]
    for label in labels:
        color = severity_color(label) if label != "Total" else (15, 23, 42)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(*color)
        pdf.cell(col_w, 9, txt=label, border=0, fill=True, align='C') # type: ignore
    pdf.ln(9)
    pdf.set_font("Arial", '', 11)
    pdf.set_text_color(0, 0, 0)
    for label in labels:
        value = stats.get(label, 0)
        pdf.set_fill_color(243, 244, 246)
        pdf.cell(col_w, 9, txt=str(value), border=1, fill=True, align='C') # type: ignore
    pdf.ln(13)

    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 9, txt="2. Executive Summary", ln=True) # type: ignore
    pdf.set_font("Arial", '', 11)
    summary = clean_text_for_pdf(sanitize_text_field(briefing.get("executive_summary", "Not available.")))
    pdf.multi_cell(0, 6, txt=summary, wrapmode="CHAR") # type: ignore
    pdf.ln(4)

    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 9, txt="3. Critical Action List", ln=True) # type: ignore
    pdf.set_font("Arial", '', 11)
    actions = briefing.get("critical_actions", [])
    if actions:
        for i, action in enumerate(actions, start=1):
            clean_action = clean_text_for_pdf(sanitize_text_field(action))
            pdf.multi_cell(0, 6, txt=f"{i}. {clean_action}", wrapmode="CHAR") # type: ignore
            pdf.ln(1)
    else:
        pdf.cell(0, 6, txt="No critical actions identified.", ln=True) # type: ignore
    pdf.ln(4)

    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 9, txt="4. Quick Reference: All Identified Vulnerabilities", ln=True) # type: ignore
    pdf.set_font("Arial", 'B', 10)
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(60, 8, txt="CVE ID", border=1, fill=True) # type: ignore
    pdf.cell(50, 8, txt="Severity", border=1, fill=True) # type: ignore
    pdf.cell(0, 8, txt="Urgency Score", border=1, fill=True, ln=True) # type: ignore

    pdf.set_font("Arial", '', 10)
    for entry in cve_list:
        pdf.set_text_color(0, 0, 0)
        pdf.cell(60, 8, txt=clean_text_for_pdf(entry["cve_id"]), border=1) # type: ignore
        r, g, b = severity_color(entry["severity"])
        pdf.set_text_color(r, g, b)
        pdf.cell(50, 8, txt=clean_text_for_pdf(entry["severity"]), border=1) # type: ignore
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, txt=str(entry["urgency_score"]), border=1, ln=True) # type: ignore

    if not cve_list:
        pdf.cell(0, 8, txt="No CVE entries found.", border=1, ln=True) # type: ignore

    pdf.ln(8)

    pdf.set_font("Arial", 'B', 13)
    pdf.cell(0, 9, txt="5. Detailed Vulnerability Findings", ln=True) # type: ignore
    pdf.ln(2)

    for entry in cve_list:
        r, g, b = severity_color(entry["severity"])

        pdf.set_font("Arial", 'B', 11)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 7, txt=clean_text_for_pdf(entry["cve_id"]), ln=True) # type: ignore

        pdf.set_font("Arial", 'B', 9)
        pdf.set_text_color(r, g, b)
        pdf.cell(0, 6, txt=clean_text_for_pdf( # type: ignore
            f"Severity: {entry['severity']}   |   CVSS Score: {entry.get('cvss_score', 'N/A')}   |   Urgency Score: {entry['urgency_score']}/100"
        ), ln=True)

        pdf.set_font("Arial", 'I', 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, txt=clean_text_for_pdf( # type: ignore
            f"CWE: {entry.get('cwe_id', 'N/A')}"
        ), ln=True)

        pdf.set_font("Arial", '', 10)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5.5, txt=clean_text_for_pdf(entry["description"]), wrapmode="CHAR") # type: ignore

        mappings = entry.get("mitre_mappings", [])
        if mappings:
            pdf.set_font("Arial", 'I', 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 6, txt=clean_text_for_pdf("MITRE ATT&CK Techniques: " + ", ".join(mappings)), ln=True) # type: ignore

        pdf.set_draw_color(220, 220, 220)
        pdf.ln(2)
        y = pdf.get_y()
        pdf.line(10, y, 200, y)
        pdf.ln(5)

    pdf.output(output_path)

if __name__ == "__main__":
    print(f"Publisher Agent is compiling the formal executive briefing for: {report_date}...")
    result = publisher_crew.kickoff()

    raw_result = str(result).strip()
    if raw_result.startswith("```json"):
        raw_result = raw_result[7:]
    if raw_result.endswith("```"):
        raw_result = raw_result[:-3]
    raw_result = raw_result.strip()

    try:
        parsed = json.loads(raw_result)

        parsed["cve_summary"] = cve_summary
        parsed["severity_stats"] = severity_stats

        with open(json_output_path, 'w', encoding='utf-8') as f:
            json.dump(parsed, f, indent=4, ensure_ascii=False)

        print("\n================================================")
        print("Executive Briefing (JSON) Generated Successfully!")
        print("================================================")
        print(f"JSON Report saved at: {json_output_path}")
        print(f"Total CVEs included in report: {len(cve_summary)}")

        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_output_path = os.path.join(reports_dir, f"AutoCTI_Report_{timestamp}.pdf")
        generate_pdf_briefing(parsed, cve_summary, severity_stats, pdf_output_path)
        print(f"PDF Report saved at: {pdf_output_path}")

    except json.JSONDecodeError:
        print(f"\nWarning: Could not parse LLM output as clean JSON. "
              f"Raw output was still written to {json_output_path} via output_file.")
        print("PDF generation was skipped because the JSON could not be parsed.")