import os
import json
import datetime
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv

load_dotenv()

today_date = datetime.datetime.now().strftime("%B %d, %Y")

scout_file_path = os.path.join("JoFile", "Scout_Agent_Results", "cti_report.json")

try:
    with open(scout_file_path, 'r', encoding='utf-8') as f:
        all_reports = json.load(f)
        raw_threat_data = all_reports.get(today_date, {})
except FileNotFoundError:
    print(f"Error: Could not find {scout_file_path}. Please run scout_agent.py first.")
    exit()

if not raw_threat_data:
    print(f"No data found for today ({today_date}) in the JSON file.")
    exit()

output_dir = os.path.join("JoFile", "triage_agent_result")
os.makedirs(output_dir, exist_ok=True)

triage_llm = LLM(
    model="ollama/qwen2.5",
    base_url="http://localhost:11434"
)

triage_agent = Agent(
    role='Senior Cyber Threat Analyst',
    goal='Analyze raw CVE data, assess severity, map to MITRE ATT&CK techniques, and calculate an Urgency Score.',
    backstory='''You are an elite threat intelligence analyst. 
    Your expertise lies in taking raw vulnerability data and translating it into actionable, contextualized intelligence. 
    You filter out low-priority alerts and identify the most critical threats using MITRE ATT&CK and CVSS logic.''',
    verbose=True,
    llm=triage_llm,
    allow_delegation=False
)

output_file_path = os.path.join(output_dir, f'Triaged_Report_{today_date.replace(", ", "").replace(" ", "_")}.md')

triage_task = Task(
    description=f'''Analyze the following raw threat data collected by the Scout Agent today:
    
    RAW THREAT DATA:
    {json.dumps(raw_threat_data, indent=2)}
    
    For each CVE in the data:
    1. Filter out rejected or clearly irrelevant CVEs.
    2. Deduce an estimated CVSS severity (Critical, High, Medium, Low) based on the description.
    3. Map the described threat behavior to potential MITRE ATT&CK tactics or techniques.
    4. Calculate a hypothetical "Urgency Score" (from 1 to 100).
    
    CRITICAL INSTRUCTION: You MUST output a clean Markdown report. Ensure every table has proper separators (|---|).''',
    
    expected_output='''An executive-ready Markdown report. You MUST strictly use exactly this table format for the output:
    
    | CVE ID | Description | CVSS Severity | MITRE ATT&CK Mappings | Urgency Score |
    |---|---|---|---|---|
    | CVE-... | ... | ... | ... | ... |
    
    Do not merge columns. Ensure the table is perfectly formatted.''',
    agent=triage_agent,
    output_file=output_file_path
)

triage_crew = Crew(
    agents=[triage_agent],
    tasks=[triage_task],
    verbose=True
)

if __name__ == "__main__":
    print(f"Waking up the Triage Agent to analyze threats for {today_date}...")
    result = triage_crew.kickoff()
    
    print("\n================================================")
    print("Triage Analysis Complete! Executive Briefing:")
    print("================================================")
    print(result)
    print(f"\nThe detailed markdown report has been saved in: {output_file_path}")