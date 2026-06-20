import os
import json
import datetime
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv

load_dotenv()
if not os.getenv("ANTHROPIC_API_KEY"):
    print("Error: ANTHROPIC_API_KEY is missing from your .env file.")
    exit()

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

"""
triage_llm = LLM(
    model="ollama/qwen2.5",
    base_url="http://localhost:11434"
)
"""

publisher_llm = LLM(
   model="anthropic/claude-sonnet-4-6",
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    max_retries=5 # type: ignore
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

output_file_path = os.path.join(output_dir, f'Triaged_Report_{today_date}.json')

triage_task = Task(
    description=f'''Analyze the following raw threat data collected by the Scout Agent today {today_date}:
    
    RAW THREAT DATA:
    {json.dumps(raw_threat_data, indent=2)}
    
    For each CVE in the data:
    1. Filter out rejected or clearly irrelevant CVEs.
    2. Deduce an estimated CVSS severity (Critical, High, Medium, Low) based on the description.
    3. Map the described threat behavior to potential MITRE ATT&CK tactics or techniques.
    4. Calculate a hypothetical "Urgency Score" (from 1 to 100).
    
    CRITICAL FORMATTING INSTRUCTIONS (MUST FOLLOW):
    1. You MUST output the result EXCLUSIVELY as a valid JSON array of objects.
    2. Do NOT wrap the output in Markdown code blocks (like ```json). Just output the raw JSON text.
    3. Keep the description concise and clear. Keep MITRE mappings to codes only.''',
    
    expected_output='''A valid JSON array of objects. You MUST strictly use exactly this JSON structure:
    [
      {
        "CVE_ID": "CVE-YYYY-NNNN",
        "Description": "Short, concise description of the vulnerability.",
        "CVSS_Severity": "Critical",
        "MITRE_Mappings": ["T1234", "T5678"],
        "Urgency_Score": 95
      },
      {
        "CVE_ID": "CVE-YYYY-NNNN",
        "Description": "...",
        "CVSS_Severity": "Medium",
        "MITRE_Mappings": ["T1111"],
        "Urgency_Score": 45
      }
    ]''',
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

    final_data = {
        "date": today_date,
    }
    

    print("\n================================================")
    print("Triage Analysis Complete! Executive Briefing:")
    print("================================================")
    print(result)
    print(f"\nThe detailed markdown report has been saved in: {output_file_path}")