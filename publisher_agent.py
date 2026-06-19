import os
import json
import datetime
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv

load_dotenv()

today_date = datetime.datetime.now().strftime("%B %d, %Y")
triage_dir = os.path.join("JoFile", "triage_agent_result")
list_of_files = [os.path.join(triage_dir, f) for f in os.listdir(triage_dir) if f.endswith(".md")]

if not list_of_files:
    print("Error: No Triage Report found. Please run triage_agent.py first.")
    exit()
latest_file = max(list_of_files, key=os.path.getctime)

with open(latest_file, 'r', encoding='utf-8') as f:
    triage_content = f.read()

output_dir = os.path.join("JoFile", "publisher_agent_result")
os.makedirs(output_dir, exist_ok=True)

publisher_llm = LLM(
    model="ollama/qwen2.5",
    base_url="http://localhost:11434"
)

publisher_agent = Agent(
    role='Security Communications Officer',
    goal='Compile analyzed threat data into executive summaries and actionable task lists for security teams.',
    backstory='''You are an expert in security communications. 
    You excel at translating complex technical vulnerabilities into clear, concise executive briefings 
    and precise task lists for security engineers.''',
    verbose=True,
    llm=publisher_llm,
    allow_delegation=False
)

output_file_path = os.path.join(output_dir, f'Executive_Briefing_{today_date.replace(", ", "").replace(" ", "_")}.md')

publish_task = Task(
    description=f'''Read the following Triage Analysis Report and perform these actions:
    1. Write a short Executive Summary (for the CISO).
    2. Extract a "Critical Action List" for the Security Engineering team.
    
    REPORT DATA:
    {triage_content}
    
    OUTPUT FORMAT: Professional Markdown format. Use clear headings and bullet points.''',
    
    expected_output='A professional security briefing and an action-item list.',
    agent=publisher_agent,
    output_file=output_file_path
)

publisher_crew = Crew(
    agents=[publisher_agent],
    tasks=[publish_task],
    verbose=True
)

if __name__ == "__main__":
    print(f"Publisher Agent is compiling the final brief for {today_date}...")
    result = publisher_crew.kickoff()
    print("\n================================================")
    print("Executive Briefing Generated Successfully!")
    print("================================================")
    print(f"\nThe final report is saved at: {output_file_path}")