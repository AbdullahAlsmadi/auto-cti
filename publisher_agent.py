import os
import json
import datetime
from crewai import Agent, Task, Crew, LLM
from dotenv import load_dotenv
from fpdf import FPDF

load_dotenv()

current_time_suffix = datetime.datetime.now().strftime("%H%M%S")
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
            
except json.JSONDecodeError:
    print(f"Error: The file {latest_file} contains invalid JSON. Please run triage_agent.py again.")
    exit()

output_dir = os.path.join("JoFile", "publisher_agent_result")
os.makedirs(output_dir, exist_ok=True)


publisher_llm = LLM(
    model="ollama/qwen2.5",
    base_url="http://localhost:11434"
)


publisher_agent = Agent(
    role='Security Communications Officer',
    goal='Compile analyzed threat data into executive summaries.',
    backstory='''You are an expert in security communications. 
    You excel at translating complex technical vulnerabilities into clear, concise executive briefings 
    and precise task lists for security engineers.''',
    verbose=True,
    llm=publisher_llm,
    allow_delegation=False
)

safe_date = report_date.replace(", ", "_").replace(" ", "_")
pdf_filename = f'Executive_Briefing_{safe_date}_{current_time_suffix}.pdf'
pdf_output_path = os.path.join(output_dir, pdf_filename)

publish_task = Task(
    description=f'''Read the following Triage Analysis Report and perform these actions:
    1. Write a short Executive Summary (for the CISO).
    2. Extract a "Critical Action List" for the Security Engineering team.
    
    REPORT DATA:
    {triage_content}
    
    OUTPUT FORMAT: Standard text report. Use clear text headings and bullet points. Do not use complex markdown tables.''',
    
    expected_output='A professional security briefing and an action-item list formatted with clear text headings.',
    agent=publisher_agent
)

publisher_crew = Crew(
    agents=[publisher_agent],
    tasks=[publish_task],
    verbose=True
)

if __name__ == "__main__":
    print(f"Publisher Agent is compiling the final brief for report date: {report_date}...")
    result = publisher_crew.kickoff()

    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        pdf.set_font("Arial", 'B', size=16)
        pdf.cell(200, 10, txt="Cyber Threat Intelligence Executive Briefing", ln=True, align='C') # type: ignore
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt=f"Report Date: {report_date} | Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C') # type: ignore
        pdf.ln(10)
        
        pdf.set_font("Arial", size=11)
        clean_text = result.raw.encode('latin-1', 'ignore').decode('latin-1') # type: ignore
        
        for line in clean_text.split('\n'):
            if line.strip().startswith('#'):
                pdf.ln(4)
                pdf.set_font("Arial", 'B', size=14)
                pdf.cell(0, 10, txt=line.replace('#', '').strip(), ln=True) # type: ignore
                pdf.set_font("Arial", size=11)
            else:
                pdf.multi_cell(0, 6, txt=line)  # type: ignore
                
        pdf.output(pdf_output_path)
        
        print("\n================================================")
        print("Executive Briefing (PDF) Generated Successfully!")
        print("================================================")
        print(f"📕 PDF Report saved at: {pdf_output_path}")
        
    except Exception as e:
        print(f"\n⚠️ PDF generation failed. Error: {e}")