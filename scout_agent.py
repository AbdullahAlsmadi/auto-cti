import os
import requests
import datetime
from crewai import Agent, Task, Crew, LLM
from crewai.tools import BaseTool
from duckduckgo_search import DDGS
from dotenv import load_dotenv

load_dotenv()
today_date = datetime.datetime.now().strftime("%B %d, %Y")

# ==========================================
# 1. Tools Definition
# ==========================================

class InternetSearchTool(BaseTool):
    name: str = "Internet Search Tool"
    description: str = "Search the open internet specifically for recent articles containing the keyword 'CVE-' to find real vulnerabilities."

    def _run(self, query: str) -> str:
        results = DDGS().text(query, max_results=10)
        return str(list(results))
    
class NISTSearchTool(BaseTool):
    name: str = "NIST NVD Recent Search Tool"
    description: str = "Use this tool FIRST. It fetches the 10 MOST RECENT CVEs added to the official NIST database. DO NOT pass a specific query, just pass 'recent'."

    def _run(self, query: str) -> str: 
        try:
            end_date = datetime.datetime(2024, 5, 20) 
            start_date = end_date - datetime.timedelta(days=7)
            
            start_str = start_date.strftime('%Y-%m-%dT00:00:00.000') + "Z"
            end_str = end_date.strftime('%Y-%m-%dT23:59:59.000') + "Z"
            
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&pubStartDate={start_str}&pubEndDate={end_str}"
            response = requests.get(url, timeout=20)

            if response.status_code != 200:
                return f"NIST API Error: Received status code {response.status_code}"
            
            data = response.json()
            
            verified_cves = []
            for item in data.get("vulnerabilities", []):
                cve_id = item.get("cve", {}).get("id") 
                if not cve_id:
                    continue 
                
                descriptions = item.get("cve", {}).get("descriptions", [])
                desc_text = "No description provided by NIST."
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_text = d.get("value")
                        break
                
                verified_cves.append(f"VERIFIED_CVE_ID: {cve_id} | DESC: {desc_text[:200]}...")
            
            if not verified_cves:
                 return "API returned data, but no valid CVE IDs were found."
                 
            final_output = "STRICT INSTRUCTION: USE EXACTLY THESE IDs:\n" + "\n".join(verified_cves)
            return final_output

        except Exception as e:
            return f"Failed to connect to NIST: {str(e)}"

class AlienVaultOTXTool(BaseTool):
    name: str = "AlienVault OTX Search Tool"
    description: str = "Search AlienVault Open Threat Exchange for threat pulses and tags associated with a specific keyword (like a CVE ID)."

    def _run(self, query: str) -> str: 
        try:
            url = f"https://otx.alienvault.com/api/v1/search/pulses?q={query}&limit=5"
            response = requests.get(url, timeout=10)

            if response.status_code != 200:
                return f"AlienVault API Error: Received status code {response.status_code}"
            
            data = response.json()
            results = []
            for pulse in data.get("results", []):
                pulse_name = pulse.get("name", "N/A")
                pulse_id = pulse.get("id", "N/A")
                tags = ", ".join(pulse.get("tags", []))
                results.append(f"Pulse Name: {pulse_name}\nTags: {tags}\n")

            return "\n".join(results) if results else "No pulses found in AlienVault OTX for this CVE."
        except Exception as e:
                return f"Failed to connect to AlienVault: {str(e)}"
        
search_tool = InternetSearchTool()
nist_tool = NISTSearchTool()
alienvault_tool = AlienVaultOTXTool()

# ==========================================
# 2. Agent & LLM Setup
# ==========================================
""""
local_agent = LLM(
    model="ollama/llama3.1",
    base_url="http://localhost:11434"
)
"""

cloud_gemini = LLM(
    model="gemini/gemini-1.5-pro",
    api_key=os.getenv("GEMINI_API_KEY")
)

scout_agent = Agent(
    role='Strict Cyber Threat Analyst',
    goal=f'Retrieve and report ONLY real, verified cybersecurity threats and existing CVEs published around the current date: {today_date}.',
    backstory=f'''You are a meticulous and strictly factual cybersecurity researcher. 
    You are fully aware that today's date is {today_date}.
    YOUR ABSOLUTE RULE: NEVER invent, guess, or hallucinate CVE numbers, data, or descriptions. 
    You must ONLY output information that is EXACTLY matched from the tool responses. 
    If a tool returns no data, or if you cannot find real CVEs, you must simply state: "No real data found."''',
    verbose=True,
    llm = cloud_gemini,
    tools=[search_tool, nist_tool, alienvault_tool],
    allow_delegation=False
)

# ==========================================
# 3. Task Definition
# ==========================================

live_task = Task(
    description=f'''Follow these exact steps to create a highly accurate, recent threat report:
    1. Keep in mind that today's current date is strictly {today_date}.
    2. USE THE NIST TOOL FIRST. Pass the query "recent" to fetch the most recent CVEs published in the last 7 days leading up to {today_date}.
    3. Read the exact VERIFIED_CVE_IDs returned by the NIST tool.
    4. For EACH real VERIFIED_CVE_ID found, use the AlienVault tool to check if there are any active threat pulses.
    5. Compile the final report using ONLY the data retrieved from the tools.
    CRITICAL CONSTRAINT: Do not search the internet for random CVEs. ONLY use the exact IDs provided by the NIST tool in step 2. DO NOT make up sequential numbers.''',
    expected_output='A factual report containing the exact verified CVEs from the NIST tool, their descriptions, and any associated AlienVault pulses. Formatted cleanly.',
    agent=scout_agent 
)

# ==========================================
# 4. Execution
# ==========================================

cyber_crew = Crew(
    agents=[scout_agent], 
    tasks=[live_task],
    verbose=True
)

print(f"Waking up the strict Scout. Today's date is calibrated to: {today_date}")
result = cyber_crew.kickoff()

print("\n================================================")
print("Final Verified Cyber Threat Intelligence (CTI) Report:")
print("================================================")
print(result)