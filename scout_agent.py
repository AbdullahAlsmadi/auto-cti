from crewai import Agent, Task, Crew, LLM
from crewai.tools import BaseTool
from duckduckgo_search import DDGS

class InternetSearchTool(BaseTool):
    name: str = "Internet Search Tool"
    description: str = "Search the internet for the latest news, CVEs, and cybersecurity threats."

    def _run(self, query: str) -> str:
        results = DDGS().text(query, max_results = 3)
        return str(list(results))

search_tool = InternetSearchTool()

local_mistral = LLM(
    model = "ollama/mistral",
    base_url = "http://localhost:11434"
)

scout_agent = Agent(
    role = 'Cyber Threat Scout',
    goal = 'Search the internet to find the latest 2026 cybersecurity threats and newly assigned CVEs.',
    backstory = 'You are an elite cyber threat intelligence researcher. You always look for real-time, current data about new vulnerabilities discovered in 2026.',
    verbose = True,
    llm = local_mistral,
    tools = [nist_search_tool, alienvault_tool, rss_reader_tool, twitter_intel_tool],
    allow_delegation = False
)

live_task = Task(
    description = 'Use the search tool to find 3 major cybersecurity news articles or new CVEs published in 2026. Ensure the vulnerabilities are current and from this year.',
    expected_output = 'A bulleted list of 3 recent 2026 cybersecurity threats with a short summary and their CVE numbers.',
    agent = scout_agent
)

Cyber_crew = Crew(
    agents = [scout_agent],
    tasks = [live_task],
    verbose = True
)

print("Starting the Cyber Threat Scout Agent...")
result = Cyber_crew.kickoff()

print("\n-------------------------------------------------")
print("Final result of the Cyber Threat Scout Agent:")
print("\n-------------------------------------------------")
print(result)