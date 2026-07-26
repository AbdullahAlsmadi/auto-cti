import sys
import os
import time
import subprocess
from crewai.flow.flow import Flow, start, listen

# ⏱️ Record the exact start time of the entire pipeline
os.environ["PIPELINE_START_TIME"] = str(time.time())

class AutoCTIFlow(Flow):
    @start()
    def run_scout(self):
        print("🚀 [Step 1/3] Starting Scout Agent...")
        subprocess.run([sys.executable, "src/scout_agent.py"], check=True)
        print("✅ Scout Agent finished successfully.")
    
    @listen(run_scout)
    def run_triage(self):
        print("🔍 [Step 2/3] Starting Triage Agent...")
        subprocess.run([sys.executable, "src/triage_agent.py"], check=True)
        print("✅ Triage Agent finished successfully.")
    
    @listen(run_triage)
    def run_publisher(self):
        print("📢 [Step 3/3] Starting Publisher Agent...")
        subprocess.run([sys.executable, "src/publisher_agent.py"], check=True)
        print("✅ Publisher Agent finished successfully.")
        print("🎉 [System] All tasks completed! Final report generated.")
    
if __name__ == "__main__":
    flow = AutoCTIFlow()
    flow.kickoff()