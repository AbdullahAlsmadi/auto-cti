# Copyright 2026 Abdullah Al Smadi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# main_system.py — Orchestrates the Scout, Triage, and Publisher agents
# sequentially via CrewAI Flow.
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