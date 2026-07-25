"""
Auto-CTI command-line entry point.
Dispatches to the individual pipeline stages.
"""
import sys
import subprocess
import os

# Directory containing this file (src/)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))

COMMANDS = {
    "scout": "scout_agent.py",
    "triage": "triage_agent.py",
    "publish": "publisher_agent.py",
    "dashboard": "dashboard.py",
}

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS and sys.argv[1] != "full":
        print("Usage: auto-cti {scout|triage|publish|dashboard|full}")
        sys.exit(1)

    command = sys.argv[1]

    if command == "full":
        for step in ("scout_agent.py", "triage_agent.py", "publisher_agent.py"):
            result = subprocess.run([sys.executable, os.path.join(SRC_DIR, step)])
            if result.returncode != 0:
                sys.exit(result.returncode)
        return

    script = COMMANDS[command]
    if command == "dashboard":
        # Streamlit needs its own launcher, not a plain python call
        subprocess.run([sys.executable, "-m", "streamlit", "run", os.path.join(SRC_DIR, script)])
    else:
        subprocess.run([sys.executable, "-m", "streamlit", "run", os.path.join(SRC_DIR, script)])

if __name__ == "__main__":
    main()