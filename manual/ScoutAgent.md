# 🛡️ Auto-CTI: Scout Agent

This project features the "Scout Agent", an autonomous AI agent built using `CrewAI`. The agent automatically searches the internet to gather the latest Common Vulnerabilities and Exposures (CVEs) and cybersecurity news, analyzing them entirely locally to ensure maximum privacy.

---

## ⚙️ Prerequisites
For the project to run successfully on any new machine, you need to have the following installed:
1. **Python 3.11** (Highly recommended to avoid library conflicts).
2. **[Ollama](https://ollama.com/)** installed and running in the background.

---

## 🛠️ Installation & Setup

To set up the project for the first time on a new machine, follow these steps sequentially in your terminal:

**1. Create and activate the virtual environment:**

*For Windows:*
```powershell
python -m venv venv
.\venv\Scripts\activate
```

*For Mac / Linux:*
```Bash
python3 -m venv venv
source venv/bin/activate
```
*Install the required libraries:*
```PowerShell
pip install --upgrade pip
pip install -r requirements.txt
pip install duckduckgo-search
```

## 🚀 Usage (Core Commands)

Every time you want to run the tool, you only need to execute these two commands (ensure your ```venv``` is active):

*1️⃣ Step 1: Run the AI Brain (Ollama)*

You must download and run the local AI model in the background so the agent can process the tasks.

```Bash
ollama run mistral
```
---
(Note: **Wait for the download to finish if this is your first time, then type /bye to return to your normal terminal prompt**).
---
*2️⃣ Step 2: Launch the Scout Agent*
Once you are sure Ollama is running in the background, execute the agent script to start the operation:
