import os
import stat
import sys
from pathlib import Path
from dotenv import load_dotenv

CONFIG_DIR = Path.home() / ".auto-cti"
ENV_FILE = CONFIG_DIR / ".env"

# Also check project root .env as fallback
PROJECT_ROOT = Path.cwd()
PROJECT_ENV = PROJECT_ROOT / ".env"

REQUIRED_KEYS = {
    "GEMINI_API_KEY": "https://ai.google.dev/gemini-api/docs/api-key",
    "NVD_API_KEY": "https://nvd.nist.gov/developers/request-an-api-key",
    "GITHUB_TOKEN": "https://github.com/settings/tokens",
    "VULNERS_API_KEY": "https://vulners.com/register",
    "OTX_API_KEY": "https://otx.alienvault.com/",
    "OPENCVE_USERNAME": "https://www.opencve.io/register",
    "OPENCVE_PASSWORD": "https://www.opencve.io/register",
}

def ensure_config_dir():
    CONFIG_DIR.mkdir(mode=0o700, exist_ok=True)

def load_env():
    ensure_config_dir()
    # Load primary .env from ~/.auto-cti/.env
    if ENV_FILE.exists():
        load_dotenv(ENV_FILE)
        if ENV_FILE.stat().st_mode & (stat.S_IROTH | stat.S_IWOTH):
            print("⚠️  Warning: .env file has insecure permissions. Run: chmod 600 ~/.auto-cti/.env")
    # Also load project root .env if exists (for development)
    if PROJECT_ENV.exists():
        load_dotenv(PROJECT_ENV, override=True)
    return os.environ

def save_env(env_dict):
    ensure_config_dir()
    with open(ENV_FILE, 'w') as f:
        f.write("# Auto-CTI Environment Configuration\n")
        for key, value in env_dict.items():
            f.write(f"{key}={value}\n")
    os.chmod(ENV_FILE, 0o600)
    print("✅ Keys saved securely to ~/.auto-cti/.env")

def get_missing_keys():
    env = load_env()
    missing = {key: url for key, url in REQUIRED_KEYS.items() if not env.get(key)}
    return missing

def prompt_missing_keys():
    if not sys.stdin.isatty():
        return
    env = load_env()
    missing = {key: url for key, url in REQUIRED_KEYS.items() if not env.get(key)}
    if not missing:
        return
    print("\n🔑 Some API keys are missing. Please provide them:")
    for key, url in missing.items():
        print(f"\n📌 {key} (get it from: {url})")
        value = input(f"   Enter {key}: ").strip()
        if value:
            env[key] = value
            save_env(env)
        else:
            print(f"   ⚠️  Skipped {key} – some features may not work.")
    load_dotenv(ENV_FILE, override=True)

def init_config():
    load_env()
    prompt_missing_keys()