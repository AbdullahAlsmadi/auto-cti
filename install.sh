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
# install.sh — Automated Linux installer for Auto-CTI: sets up the virtual
# environment, dependencies, and the auto-cti command-line wrapper.

#!/bin/bash
# Auto-CTI Installer – Fully automatic, no user interaction needed

set -e

echo "🛡️  Auto-CTI Linux Installation"
echo "==============================="
echo

# Determine if we are root (no sudo needed)
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Function to install packages based on distro
install_packages() {
    if command -v pacman &> /dev/null; then
        $SUDO pacman -S --noconfirm "$@"
    elif command -v apt &> /dev/null; then
        $SUDO apt update
        $SUDO apt install -y "$@"
    elif command -v dnf &> /dev/null; then
        $SUDO dnf install -y "$@"
    else
        echo "⚠️  Could not auto-install packages. Please install: $@ manually."
        exit 1
    fi
}

# 1. Check Python and install if missing
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Installing..."
    install_packages python3 python3-pip python3-venv
fi

# 2. Verify Python version using numeric comparison
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

# Check if version is >= 3.9
if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 9 ]; }; then
    echo "❌ Python $PYTHON_VERSION is too old. Please install Python 3.9 or higher."
    exit 1
fi

# 3. Install bc if missing (for version comparison fallback, but we don't need it now)
if ! command -v bc &> /dev/null; then
    echo "📦 Installing bc (required for version checks)..."
    install_packages bc
fi

# 4. Install GCC and make if missing (for building numpy)
if ! command -v gcc &> /dev/null || ! command -v make &> /dev/null; then
    echo "📦 Installing build tools (gcc, make)..."
    install_packages gcc make
fi

# 5. Create installation directory
INSTALL_DIR="$HOME/.auto-cti"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/data"

# 6. Copy source files
echo "📦 Installing Auto-CTI to $INSTALL_DIR..."
cp -r src/ "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

# 7. Create virtual environment and install dependencies
echo "📦 Creating virtual environment and installing dependencies..."
python3.12 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r "$INSTALL_DIR/requirements.txt"
deactivate

# 8. Create global wrapper script
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/auto-cti" << 'EOF'
#!/bin/bash
export PYTHONPATH="$HOME/.auto-cti:$PYTHONPATH"
source "$HOME/.auto-cti/venv/bin/activate"
cd "$HOME/.auto-cti"
if [ "$1" == "-s" ]; then
    python src/scout_agent.py
elif [ "$1" == "-t" ]; then
    python src/triage_agent.py
elif [ "$1" == "-p" ]; then
    python src/publisher_agent.py
elif [ "$1" == "-d" ]; then
    python -m streamlit run src/dashboard.py
elif [ "$1" == "-f" ]; then
    python src/scout_agent.py && python src/triage_agent.py && python src/publisher_agent.py
elif [ "$1" == "-u" ]; then
    "$HOME/.auto-cti/uninstall.sh"
else
    echo "🛡️ Auto-CTI Command Guide:"
    echo "   auto-cti -d  - Launch interactive dashboard"
    echo "   auto-cti -s  - Run Scout Agent"
    echo "   auto-cti -t  - Run Triage Agent"
    echo "   auto-cti -p  - Run Publisher Agent"
    echo "   auto-cti -f  - Run full pipeline"
    echo "   auto-cti -u  - Remove Auto-CTI completely"
fi
EOF
chmod +x "$HOME/.local/bin/auto-cti"

# 9. Add ~/.local/bin to PATH if not already
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo "✅ Added ~/.local/bin to PATH. Restart your shell or run: source ~/.bashrc"
fi

# 10. Create uninstall script
cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
echo "🗑️  Uninstalling Auto-CTI..."
rm -rf "$HOME/.auto-cti"
rm -f "$HOME/.local/bin/auto-cti"
echo "✅ Auto-CTI removed completely."
EOF
chmod +x "$INSTALL_DIR/uninstall.sh"

# 11. Create sample .env (will be overwritten by the app if missing)
# Write the .env template directly to the location used by secure_config.py
if [ ! -f "$INSTALL_DIR/.env" ]; then
    cat > "$INSTALL_DIR/.env" << 'EOF'
# ============================================================
# Auto-CTI Environment Configuration
# ============================================================

# ---------- API Keys ----------
GEMINI_API_KEY=
NVD_API_KEY=
GITHUB_TOKEN=
VULNERS_API_KEY=
OTX_API_KEY=
OPENCVE_USERNAME=
OPENCVE_PASSWORD=
GOOGLE_SEARCH_API_KEY=
GOOGLE_SEARCH_CX=

# ---------- Feature Toggles ----------
# Set to "true" to enable, "false" to disable (or leave empty for default = false)

# Sploitus exploit aggregator (default: disabled)
# NOTE: Consistently returns HTTP 403 due to Cloudflare bot protection.
# Enabling will add ~1-2 seconds latency per CVE with no results expected.
ENABLE_SPLOITUS=false

# Vulners Lucene search (default: disabled)
# NOTE: Returns HTTP 402 (payment required) on the free tier.
# Only enable if you have a paid Vulners subscription plan.
ENABLE_VULNERS_LUCENE=false
EOF
    chmod 600 "$INSTALL_DIR/.env"
fi

# Remove the obsolete config directory to avoid confusion
rm -rf "$INSTALL_DIR/config"

echo
echo "✅ Installation complete!"
echo
echo "🚀 You can now run:"
echo "   auto-cti -d  - Launch interactive dashboard"
echo "   auto-cti -s  - Run Scout Agent"
echo "   auto-cti -t  - Run Triage Agent"
echo "   auto-cti -p  - Run Publisher Agent"
echo "   auto-cti -f  - Run full pipeline"
echo
echo "🔑 On first run, you will be prompted for API keys."
echo "   Keys are stored securely in ~/.auto-cti/.env"
echo
echo "If 'auto-cti' is not found, restart your terminal or run:"
echo "   source ~/.bashrc"