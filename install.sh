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

# 1. Select a supported Python interpreter (must be 3.10, 3.11, or 3.12).
PYTHON_BIN=""
PYTHON_VERSION=""

for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &> /dev/null; then
        VER=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        MAJ=${VER%.*}
        MIN=${VER#*.}
        if [ "$MAJ" -eq 3 ] && [ "$MIN" -ge 10 ] && [ "$MIN" -le 12 ]; then
            PYTHON_BIN=$(command -v "$candidate")
            PYTHON_VERSION=$VER
            echo "✅ Using Python $VER ($PYTHON_BIN)"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    DEFAULT_VER=$(python3 --version 2>&1 || echo "not installed")
    echo
    echo "❌ Auto-CTI requires Python 3.10, 3.11, or 3.12."
    echo "   Your default python3 reports: $DEFAULT_VER"
    echo
    echo "   Python 3.13+ is NOT supported yet because several required"
    echo "   packages (tiktoken via PyO3, docstring_parser, etc.) have not"
    echo "   been updated for those versions."
    echo
    echo "   Install Python 3.12 and re-run this installer:"
    echo "     Arch Linux:    sudo pacman -S python312"
    echo "                    (or, if not in official repos: yay -S python312)"
    echo "     Ubuntu/Debian: sudo apt install python3.12 python3.12-venv"
    echo "     Fedora:        sudo dnf install python3.12"
    echo
    echo "   Then re-run:  ./install.sh"
    echo
    exit 1
fi

if ! "$PYTHON_BIN" -c 'import venv' 2>/dev/null; then
    echo "❌ The 'venv' module is missing for $PYTHON_BIN."
    echo "   Ubuntu/Debian: sudo apt install python3.12-venv"
    echo "   Fedora:        sudo dnf install python3.12"
    exit 1
fi

# 2. Install GCC and make if missing (for building numpy)
if ! command -v gcc &> /dev/null || ! command -v make &> /dev/null; then
    echo "📦 Installing build tools (gcc, make)..."
    install_packages gcc make
fi

# 3. Install Rust toolchain if missing (fallback for source-building tiktoken)
if ! command -v cargo &> /dev/null; then
    echo "📦 Installing Rust toolchain (fallback for tiktoken builds)..."
    if command -v pacman &> /dev/null; then
        install_packages rust
    elif command -v apt &> /dev/null; then
        install_packages rustc cargo
    elif command -v dnf &> /dev/null; then
        install_packages rust cargo
    else
        echo "⚠️  Cannot auto-install Rust. Continuing without it;"
        echo "    wheels should be available for Python $PYTHON_VERSION."
    fi
fi

# 4. Create installation directory
INSTALL_DIR="$HOME/.auto-cti"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/data"

# 5. Copy source files and documentation
echo "📦 Installing Auto-CTI to $INSTALL_DIR..."
cp -r src/ "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp LICENSE "$INSTALL_DIR/" 2>/dev/null || true
cp NOTICE "$INSTALL_DIR/" 2>/dev/null || true
cp SECURITY.md "$INSTALL_DIR/" 2>/dev/null || true
cp CITATION.cff "$INSTALL_DIR/" 2>/dev/null || true

# Record the exact code version (stored in every archived run)
VERSION="unknown"
if command -v git &> /dev/null && git rev-parse --short HEAD &> /dev/null; then
    VERSION="$(git rev-parse --short HEAD)"
    git diff --quiet 2>/dev/null || VERSION="$VERSION-dirty"
fi
echo "$VERSION" > "$INSTALL_DIR/VERSION"

# 6. Create virtual environment and install dependencies
echo
echo -e "\033[1;36m📦  Creating virtual environment with Python $PYTHON_VERSION…\033[0m"
rm -rf "$INSTALL_DIR/venv"
"$PYTHON_BIN" -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

echo -e "\033[1;36m📦  Upgrading pip…\033[0m"
pip install --upgrade pip --quiet --disable-pip-version-check 2>&1 | tail -1

TOTAL_PKGS=$(grep -cve '^\s*$' -e '^#' "$INSTALL_DIR/requirements.txt")
echo
echo -e "\033[1;36m📦  Installing $TOTAL_PKGS dependency groups (this may take a few minutes)…\033[0m"
echo -e "\033[2m    (pip output is hidden; only the final status is shown)\033[0m"
echo

if pip install -r "$INSTALL_DIR/requirements.txt" \
        --quiet \
        --disable-pip-version-check \
        --no-input \
        --prefer-binary \
        2> /tmp/auto-cti-pip-error.log; then
    echo -e "\033[1;32m✅  Dependencies installed successfully.\033[0m"
else
    echo -e "\033[1;33m⚠️  Binary-only install incomplete; retrying with source builds…\033[0m"
    if pip install -r "$INSTALL_DIR/requirements.txt" \
            --quiet \
            --disable-pip-version-check \
            --no-input \
            2> /tmp/auto-cti-pip-error.log; then
        echo -e "\033[1;32m✅  Dependencies installed successfully (with source builds).\033[0m"
    else
        echo -e "\033[1;31m❌  Dependency installation failed on Python $PYTHON_VERSION.\033[0m"
        echo -e "\033[1;33m    Full log: /tmp/auto-cti-pip-error.log\033[0m"
        echo
        tail -20 /tmp/auto-cti-pip-error.log
        deactivate
        exit 1
    fi
fi

deactivate

# 7. Create global wrapper script
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
    python src/scout_agent.py && python src/triage_agent.py && python src/publisher_agent.py \
        && python src/tools/archive_run.py "${@:2}"
elif [ "$1" == "-u" ]; then
    "$HOME/.auto-cti/uninstall.sh"
elif [ "$1" == "-v" ]; then
    python src/tools/verify_urgency.py "${@:2}"
elif [ "$1" == "-b" ]; then
    python src/tools/poc_breakdown.py "${@:2}"
elif [ "$1" == "-g" ]; then
    python src/tools/llm_agreement.py "${@:2}"
elif [ "$1" == "-a" ]; then
    python src/tools/archive_run.py "${@:2}"
elif [ "$1" == "-k" ]; then
    python src/tools/check_keys.py
elif [ "$1" == "-e" ]; then
    python src/tools/edit_env.py
else
    echo "🛡️  Auto-CTI Command Guide"
    echo "============================================"
    echo
    echo "  CORE COMMANDS (pipeline):"
    echo "    -d   Launch interactive dashboard"
    echo "    -s   Run Scout Agent"
    echo "    -t   Run Triage Agent"
    echo "    -p   Run Publisher Agent"
    echo "    -f   Run full pipeline (Scout → Triage → Publisher → Archive)"
    echo
    echo "  ANALYSIS TOOLS (verification):"
    echo "    -v   Verify Urgency Score formula"
    echo "    -b   PoC breakdown (external / patch-diff / none)"
    echo "    -g   LLM vs authoritative CVSS agreement"
    echo "    -a   Archive the current run (optionally: -a <label>)"
    echo
    echo "  CONFIGURATION:"
    echo "    -k   Check API keys (live test, no secrets shown)"
    echo "    -e   Edit .env file in your editor"
    echo
    echo "  MAINTENANCE:"
    echo "    -u   Remove Auto-CTI completely"
    echo
    echo "  Examples:"
    echo "    auto-cti -d                    # start the SOC dashboard"
    echo "    auto-cti -f cycle1_run1        # run + archive with a label"
    echo "    auto-cti -b --list             # list plausible PoC links"
    echo "    auto-cti -v /path/to/runs      # verify a batch of archived runs"
    echo "    auto-cti -g                    # LLM agreement with authoritative sources"
    echo
fi
EOF
chmod +x "$HOME/.local/bin/auto-cti"

# 8. Add ~/.local/bin to PATH if not already
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo "✅ Added ~/.local/bin to PATH. Restart your shell or run: source ~/.bashrc"
fi

# 9. Create uninstall script
cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
echo "🗑️  Uninstalling Auto-CTI..."
rm -rf "$HOME/.auto-cti"
rm -f "$HOME/.local/bin/auto-cti"
echo "✅ Auto-CTI removed completely."
EOF
chmod +x "$INSTALL_DIR/uninstall.sh"

# 10. Create sample .env
if [ ! -f "$INSTALL_DIR/.env" ]; then
    cat > "$INSTALL_DIR/.env" << 'EOF'
# ============================================================
# Auto-CTI Environment Configuration
# ============================================================

# ---------- Required ----------
# Get from: https://ai.google.dev/gemini-api/docs/api-key
GEMINI_API_KEY=

# ---------- Recommended ----------
# Get from: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=
# Get from: https://github.com/settings/tokens
GITHUB_TOKEN=
# Get from: https://otx.alienvault.com/
OTX_API_KEY=

# ---------- Optional ----------
# Get from: https://vulners.com/register
VULNERS_API_KEY=
# Get from: https://www.opencve.io/register
OPENCVE_USERNAME=
OPENCVE_PASSWORD=
# Get from: https://developers.google.com/custom-search/v1/overview
GOOGLE_SEARCH_API_KEY=
# Get from: https://programmablesearchengine.google.com/about/
GOOGLE_SEARCH_CX=

# ---------- Feature Toggles ----------
SCOUT_SKIP_NVD=false
ENABLE_SPLOITUS=false
ENABLE_VULNERS_LUCENE=false
ENABLE_SEEBUG=false
ENABLE_GITHUB_POC=false
ENABLE_NVD_EXPLOIT_REFS=true
EOF
    chmod 600 "$INSTALL_DIR/.env"
fi

echo
echo "✅ Installation complete!"
echo
echo "🚀 Quick start:"
echo "   auto-cti -d    Launch the SOC dashboard"
echo "   auto-cti -f    Run the full pipeline in the terminal"
echo
echo "🔧 Other commands:"
echo "   auto-cti -k    Check your API keys"
echo "   auto-cti -e    Edit ~/.auto-cti/.env"
echo
echo "🔑 On first run, you will be prompted for API keys."
echo "   Keys are stored securely in ~/.auto-cti/.env (mode 600)."
echo
echo "If 'auto-cti' is not found, restart your terminal or run:"
echo "   source ~/.bashrc"