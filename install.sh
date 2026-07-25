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
if [ "$1" == "scout" ]; then
    python src/scout_agent.py
elif [ "$1" == "triage" ]; then
    python src/triage_agent.py
elif [ "$1" == "publish" ]; then
    python src/publisher_agent.py
elif [ "$1" == "dashboard" ]; then
    python -m streamlit run src/dashboard.py
elif [ "$1" == "full" ]; then
    python src/scout_agent.py && python src/triage_agent.py && python src/publisher_agent.py
elif [ "$1" == "uninstall" ]; then
    "$HOME/.auto-cti/uninstall.sh"
else
    echo "🛡️ Auto-CTI Command Guide:"
    echo "   auto-cti dashboard  - Launch interactive dashboard"
    echo "   auto-cti scout      - Run Scout Agent"
    echo "   auto-cti triage     - Run Triage Agent"
    echo "   auto-cti publish    - Run Publisher Agent"
    echo "   auto-cti full       - Run full pipeline"
    echo "   auto-cti uninstall  - Remove Auto-CTI completely"
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
if [ ! -f "$INSTALL_DIR/config/.env" ]; then
    cat > "$INSTALL_DIR/config/.env" << 'EOF'
# Auto-CTI Environment – fill in your API keys
GEMINI_API_KEY=
NVD_API_KEY=
GITHUB_TOKEN=
VULNERS_API_KEY=
OTX_API_KEY=
OPENCVE_USERNAME=
OPENCVE_PASSWORD=
EOF
    chmod 600 "$INSTALL_DIR/config/.env"
fi

echo
echo "✅ Installation complete!"
echo
echo "🚀 You can now run:"
echo "   auto-cti dashboard  - Launch interactive dashboard"
echo "   auto-cti scout      - Run Scout Agent"
echo "   auto-cti triage     - Run Triage Agent"
echo "   auto-cti publish    - Run Publisher Agent"
echo "   auto-cti full       - Run full pipeline"
echo
echo "🔑 On first run, you will be prompted for API keys."
echo "   Keys are stored securely in ~/.auto-cti/config/.env"
echo
echo "If 'auto-cti' is not found, restart your terminal or run:"
echo "   source ~/.bashrc"