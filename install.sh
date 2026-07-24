#!/bin/bash
# Auto-CTI Installer – Fully automatic, no user interaction needed

set -e

echo "🛡️  Auto-CTI Linux Installation"
echo "==============================="
echo

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Installing..."
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y python3 python3-pip python3-venv
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y python3 python3-pip
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm python python-pip
    else
        echo "⚠️  Could not auto-install Python. Please install Python 3.9+ manually."
        exit 1
    fi
fi

# 2. Verify Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ $(echo "$PYTHON_VERSION < 3.9" | bc -l) -eq 1 ]]; then
    echo "❌ Python $PYTHON_VERSION is too old. Please install Python 3.9 or higher."
    exit 1
fi

# 3. Create installation directory
INSTALL_DIR="$HOME/.auto-cti"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/data"

# 4. Copy source files
echo "📦 Installing Auto-CTI to $INSTALL_DIR..."
cp -r src/ "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

# 5. Create virtual environment and install dependencies
echo "📦 Creating virtual environment and installing dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r "$INSTALL_DIR/requirements.txt"
deactivate

# 6. Create global wrapper script
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
    python src/dashboard.py
elif [ "$1" == "full" ]; then
    python src/scout_agent.py && python src/triage_agent.py && python src/publisher_agent.py
elif [ "$1" == "uninstall" ]; then
    "$HOME/.auto-cti/uninstall.sh"
else
    echo "Usage: auto-cti {scout|triage|publish|dashboard|full|uninstall}"
fi
EOF
chmod +x "$HOME/.local/bin/auto-cti"

# 7. Add ~/.local/bin to PATH if not already
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo "✅ Added ~/.local/bin to PATH. Restart your shell or run: source ~/.bashrc"
fi

# 8. Create uninstall script
cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
echo "🗑️  Uninstalling Auto-CTI..."
rm -rf "$HOME/.auto-cti"
rm -f "$HOME/.local/bin/auto-cti"
echo "✅ Auto-CTI removed completely."
EOF
chmod +x "$INSTALL_DIR/uninstall.sh"

# 9. Create sample .env (will be overwritten by the app if missing)
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