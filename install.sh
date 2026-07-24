#!/bin/bash
# Auto-CTI Linux Installer

set -e

echo "🛡️  Auto-CTI Linux Installation"
echo "==============================="
echo

if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required. Install it first: sudo apt install python3 python3-pip"
    exit 1
fi

INSTALL_DIR="$HOME/.auto-cti"
mkdir -p "$INSTALL_DIR"

echo "📦 Installing Auto-CTI to $INSTALL_DIR..."
cp -r src/ "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

echo "📦 Installing Python dependencies..."
pip3 install -r "$INSTALL_DIR/requirements.txt" --user --quiet

mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/auto-cti" << 'EOF'
#!/bin/bash
cd "$HOME/.auto-cti"
export PYTHONPATH="$HOME/.auto-cti:$PYTHONPATH"
if [ "$1" == "scout" ]; then
    python3 src/scout_agent.py
elif [ "$1" == "triage" ]; then
    python3 src/triage_agent.py
elif [ "$1" == "publish" ]; then
    python3 src/publisher_agent.py
elif [ "$1" == "dashboard" ]; then
    python3 src/dashboard.py
elif [ "$1" == "full" ]; then
    python3 src/scout_agent.py && python3 src/triage_agent.py && python3 src/publisher_agent.py
else
    echo "Usage: auto-cti {scout|triage|publish|dashboard|full}"
fi
EOF
chmod +x "$HOME/.local/bin/auto-cti"

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo "✅ Added ~/.local/bin to PATH. Run: source ~/.bashrc"
fi

echo
echo "✅ Installation complete!"
echo
echo "🚀 Commands:"
echo "   auto-cti dashboard  - Launch interactive dashboard"
echo "   auto-cti scout      - Run Scout Agent"
echo "   auto-cti triage     - Run Triage Agent"
echo "   auto-cti publish    - Run Publisher Agent"
echo "   auto-cti full       - Run full pipeline"
echo
echo "🔑 On first run, you will be prompted for API keys."