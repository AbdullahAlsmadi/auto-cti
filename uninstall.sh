#!/bin/bash
# Auto-CTI Uninstaller

echo "🗑️  Uninstalling Auto-CTI..."

if [ -d "$HOME/.auto-cti" ]; then
    rm -rf "$HOME/.auto-cti"
    echo "   Removed ~/.auto-cti"
fi

if [ -f "$HOME/.local/bin/auto-cti" ]; then
    rm -f "$HOME/.local/bin/auto-cti"
    echo "   Removed ~/.local/bin/auto-cti"
fi

echo "✅ Auto-CTI removed completely."