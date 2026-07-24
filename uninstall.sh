#!/bin/bash
# Auto-CTI Uninstaller

echo "🗑️  Uninstalling Auto-CTI..."

# حذف مجلد التثبيت
if [ -d "$HOME/.auto-cti" ]; then
    rm -rf "$HOME/.auto-cti"
    echo "   Removed ~/.auto-cti"
fi

# حذف الأمر العام
if [ -f "$HOME/.local/bin/auto-cti" ]; then
    rm -f "$HOME/.local/bin/auto-cti"
    echo "   Removed ~/.local/bin/auto-cti"
fi

echo "✅ Auto-CTI removed completely."