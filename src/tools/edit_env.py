import os, subprocess

p = os.path.expanduser("~/.auto-cti/.env")
editor = os.getenv("EDITOR", "nano")
subprocess.call([editor, p])