import os
import json
import glob

BASE = r"C:\users\nour\curated-arsenal"
SCRIPTS = os.path.join(BASE, "data", "scripts")
TOOLS_JSON = os.path.join(BASE, "data", "tools.json")

print("=" * 70)
print("1. FILES IN data/scripts:")
print("=" * 70)
for f in sorted(glob.glob(os.path.join(SCRIPTS, "*.py"))):
    size = os.path.getsize(f)
    print(f"  {os.path.basename(f):<40} {size:>6} bytes")

print()
print("=" * 70)
print("2. TOOLS.JSON MAPPING (scanner-related):")
print("=" * 70)
with open(TOOLS_JSON, "r", encoding="utf-8") as f:
    data = json.load(f)

for t in data.get("tools", []):
    name = t.get("name", "").lower()
    if "scan" in name or "domain" in name:
        print(f"  Tool ID: {t['id']}")
        print(f"  Name: {t['name']}")
        print(f"  File Path: {t['file_path']}")
        file_full = os.path.join(BASE, t['file_path'])
        exists = os.path.exists(file_full)
        size = os.path.getsize(file_full) if exists else 0
        print(f"  File exists: {exists} ({size} bytes)")
        print()

print("=" * 70)
print("3. CONTENT OF domain_scanner_v2.py (first 60 lines):")
print("=" * 70)
v2_path = os.path.join(SCRIPTS, "domain_scanner_v2.py")
if os.path.exists(v2_path):
    with open(v2_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    for i, line in enumerate(lines[:60], 1):
        print(f"{i:>3}: {line.rstrip()}")
else:
    print("  File NOT FOUND!")