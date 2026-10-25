import os
import re

file_path = r"C:\users\nour\curated-arsenal\data\scripts\domain_scanner_v2.py"

if not os.path.exists(file_path):
    print("[!] File NOT FOUND:", file_path)
    exit(1)

with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

print("[*] File size:", len(content), "chars")
print("=" * 60)

# Check for TECH_SIGNATURES
if "TECH_SIGNATURES" in content:
    print("[+] Found TECH_SIGNATURES keyword")
    # Find the line
    for i, line in enumerate(content.split("\n"), 1):
        if "TECH_SIGNATURES" in line:
            print(f"    Line {i}: {line[:100]}")
else:
    print("[-] TECH_SIGNATURES NOT FOUND")

print("=" * 60)

# Check for detect_technologies
if "def detect_technologies" in content:
    print("[+] Found detect_technologies function")
    for i, line in enumerate(content.split("\n"), 1):
        if "def detect_technologies" in line:
            print(f"    Line {i}: {line[:100]}")
else:
    print("[-] detect_technologies NOT FOUND")

print("=" * 60)

# Check for Drupal mention
if "Drupal" in content:
    print("[!] Drupal still exists in file:")
    for i, line in enumerate(content.split("\n"), 1):
        if "Drupal" in line or "drupal" in line:
            print(f"    Line {i}: {line[:150]}")

print("=" * 60)
print("[*] First 100 lines (structure):")
print("-" * 60)
lines = content.split("\n")
for i, line in enumerate(lines[:100], 1):
    if "TECH_SIGNATURE" in line or "Drupal" in line or "def detect" in line or "def _detect" in line:
        print(f"{i}: {line[:120]}")