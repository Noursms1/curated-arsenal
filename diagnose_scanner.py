import re

FILE = r"C:\users\nour\curated-arsenal\data\scripts\advanced_domain_scanner_v2.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

print("[*] File size:", len(content), "chars")
print()

# Find all function definitions
print("[*] All functions in file:")
for match in re.finditer(r'^def (\w+)\(', content, re.MULTILINE):
    line_num = content[:match.start()].count("\n") + 1
    print(f"  Line {line_num}: def {match.group(1)}()")

print()
print("[*] Checking for main entry point:")

# Check different patterns
patterns = {
    "def main()": r'def main\(\)',
    "if __name__": r'if __name__',
    "argparse": r'import argparse',
    "sys.argv": r'sys\.argv',
    "input(": r'input\(',
}

for name, pattern in patterns.items():
    found = re.search(pattern, content)
    if found:
        line_num = content[:found.start()].count("\n") + 1
        print(f"  [+] Found '{name}' at line {line_num}")
    else:
        print(f"  [-] '{name}' NOT FOUND")

print()
print("[*] Last 30 lines of the file (to see entry point):")
print("-" * 60)
lines = content.split("\n")
for i, line in enumerate(lines[-30:], len(lines) - 29):
    print(f"{i:>3}: {line}")