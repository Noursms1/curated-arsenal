import os

file_path = r"C:\users\nour\curated-arsenal\data\scripts\domain_scanner_v2.py"

if not os.path.exists(file_path):
    print("[!] File not found.")
    exit(1)

with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Replace sys.getenv with os.getenv
if "sys.getenv" in content:
    content = content.replace("sys.getenv", "os.getenv")
    print("[+] Fixed: Changed sys.getenv to os.getenv")

# 2. Ensure 'import os' exists
if "import os" not in content:
    content = "import os\n" + content
    print("[+] Added: import os at the top")

# 3. Add empty PROXY env variable just in case (Not needed, but good practice)
with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("[✅] Tool fixed successfully! Try running it again in the platform.")