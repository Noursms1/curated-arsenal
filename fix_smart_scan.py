import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_FILE = os.path.join(BASE_DIR, "app.py")

with open(APP_FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Add better filtering in smart_scan
old_filter = """    # 3. Select compatible tools
    selected_tools = []
    for t in tools:
        cat = t.get("category", "").lower()
        name = t.get("name", "").lower()
        
        if target_type == "domain":
            if cat in ["recon", "network", "web"]:
                selected_tools.append(t)
        elif target_type == "ip":
            if cat in ["network"] or "port" in name:
                selected_tools.append(t)
        elif target_type == "url":
            if cat in ["web"]:
                selected_tools.append(t)

    # Limit to 5 tools to avoid extreme delays
    selected_tools = selected_tools[:5]"""

new_filter = """    # 3. Select compatible tools
    BLOCKED_KEYWORDS = ["cidr", "subnet", "calc"]
    selected_tools = []
    seen_names = set()
    
    for t in tools:
        cat = t.get("category", "").lower()
        name = t.get("name", "").lower()
        
        # Skip CIDR/subnet calculators (they need CIDR input, not domains)
        if any(k in name for k in BLOCKED_KEYWORDS):
            continue
        
        # Skip duplicates (same base name)
        base_name = name.split("_")[0].split(" ")[0]
        if base_name in seen_names:
            continue
        
        if target_type == "domain":
            if cat in ["recon", "network", "web"]:
                selected_tools.append(t)
                seen_names.add(base_name)
        elif target_type == "ip":
            if cat in ["network"] or "port" in name:
                selected_tools.append(t)
                seen_names.add(base_name)
        elif target_type == "url":
            if cat in ["web"]:
                selected_tools.append(t)
                seen_names.add(base_name)

    # Limit to 5 tools
    selected_tools = selected_tools[:5]"""

if old_filter in content:
    content = content.replace(old_filter, new_filter)
    with open(APP_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    
    import py_compile
    try:
        py_compile.compile(APP_FILE, doraise=True)
        print("[+] Smart Scanner fixed: CIDR excluded, duplicates skipped!")
    except py_compile.PyCompileError as e:
        print("[!] Syntax error: " + str(e))
else:
    print("[!] Could not find filter block, might be already updated")