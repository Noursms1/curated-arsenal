import os
import re

FILES = [
    r"C:\users\nour\curated-arsenal\data\scripts\domain_scanner_v2.py",
    r"C:\users\nour\curated-arsenal\data\scripts\domain_scanner.py"
]

NEW_DICT_STR = '''TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "Drupal": [r"Drupal.settings", r"drupalSettings", r"/sites/default/files/", r"X-Generator.*Drupal"],
    "Joomla": [r"joomla", r"/components/com_"],
    "React": [r"__REACT_DEVTOOLS", r"react-dom"],
    "Vue.js": [r"vue\\.js", r"__vue__"],
    "Angular": [r"ng-version", r"angular"],
    "Ruby on Rails": [r"csrf-param.*authenticity_token", r"/assets/[a-zA-Z0-9\\-]+-[a-zA-Z0-9]{6,}\\.", r"rails-ujs", r"X-Runtime", r"request-id"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "jQuery": [r"jquery"],
    "Bootstrap": [r"bootstrap"],
    "Nginx": [r"nginx"],
    "Apache": [r"apache"],
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "Shopify": [r"shopify", r"cdn\\.shopify"],
    "Google Analytics": [r"google-analytics", r"gtag"],
    "Facebook Pixel": [r"fbq", r"facebook\\.com/tr"],
}'''

NEW_DETECT_FUNC = '''def detect_technologies(content, headers):
    """اكتشاف التقنيات المستخدمة بدقة"""
    found = set()
    if not content: content = ""
    header_str = str(headers)
    
    # 1. فحص البصمات في المحتوى والهيدرز
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, header_str, re.IGNORECASE):
                found.add(tech)
                break
    
    # 2. فحص السيرفر
    server = headers.get("Server", "").lower()
    if "nginx" in server:
        found.add("Nginx")
    if "apache" in server:
        found.add("Apache")
    
    # 3. فحص X-Powered-By
    powered_by = headers.get("X-Powered-By", "").lower()
    if "php" in powered_by:
        found.add("PHP")
    if "asp" in powered_by:
        found.add("ASP.NET")
    if "express" in powered_by:
        found.add("Express.js")
    
    return sorted(list(found))'''

for file_path in FILES:
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        continue
        
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    modified = False
    
    # 1. Replace TECH_SIGNATURES
    pattern = r'TECH_SIGNATURES\s*=\s*\{.*?\n\}'
    if re.search(pattern, content, re.DOTALL):
        content = re.sub(pattern, NEW_DICT_STR, content, count=1, flags=re.DOTALL)
        modified = True
    
    # 2. Replace detect_technologies
    pattern_func = r'def detect_technologies\(content, headers\):.*?(?=\ndef |\Z)'
    if re.search(pattern_func, content, re.DOTALL):
        content = re.sub(pattern_func, NEW_DETECT_FUNC + "\n\n", content, count=1, flags=re.DOTALL)
        modified = True

    if modified:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Successfully patched: {os.path.basename(file_path)}")
    else:
        print(f"[!] Could not find target patterns in {os.path.basename(file_path)}")

print("\nDone! Test it by running a scan on hackerone.com.")