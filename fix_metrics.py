import os
import json
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "data", "scripts")
REVIEWS_DIR = os.path.join(BASE_DIR, "data", "reviews")
TOOLS_JSON = os.path.join(BASE_DIR, "data", "tools.json")
HTML_FILE = os.path.join(BASE_DIR, "templates", "tool_detail.html")

# 1. Fix HTML Template (Safe fallback for metrics)
if os.path.exists(HTML_FILE):
    with open(HTML_FILE, "r", encoding="utf-8") as f:
        html_content = f.read()
    
    old_line = "const metrics = {{ tool.metrics | tojson | safe }};"
    new_line = "const metrics = {{ tool.metrics | default({}) | tojson | safe }};"
    
    if old_line in html_content:
        html_content = html_content.replace(old_line, new_line)
        with open(HTML_FILE, "w", encoding="utf-8") as f:
            f.write(html_content)
        print("[+] Fixed tool_detail.html (added default metrics)")

# 2. Rebuild tools.json (with default metrics)
def format_name(filename):
    name = os.path.splitext(filename)[0]
    return " ".join([word.capitalize() for word in name.replace('-', '_').split('_')])

def build_json():
    tools_list = []
    if not os.path.exists(SCRIPTS_DIR):
        return

    py_files = glob.glob(os.path.join(SCRIPTS_DIR, "*.py"))
    
    for py_file in py_files:
        filename = os.path.basename(py_file)
        tool_id = os.path.splitext(filename)[0]
        
        review_file = os.path.join(REVIEWS_DIR, tool_id + ".md")
        has_review = os.path.exists(review_file)
        
        # Default metrics
        default_metrics = {
            "Speed": 8,
            "Accuracy": 7,
            "Stealth": 9,
            "Coverage": 6,
            "Ease of Use": 8
        }
        
        tool_data = {
            "id": tool_id,
            "name": format_name(filename),
            "category": "General",
            "description": "أداة مضافة تلقائياً من الترسانة.",
            "language": "Python",
            "file_path": f"data/scripts/{filename}",
            "review_path": f"data/reviews/{tool_id}.md" if has_review else "",
            "usage": f"python {filename} [args]",
            "tags": ["Auto-Added", "Python"],
            "author": "NSMSO",
            "confidence_score": 90 if has_review else 50,
            "created_at": "2026-10-24",
            "metrics": default_metrics
        }
        tools_list.append(tool_data)

    with open(TOOLS_JSON, "w", encoding="utf-8") as f:
        json.dump({"tools": tools_list}, f, indent=2, ensure_ascii=False)

    print(f"[+] Rebuilt tools.json with {len(tools_list)} tools (metrics added).")

if __name__ == "__main__":
    import glob # import here just in case
    build_json()