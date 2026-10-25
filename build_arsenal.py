# -*- coding: utf-8 -*-
import os
import json
import glob

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "data", "scripts")
REVIEWS_DIR = os.path.join(BASE_DIR, "data", "reviews")
TOOLS_JSON = os.path.join(BASE_DIR, "data", "tools.json")

def format_name(filename):
    # بيحول اسم الملف زي dns_resolver.py لاسم زي Dns Resolver
    name = os.path.splitext(filename)[0]
    return " ".join([word.capitalize() for word in name.replace('-', '_').split('_')])

def build_json():
    tools_list = []
    
    # التأكد إن الفولدرات موجودة
    if not os.path.exists(SCRIPTS_DIR):
        print("[!] Scripts folder not found.")
        return

    py_files = glob.glob(os.path.join(SCRIPTS_DIR, "*.py"))
    print(f"[*] Found {len(py_files)} scripts. Building tools.json...")

    for py_file in py_files:
        filename = os.path.basename(py_file)
        tool_id = os.path.splitext(filename)[0]
        
        # هل فيه ملف مراجعة؟
        review_file = os.path.join(REVIEWS_DIR, tool_id + ".md")
        has_review = os.path.exists(review_file)
        
        tool_data = {
            "id": tool_id,
            "name": format_name(filename),
            "category": "General", # تقدر تغيرها بعدين
            "description": "أداة مضافة تلقائياً من الترسانة. (راجع ملف المراجعة للتفاصيل).",
            "language": "Python",
            "file_path": f"data/scripts/{filename}",
            "review_path": f"data/reviews/{tool_id}.md" if has_review else "",
            "usage": f"python {filename} [args]",
            "tags": ["Auto-Added", "Python"],
            "author": "NSMSO",
            "confidence_score": 90 if has_review else 50,
            "created_at": "2026-10-24"
        }
        tools_list.append(tool_data)
        
        status = "✅ With Review" if has_review else "⚠️ Missing Review"
        print(f"  -> Added: {tool_id} ({status})")

    # حفظ الملف
    with open(TOOLS_JSON, "w", encoding="utf-8") as f:
        json.dump({"tools": tools_list}, f, indent=2, ensure_ascii=False)

    print(f"\n[✅] Successfully generated tools.json with {len(tools_list)} tools!")
    print("[*] Restart the Flask server to see the changes.")

if __name__ == "__main__":
    build_json()