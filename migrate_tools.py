import os
import shutil
import re
import glob

# المسارات
OLD_DIR = r"C:\users\nour\ptc-webapp\data\tribe_tools"
NEW_DIR = r"C:\users\nour\curated-arsenal\data\scripts"
REVIEW_DIR = r"C:\users\nour\curated-arsenal\data\reviews"

print("[*] Starting migration from old platform...")
print(f"[*] Source: {OLD_DIR}")
print(f"[*] Target: {NEW_DIR}\n")

if not os.path.exists(OLD_DIR):
    print("[!] Old tools folder not found!")
    exit(1)

# إنشاء فولدر المراجعات لو مش موجود
os.makedirs(REVIEW_DIR, exist_ok=True)

migrated_count = 0
old_files = glob.glob(os.path.join(OLD_DIR, "*.py"))

for old_file in old_files:
    filename = os.path.basename(old_file)
    # إزالة الأرقام اللي في آخر الاسم
    clean_name = re.sub(r'_\d{9,}\.py$', '.py', filename)
    
    new_file_path = os.path.join(NEW_DIR, clean_name)
    review_file_path = os.path.join(REVIEW_DIR, clean_name.replace('.py', '.md'))
    
    # لو الأداة دي متضافة بالفعل نتخطاها
    if os.path.exists(new_file_path):
        continue
        
    try:
        # نقل السكريبت
        shutil.copy2(old_file, new_file_path)
        
        # إنشاء ملف مراجعة مبدئي
        tool_name = clean_name.replace('.py', '').replace('_', ' ').title()
        with open(review_file_path, "w", encoding="utf-8") as f:
            f.write(f"# Review: {tool_name}\n\n")
            f.write(f"## Overview\nThis tool was automatically migrated from the PCT platform.\n\n")
            f.write(f"## Original File\n`{filename}`\n\n")
            f.write(f"## Status\n- [ ] Needs Human Review\n- [ ] Tested\n")
            
        print(f"  [+] Migrated: {clean_name}")
        migrated_count += 1
    except Exception as e:
        print(f"  [!] Error migrating {filename}: {e}")

print(f"\n[✅] Migration complete! Added {migrated_count} new tools.")
print("[*] Now running build_arsenal.py to update the platform...")

# تشغيل سكريبت بناء الـ JSON
os.chdir(r"C:\users\nour\curated-arsenal")
os.system("python build_arsenal.py")