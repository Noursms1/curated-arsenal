import sys, json, argparse

def load_signatures():
    """قائمة مختصرة من توقيعات الملفات الشائعة (hex) مع اسم النوع."""
    return {
        "25504446": "PDF",
        "89504E47": "PNG",
        "FFD8FF": "JPEG",
        "504B0304": "ZIP",
        "52617221": "RAR",
        "424D": "BMP",
        "7F454C46": "ELF",
        "4D5A": "EXE",
    }

def get_file_type(path, signatures):
    try:
        with open(path, "rb") as f:
            header = f.read(12).hex().upper()
    except Exception as e:
        return {"file": path, "error": str(e)}
    for magic, ftype in signatures.items():
        if header.startswith(magic):
            return {"file": path, "type": ftype, "magic": magic}
    return {"file": path, "type": "unknown"}

def main():
    parser = argparse.ArgumentParser(description="تحقق من توقيع الملفات وتحديد نوعها")
    parser.add_argument("files", nargs="*", help="مسارات الملفات للتحليل")
    args = parser.parse_args()

    # إذا لم تُعطَ مسارات عبر سطر الأوامر، اقرأها من stdin سطرًا بسطر
    file_paths = args.files
    if not file_paths:
        file_paths = [line.strip() for line in sys.stdin if line.strip()]

    signatures = load_signatures()
    results = [get_file_type(p, signatures) for p in file_paths]
    json.dump(results, sys.stdout, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
