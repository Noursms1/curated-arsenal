import sys, re, json
URL_RE = re.compile(r"https?://[^\s\"'<>\x00-\x1f]{5,200}")
def extract(path):
    try:
        with open(path, "rb") as f: data = f.read(10*1024*1024).decode("utf-8", errors="ignore")
        urls = sorted(set(URL_RE.findall(data)))
        return {"file": path, "count": len(urls), "urls": urls[:100]}
    except Exception as e: return {"error": str(e)}
if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else input("Path: ")
    print(json.dumps(extract(p), indent=2, ensure_ascii=False))
