#!/usr/bin/env python3
"""
فحص رؤوس الأمان في استجابة HTTP.
"""

import sys
import json
import argparse
import requests

def main():
    parser = argparse.ArgumentParser(description="فحص رؤوس الأمان في استجابة HTTP.")
    parser.add_argument("url", nargs="?", help="عنوان URL المستهدف")
    args = parser.parse_args()

    if not args.url:
        # قراءة العنوان من stdin إذا لم يُعطى في سطر الأوامر
        url = sys.stdin.read().strip()
    else:
        url = args.url
    if "://" not in url:
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=10, verify=False)
    except Exception as e:
        result = {"error": str(e)}
        print(json.dumps(result, ensure_ascii=False))
        return

    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    present = {h: resp.headers.get(h) for h in security_headers if h in resp.headers}
    missing = [h for h in security_headers if h not in resp.headers]

    output = {
        "url": url,
        "present_headers": present,
        "missing_headers": missing,
        "status_code": resp.status_code,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
