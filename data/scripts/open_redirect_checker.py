import sys
import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def load_payloads(source_path=None):
    """قراءة القيم المراد اختبارها من ملف أو من stdin"""
    payloads = []
    if source_path:
        with open(source_path, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]
    else:
        # قراءة من stdin إذا لم يُعطَ ملف
        for line in sys.stdin:
            line = line.strip()
            if line:
                payloads.append(line)
    return payloads

def build_test_url(base_url, payload, param_name='url'):
    """إضافة معلمة الاختبار إلى URL"""
    parsed = urlparse(base_url)
    query = parse_qs(parsed.query)
    query[param_name] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

def test_redirect(target_url, payloads, param_name='url'):
    vulnerable = []
    headers = {'User-Agent': 'open-redirect-checker'}
    for payload in payloads:
        test_url = build_test_url(target_url, payload, param_name)
        try:
            resp = requests.get(test_url, headers=headers, timeout=10, verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        # فحص الهيدر Location أولاً
        location = resp.headers.get('Location', '')
        if payload in location:
            vulnerable.append({'payload': payload, 'type': 'Location header', 'test_url': test_url})
            continue
        # فحص جسم الاستجابة إذا كان يحتوي على الـ payload
        if payload in resp.text:
            vulnerable.append({'payload': payload, 'type': 'Response body', 'test_url': test_url})
    return vulnerable

def main():
    if len(sys.argv) < 2:
        sys.stderr.write('Usage: python open_redirect_checker.py <target_url> [payload_file]\n')
        sys.exit(1)
    target_url = sys.argv[1]
    payload_file = sys.argv[2] if len(sys.argv) > 2 else None
    payloads = load_payloads(payload_file)
    results = test_redirect(target_url, payloads)
    output = {
        'target': target_url,
        'vulnerable_payloads': results,
        'checked': len(payloads)
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
