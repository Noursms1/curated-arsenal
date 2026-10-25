import sys, json, re
import requests

def fetch_source(address, api_key):
    url = f'https://api.etherscan.io/api'
    params = {
        'module': 'contract',
        'action': 'getsourcecode',
        'address': address,
        'apikey': api_key
    }
    try:
        resp = requests.get(url, params=params, timeout=10, verify=False)
        resp.raise_for_status()
        data = resp.json()
        if data.get('status') != '1' or not data.get('result'):
            return None
        source = data['result'][0].get('SourceCode')
        # Etherscan may wrap source in extra braces for multi‑file contracts
        if source.startswith('{') and source.endswith('}'):
            try:
                source = json.loads(source)
                # take first file content if dict
                if isinstance(source, dict):
                    source = next(iter(source.values()))
            except Exception:
                pass
        return source
    except Exception:
        return None

def detect_reentrancy(source):
    if not source:
        return {'risk': False, 'issues': []}
    issues = []
    lines = source.split('\n')
    external_call_pattern = re.compile(r'\b(call|delegatecall|send|transfer)\b')
    state_assign_pattern = re.compile(r'\b\w+\s*=')
    for i, line in enumerate(lines):
        if external_call_pattern.search(line):
            # look ahead a few lines for state change before a return or end of function
            for j in range(i + 1, min(i + 6, len(lines))):
                next_line = lines[j]
                if state_assign_pattern.search(next_line):
                    issues.append({
                        'line': j + 1,
                        'code': next_line.strip(),
                        'message': 'تعديل حالة بعد استدعاء خارجي قد يسبب إعادة الدخول'
                    })
                    break
    return {'risk': bool(issues), 'issues': issues}

def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            'error': 'استخدام: python reentrancy_scanner.py <contract_address> <etherscan_api_key>'
        }))
        sys.exit(1)
    address = sys.argv[1]
    api_key = sys.argv[2]
    source = fetch_source(address, api_key)
    result = detect_reentrancy(source)
    output = {
        'contract': address,
        'reentrancy_risk': result['risk'],
        'issues': result['issues']
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
