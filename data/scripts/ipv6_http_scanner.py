import sys
import json
import ipaddress
import requests

def load_network():
    """قراءة نطاق IPv6 من سطر الأوامر أو من stdin"""
    if len(sys.argv) > 1:
        net_str = sys.argv[1].strip()
    else:
        net_str = sys.stdin.read().strip()
    if not net_str:
        raise ValueError('لم يتم توفير نطاق IPv6')
    return ipaddress.ip_network(net_str, strict=False)

def scan_network(network, limit=1000):
    """محاولة طلب HTTP GET إلى كل عنوان في النطاق (حتى الحد المحدد)"""
    reachable = []
    for i, ip in enumerate(network.hosts()):
        if i >= limit:
            break
        url = f'http://[{ip}]/'
        try:
            resp = requests.get(url, timeout=10, verify=False)
            # أي استجابة تُعتبر إشارة أن العنوان متاح
            reachable.append({
                'ip': str(ip),
                'status_code': resp.status_code,
                'reason': resp.reason
            })
        except requests.RequestException:
            # لا شيء يضاف إذا فشل الاتصال
            continue
    return reachable

def main():
    try:
        network = load_network()
        results = scan_network(network)
        print(json.dumps({'network': str(network), 'reachable': results}, ensure_ascii=False, indent=2))
    except Exception as e:
        error_obj = {'error': str(e)}
        print(json.dumps(error_obj, ensure_ascii=False))

if __name__ == '__main__':
    main()
