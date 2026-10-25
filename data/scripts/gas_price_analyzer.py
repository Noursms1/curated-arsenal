import sys
import json
import requests
from datetime import datetime

def fetch_eth_gas_prices():
    """جلب أسعار الغاز من ethgasstation.info وتوحيد الوحدات إلى Gwei"""
    url = "https://ethgasstation.info/api/ethgasAPI.json"
    try:
        resp = requests.get(url, timeout=10, verify=False)
        resp.raise_for_status()
        data = resp.json()
        # القيم في ethgasstation مضروبة في 10
        safe_low = data.get('safeLow') / 10.0
        average = data.get('average') / 10.0
        fast = data.get('fast') / 10.0
        return {
            "safeLow": safe_low,
            "average": average,
            "fast": fast,
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        }
    except Exception as e:
        return {"error": str(e)}

def main():
    # قراءة السلسلة المطلوبة من سطر الأوامر (حاليًا يدعم فقط eth)
    chain = "eth"
    if len(sys.argv) > 1:
        chain = sys.argv[1].lower()
    if chain != "eth":
        result = {"error": f"سلسلة غير مدعومة: {chain}. الأداة تدعم فقط eth حالياً."}
    else:
        result = fetch_eth_gas_prices()
    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
