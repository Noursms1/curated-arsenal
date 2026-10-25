#!/usr/bin/env python3
"""
crtsh.py — استخراج النطاقات الفرعية من crt.sh.

المتطلبات:
    pip install requests certifi

الاستخدام:
    python crtsh.py github.com
    python crtsh.py github.com --pretty --include-wildcards
    python crtsh.py github.com --format text --quiet
    python crtsh.py --file domains.txt
    cat domains.txt | python crtsh.py

أكواد الخروج:
    0 = نجح الاستعلام (حتى لو صفر نتائج)
    1 = فشل الاستعلام
    2 = خطأ إدخال
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from typing import Iterable, List, Optional, Set

import certifi
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============================================================
# ثوابت
# ============================================================

CRTSH_API = "https://crt.sh/"

USER_AGENT = "crtsh-cli/2.0 (+https://example.local; security research)"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# أحرف تحيط بالنطاق قد تظهر في name_value
CLEAN_CHARS = " \t\r\n,;"

# ============================================================
# أدوات
# ============================================================

def log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(msg, file=sys.stderr)


def validate_domain(domain: str) -> str:
    """يطبّع ويتحقق من نطاق."""
    domain = domain.strip().lower().strip(".")
    if not domain:
        raise ValueError("نطاق فارغ")
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"نطاق غير صالح: {domain!r}")
    return domain


def build_session() -> requests.Session:
    """
    Session مع retry على 503/429/5xx.
    crt.sh يرفض كثيرًا تحت الضغط، فاحتياطي على 429/503 ضروري.
    """
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=2,                 # 2, 4, 8, 16, 32 ثانية
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json, */*",
    })
    return session


def polite_delay(lo: float = 1.0, hi: float = 2.5) -> None:
    """crt.sh يفضّل تأخيرًا بين الطلبات."""
    time.sleep(random.uniform(lo, hi))


def normalize_name(name: str) -> Optional[str]:
    """
    - trim
    - lowercase
    - إزالة أحرف تحيط
    - رفض ما ليس نطاقًا
    """
    if not name:
        return None
    name = name.strip(CLEAN_CHARS).lower()
    if not name:
        return None
    # rfc: يجب أن يحتوي نقطة على الأقل (TLD)
    if "." not in name:
        return None
    # رفض الأحرف غير المسموحة
    if not re.match(r"^[a-z0-9.*_-]+$", name):
        return None
    return name

# ============================================================
# منطق الاستعلام
# ============================================================

def query_crtsh(
    session: requests.Session,
    domain: str,
    timeout: int,
    quiet: bool,
) -> List[dict]:
    """
    يستعلم crt.sh ويعيد list of dict (كل عنصر شهادة).
    يرفع RuntimeError عند فشل بعد كل المحاولات.
    """
    log(f"[crt.sh] querying %.{domain} ...", quiet)
    polite_delay()

    try:
        resp = session.get(
            CRTSH_API,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
            verify=certifi.where(),       # ← التحقق مفعّل
        )
    except requests.RequestException as e:
        raise RuntimeError(f"network: {type(e).__name__}: {e}") from e

    if resp.status_code == 503:
        raise RuntimeError("crt.sh: 503 Service Unavailable (busy)")
    if resp.status_code == 429:
        raise RuntimeError("crt.sh: 429 Too Many Requests")
    if resp.status_code >= 500:
        raise RuntimeError(f"crt.sh: HTTP {resp.status_code}")
    resp.raise_for_status()

    text = resp.text.strip()
    if not text:
        log("[crt.sh] empty response (likely zero results)", quiet)
        return []

    try:
        data = resp.json()
    except ValueError as e:
        # crt.sh أحيانًا يرد بصفحة HTML عند overload
        raise RuntimeError(
            f"crt.sh: non-JSON response (first 200 chars): {text[:200]!r}"
        ) from e

    if not isinstance(data, list):
        raise RuntimeError(f"crt.sh: unexpected JSON type: {type(data).__name__}")

    log(f"[crt.sh] {len(data)} certificate entries received", quiet)
    return data


def extract_hosts(
    entries: Iterable[dict],
    domain: str,
    include_apex: bool,
    include_wildcards: bool,
) -> Set[str]:
    """يستخرج أسماء النطاقات الفرعية، مع الفلترة والتنظيف."""
    suffix = "." + domain
    hosts: Set[str] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("name_value")
        if not raw or not isinstance(raw, str):
            continue

        for line in raw.splitlines():
            name = normalize_name(line)
            if not name:
                continue

            # معالجة wildcards
            if name.startswith("*."):
                if not include_wildcards:
                    name = name[2:]
                else:
                    # نبقيها كـ wildcard
                    pass

            # فلترة النطاق
            if name == domain:
                if include_apex:
                    hosts.add(name)
                continue
            if name.endswith(suffix):
                hosts.add(name)

    return hosts

# ============================================================
# المنسّق
# ============================================================

def fetch_subdomains(
    domain: str,
    timeout: int = 60,
    include_apex: bool = False,
    include_wildcards: bool = False,
    quiet: bool = False,
) -> dict:
    """يعيد dict كامل النتيجة."""
    session = build_session()
    result = {
        "domain": domain,
        "source": "crt.sh",
        "count": 0,
        "subdomains": [],
    }

    try:
        entries = query_crtsh(session, domain, timeout=timeout, quiet=quiet)
        hosts = extract_hosts(entries, domain,
                              include_apex=include_apex,
                              include_wildcards=include_wildcards)
        result["subdomains"] = sorted(hosts)
        result["count"] = len(hosts)
        log(f"[crt.sh] {len(hosts)} unique hosts after filtering", quiet)
    except RuntimeError as e:
        result["error"] = str(e)
        log(f"[crt.sh] FAILED: {e}", quiet)

    return result

# ============================================================
# CLI
# ============================================================

def _gather_domains(args) -> List[str]:
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                return [ln.strip() for ln in f
                        if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError as e:
            raise SystemExit(f"file: {e}")
    if args.domain:
        return [args.domain]
    return [ln.strip() for ln in sys.stdin.read().splitlines() if ln.strip()]


def _clean_target(t):
    return t.replace("http://", "").replace("https://", "").split("/")[0].split("?")[0]

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="crtsh.py",
        description="استخراج النطاقات الفرعية من crt.sh.",
    )
    p.add_argument("domain", nargs="?", help="النطاق (أو من stdin)")
    p.add_argument("-f", "--file", help="ملف بنطاق في كل سطر")
    p.add_argument("--timeout", type=int, default=60,
                   help="مهلة الطلب (ثانية، افتراضي 60)")
    p.add_argument("--include-apex", action="store_true",
                   help="تضمين النطاق الأساسي في النتيجة")
    p.add_argument("--include-wildcards", action="store_true",
                   help="إبقاء السجلات wildcard كما هي (*.example.com)")
    p.add_argument("--format", choices=["json", "text"], default="json")
    p.add_argument("--pretty", action="store_true", help="JSON منسّق")
    p.add_argument("--quiet", action="store_true", help="بلا رسائل تقدّم")
    args = p.parse_args(argv)

    raw_domains = _gather_domains(args)
    if not raw_domains:
        print(json.dumps({"error": "no domain provided"}, ensure_ascii=False),
              file=sys.stderr)
        return 2

    domains: List[str] = []
    for d in raw_domains:
        try:
            domains.append(validate_domain(d))
        except ValueError as e:
            print(json.dumps({"error": str(e)}, ensure_ascii=False), file=sys.stderr)

    if not domains:
        return 2

    results = [
        fetch_subdomains(
            d,
            timeout=args.timeout,
            include_apex=args.include_apex,
            include_wildcards=args.include_wildcards,
            quiet=args.quiet,
        )
        for d in domains
    ]

    all_succeeded = all("error" not in r for r in results)

    if args.format == "text":
        for r in results:
            for h in r["subdomains"]:
                print(h)
    else:
        payload = results[0] if len(results) == 1 else results
        json.dump(payload, sys.stdout, ensure_ascii=False,
                  indent=2 if args.pretty else None)
        sys.stdout.write("\n")

    return 0 if all_succeeded else 1


if __name__ == "__main__":
    sys.exit(main())