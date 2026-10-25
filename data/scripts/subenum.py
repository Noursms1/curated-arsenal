#!/usr/bin/env python3
"""
subenum.py — تعداد النطاقات الفرعية من مصادر متعددة.

المصادر: Wayback CDX, crt.sh, HackerTarget
المتطلبات: pip install requests certifi

الاستخدام:
    python subenum.py github.com
    python subenum.py github.com --sources wayback,crt --pretty
    python subenum.py github.com --format text --quiet
    cat domains.txt | python subenum.py
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

import certifi
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============================================================
# ثوابت
# ============================================================

USER_AGENT = "subenum/1.0 (+https://example.local; research)"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

WAYBACK_CDX     = "https://web.archive.org/cdx/search/cdx"
CRTSH_API       = "https://crt.sh/"
HACKERTARGET_API = "https://api.hackertarget.com/hostsearch/"

# ============================================================
# أدوات مساعدة
# ============================================================

def log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(msg, file=sys.stderr)


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower().strip(".")
    if not domain:
        raise ValueError("نطاق فارغ")
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"نطاق غير صالح: {domain!r}")
    return domain


def build_session() -> requests.Session:
    """Session مع retry/backoff يحترم Retry-After."""
    session = requests.Session()
    retries = Retry(
        total=4,
        backoff_factor=2,           # 2, 4, 8, 16 ثانية
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        respect_retry_after_header=True,
        raise_on_status=False,      # نتعامل مع الحالة النهائية بأنفسنا
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
    })
    return session


def polite_delay(lo: float = 0.8, hi: float = 1.8) -> None:
    time.sleep(random.uniform(lo, hi))


def extract_host(url: str) -> Optional[str]:
    try:
        h = urlparse(url).hostname
        return h.lower() if h else None
    except (ValueError, AttributeError):
        return None


def filter_subdomains(hosts: Iterable[str], domain: str, include_apex: bool) -> Set[str]:
    suffix = "." + domain
    out: Set[str] = set()
    for h in hosts:
        if not h:
            continue
        if h == domain and include_apex:
            out.add(h)
        elif h.endswith(suffix):
            out.add(h)
    return out

# ============================================================
# المصادر
# ============================================================

def query_wayback(session, domain, limit, timeout, quiet) -> Set[str]:
    params = {
        "url": domain,
        "matchType": "domain",        # ← التصحيح الجوهري
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(limit),
        "filter": "statuscode:200",
    }
    log(f"[wayback] {domain} (limit={limit})", quiet)
    polite_delay()

    resp = session.get(WAYBACK_CDX, params=params, timeout=timeout, verify=certifi.where())
    if resp.status_code == 503:
        raise RuntimeError("Wayback: 503 Service Unavailable")
    if resp.status_code == 429:
        raise RuntimeError("Wayback: 429 Too Many Requests")
    resp.raise_for_status()

    text = resp.text.strip()
    if not text:
        return set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise RuntimeError(f"Wayback: non-JSON response: {text[:160]!r}")

    if not isinstance(data, list) or not data:
        return set()

    # تخطّي صف الرأس ["original"] صراحةً
    rows = data[1:] if data and isinstance(data[0], list) and data[0] == ["original"] else data
    hosts = (extract_host(r[0]) for r in rows
             if isinstance(r, list) and r and r[0])
    result = {h for h in hosts if h}
    log(f"[wayback] {len(rows)} URL → {len(result)} hosts", quiet)
    return result


def query_crtsh(session, domain, timeout, quiet) -> Set[str]:
    log(f"[crt.sh] {domain}", quiet)
    polite_delay()
    resp = session.get(CRTSH_API, params={"q": f"%.{domain}", "output": "json"},
                       timeout=timeout, verify=certifi.where())
    if resp.status_code == 503:
        raise RuntimeError("crt.sh: 503 (busy)")
    resp.raise_for_status()

    text = resp.text.strip()
    if not text:
        return set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise RuntimeError(f"crt.sh: non-JSON: {text[:160]!r}")

    if not isinstance(data, list):
        return set()

    hosts: Set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name:
                hosts.add(name)
    log(f"[crt.sh] {len(data)} certs → {len(hosts)} hosts", quiet)
    return hosts


def query_hackertarget(session, domain, timeout, quiet) -> Set[str]:
    log(f"[hackertarget] {domain}", quiet)
    polite_delay()
    resp = session.get(HACKERTARGET_API, params={"q": domain},
                       timeout=timeout, verify=certifi.where())
    resp.raise_for_status()
    text = resp.text.strip()

    low = text.lower()
    if not text or "error" in low or "api count exceeded" in low:
        raise RuntimeError(f"hackertarget: {text[:120]!r}")

    hosts: Set[str] = set()
    for line in text.splitlines():
        if "," in line:
            h = line.split(",", 1)[0].strip().lower()
            if h:
                hosts.add(h)
    log(f"[hackertarget] {len(hosts)} hosts", quiet)
    return hosts

# ============================================================
# المنسّق
# ============================================================

SOURCES = {
    "wayback": query_wayback,
    "crt": query_crtsh,
    "hackertarget": query_hackertarget,
}


def fetch_subdomains(domain, sources, limit, timeout, include_apex, quiet) -> dict:
    session = build_session()
    all_hosts: Set[str] = set()
    succeeded: List[str] = []
    errors: dict = {}

    for name in sources:
        fn = SOURCES.get(name)
        if fn is None:
            errors[name] = "unknown source"
            continue
        try:
            if name == "wayback":
                raw = fn(session, domain, limit=limit, timeout=timeout, quiet=quiet)
            else:
                raw = fn(session, domain, timeout=timeout, quiet=quiet)
            all_hosts |= filter_subdomains(raw, domain, include_apex)
            succeeded.append(name)
        except Exception as e:
            errors[name] = f"{type(e).__name__}: {e}"
            log(f"[{name}] FAILED: {e}", quiet)

    result = {
        "domain": domain,
        "sources_ok": succeeded,
        "count": len(all_hosts),
        "subdomains": sorted(all_hosts),
    }
    if errors:
        result["errors"] = errors
    return result

# ============================================================
# CLI
# ============================================================

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="subenum.py",
        description="تعداد نطاقات فرعية من Wayback + crt.sh + HackerTarget.",
    )
    p.add_argument("domain", nargs="?", help="النطاق (أو من stdin)")
    p.add_argument("--file", help="ملف بنطاق في كل سطر")
    p.add_argument("--sources", default="wayback,crt,hackertarget",
                   help="قائمة مصادر (افتراضي: الكل)")
    p.add_argument("--limit", type=int, default=10000,
                   help="حد URLs لـ Wayback (افتراضي 10000)")
    p.add_argument("--timeout", type=int, default=120, help="مهلة الشبكة (ثانية)")
    p.add_argument("--include-apex", action="store_true",
                   help="تضمين النطاق الأساسي")
    p.add_argument("--format", choices=["json", "text"], default="json")
    p.add_argument("--pretty", action="store_true", help="JSON منسّق")
    p.add_argument("--quiet", action="store_true", help="بلا رسائل تقدّم")
    args = p.parse_args(argv)

    # جمع النطاقات
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                raw = [ln.strip() for ln in f
                       if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError as e:
            print(json.dumps({"error": f"file: {e}"}), file=sys.stderr)
            return 2
    elif args.domain:
        raw = [args.domain]
    else:
        raw = [ln.strip() for ln in sys.stdin.read().splitlines() if ln.strip()]

    if not raw:
        print(json.dumps({"error": "no domain provided"}, ensure_ascii=False),
              file=sys.stderr)
        return 2

    domains: List[str] = []
    for d in raw:
        try:
            domains.append(validate_domain(d))
        except ValueError as e:
            print(json.dumps({"error": str(e)}, ensure_ascii=False), file=sys.stderr)

    if not domains:
        return 2

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    if any(s not in SOURCES for s in sources):
        print(json.dumps({"error": f"unknown sources; valid={list(SOURCES)}"}),
              file=sys.stderr)
        return 2

    results = []
    any_success = False
    for domain in domains:
        res = fetch_subdomains(
            domain, sources=sources, limit=args.limit,
            timeout=args.timeout, include_apex=args.include_apex,
            quiet=args.quiet,
        )
        results.append(res)
        any_success = any_success or bool(res["sources_ok"])

    # الإخراج
    if args.format == "text":
        for res in results:
            for h in res["subdomains"]:
                print(h)
    else:
        payload = results[0] if len(results) == 1 else results
        json.dump(payload, sys.stdout, ensure_ascii=False,
                  indent=2 if args.pretty else None)
        sys.stdout.write("\n")

    return 0 if any_success else 1


if __name__ == "__main__":
    sys.exit(main())