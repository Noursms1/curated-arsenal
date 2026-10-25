#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
subenum.py — تعداد النطاقات الفرعية من مصادر متعددة.

المصادر: Wayback CDX, crt.sh, HackerTarget, AlienVault OTX, URLScan.io
المتطلبات: pip install requests certifi

متغيرات بيئة اختيارية:
    OTX_API_KEY       مفتاح AlienVault OTX (ترويسة X-OTX-API-KEY)
    URLSCAN_API_KEY   مفتاح URLScan.io  (ترويسة API-Key)

رموز الخروج:
    0    نجح مصدر واحد على الأقل
    1    فشلت جميع المصادر
    2    خطأ في المدخلات (نطاق غير صالح / ملف / regex)
    130  مقاطعة Ctrl+C

الاستخدام:
    python subenum.py github.com
    python subenum.py github.com --sources wayback,crt --pretty
    python subenum.py github.com --format text --quiet
    python subenum.py github.com --exclude '^www\\.' --output out.json
    cat domains.txt | python subenum.py
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

import certifi
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__version__ = "1.1.0"

# ============================================================
# ثوابت
# ============================================================

USER_AGENT = f"subenum/{__version__} (+https://example.local; research)"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
HOST_IP_RE = re.compile(r"^([A-Za-z0-9*_.-]+),\s*([0-9A-Fa-f:.]+)$")

WAYBACK_CDX      = "https://web.archive.org/cdx/search/cdx"
CRTSH_API        = "https://crt.sh/"
HACKERTARGET_API = "https://api.hackertarget.com/hostsearch/"
OTX_API          = "https://otx.alienvault.com/api/v1/indicators/domain"
URLSCAN_API      = "https://urlscan.io/api/v1/search/"

OTX_API_KEY     = os.environ.get("OTX_API_KEY", "").strip()
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "").strip()

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
    if any(ord(c) > 127 for c in domain):
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError as e:
            raise ValueError(f"تعذّر تحويل IDN إلى punycode: {domain!r}") from e
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"نطاق غير صالح: {domain!r}")
    return domain


def build_session() -> requests.Session:
    """Session مع retry/backoff يحترم Retry-After (جلسة مستقلة لكل خيط)."""
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
    """تنظيف وتصفية موحّدة: أحرف صغيرة، إزالة '*.' والنقاط الطرفية،
    والاحتفاظ بالمضيفين داخل domain فقط."""
    suffix = "." + domain
    out: Set[str] = set()
    for h in hosts:
        if not h:
            continue
        h = str(h).strip().strip(".").lower()
        if h.startswith("*."):
            h = h[2:]
        if h == domain and include_apex:
            out.add(h)
        elif h.endswith(suffix):
            out.add(h)
    return out

# ============================================================
# المصادر
# ============================================================

def query_wayback(session: requests.Session, domain: str, *,
                  limit: int = 10000, wayback_filter: str = "statuscode:200",
                  timeout: int, quiet: bool, **_: object) -> Set[str]:
    params: Dict[str, str] = {
        "url": domain,
        "matchType": "domain",        # ← يجلب النطاق + كل نطاقاته الفرعية
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(limit),
    }
    if wayback_filter:
        params["filter"] = wayback_filter
    log(f"[wayback] {domain} (limit={limit}, filter={wayback_filter or 'none'})", quiet)
    polite_delay()

    resp = session.get(WAYBACK_CDX, params=params, timeout=timeout, verify=certifi.where())
    if resp.status_code in (429, 503):
        raise RuntimeError(f"Wayback: {resp.status_code} (after retries)")
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


def query_crtsh(session: requests.Session, domain: str, *,
                timeout: int, quiet: bool, **_: object) -> Set[str]:
    log(f"[crt.sh] {domain}", quiet)
    polite_delay()
    resp = session.get(CRTSH_API, params={"q": f"%.{domain}", "output": "json"},
                       timeout=timeout, verify=certifi.where())
    if resp.status_code in (429, 503):
        raise RuntimeError(f"crt.sh: {resp.status_code} (busy, after retries)")
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


def query_hackertarget(session: requests.Session, domain: str, *,
                       timeout: int, quiet: bool, **_: object) -> Set[str]:
    log(f"[hackertarget] {domain}", quiet)
    polite_delay()
    resp = session.get(HACKERTARGET_API, params={"q": domain},
                       timeout=timeout, verify=certifi.where())
    resp.raise_for_status()
    text = resp.text.strip()

    # تحليل صارم: كل سطر "host,ip" — لا يُرفض السطر لأن مضيفاً ما يحوي "error"
    hosts: Set[str] = set()
    for line in text.splitlines():
        m = HOST_IP_RE.match(line.strip())
        if m:
            hosts.add(m.group(1).lower())
    if not hosts:
        low = text.lower()
        if "api count exceeded" in low or low.startswith("error"):
            raise RuntimeError(f"hackertarget: quota/limit: {text[:120]!r}")
        raise RuntimeError(f"hackertarget: unexpected response: {text[:120]!r}")
    log(f"[hackertarget] {len(hosts)} hosts", quiet)
    return hosts


def query_otx(session: requests.Session, domain: str, *,
              timeout: int, quiet: bool, **_: object) -> Set[str]:
    url = f"{OTX_API}/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    log(f"[otx] {domain}", quiet)
    polite_delay()
    resp = session.get(url, headers=headers, timeout=timeout, verify=certifi.where())
    if resp.status_code in (401, 403):
        raise RuntimeError("OTX: auth required — set OTX_API_KEY")
    if resp.status_code == 404:
        log("[otx] no data (404)", quiet)
        return set()
    resp.raise_for_status()

    try:
        data = resp.json()
    except ValueError as e:
        raise RuntimeError(f"OTX: non-JSON: {resp.text[:160]!r}") from e
    entries = data.get("passive_dns") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return set()
    hosts = {str(e.get("hostname", "")).strip().lower()
             for e in entries if isinstance(e, dict) and e.get("hostname")}
    hosts.discard("")
    log(f"[otx] {len(entries)} records → {len(hosts)} hosts", quiet)
    return hosts


def query_urlscan(session: requests.Session, domain: str, *,
                  timeout: int, quiet: bool, **_: object) -> Set[str]:
    params = {"q": f"domain:{domain}", "size": "1000"}
    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
    log(f"[urlscan] {domain}", quiet)
    polite_delay()
    resp = session.get(URLSCAN_API, params=params, headers=headers,
                       timeout=timeout, verify=certifi.where())
    if resp.status_code in (401, 403):
        raise RuntimeError("urlscan: auth required — set URLSCAN_API_KEY")
    if resp.status_code == 429:
        raise RuntimeError("urlscan: 429 rate limited")
    resp.raise_for_status()

    try:
        data = resp.json()
    except ValueError as e:
        raise RuntimeError(f"urlscan: non-JSON: {resp.text[:160]!r}") from e
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return set()

    hosts: Set[str] = set()
    for r in results:
        if not isinstance(r, dict):
            continue
        page = r.get("page") or {}
        d = str(page.get("domain") or "").strip().lower()
        if d:
            hosts.add(d)
        u = extract_host(str(page.get("url") or ""))
        if u:
            hosts.add(u)
    if isinstance(data, dict) and data.get("has_more"):
        log("[urlscan] has_more=true — نتائج مقطوعة (استخدم URLSCAN_API_KEY لرفع الحد)", quiet)
    log(f"[urlscan] {len(results)} results → {len(hosts)} hosts", quiet)
    return hosts

# ============================================================
# المنسّق
# ============================================================

SOURCES: Dict[str, Callable[..., Set[str]]] = {
    "wayback": query_wayback,
    "crt": query_crtsh,
    "hackertarget": query_hackertarget,
    "otx": query_otx,
    "urlscan": query_urlscan,
}


def fetch_subdomains(domain: str, sources: List[str], *,
                     limit: int, wayback_filter: str, timeout: int,
                     include_apex: bool, quiet: bool, workers: int) -> dict:
    """جلب من جميع المصادر بالتوازي (خيط لكل مصدر، جلسة مستقلة لكل خيط)."""
    t0 = time.monotonic()
    all_hosts: Set[str] = set()
    succeeded: List[str] = []
    errors: Dict[str, str] = {}

    def run(name: str) -> Set[str]:
        session = build_session()
        kwargs: Dict[str, object] = {"timeout": timeout, "quiet": quiet}
        if name == "wayback":
            kwargs.update(limit=limit, wayback_filter=wayback_filter)
        ts = time.monotonic()
        try:
            raw = SOURCES[name](session, domain, **kwargs)
        except Exception as e:
            log(f"[{name}] FAILED after {time.monotonic() - ts:.1f}s: {e}", quiet)
            raise
        log(f"[{name}] done in {time.monotonic() - ts:.1f}s", quiet)
        return raw

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(sources)))) as ex:
        fut_map = {ex.submit(run, name): name for name in sources}
        for fut in as_completed(fut_map):
            name = fut_map[fut]
            try:
                raw = fut.result()
            except Exception as e:
                errors[name] = f"{type(e).__name__}: {e}"
                continue
            all_hosts |= filter_subdomains(raw, domain, include_apex)
            succeeded.append(name)

    succeeded.sort(key=sources.index)
    elapsed = round(time.monotonic() - t0, 1)

    result = {
        "domain": domain,
        "sources_ok": succeeded,
        "count": len(all_hosts),
        "subdomains": sorted(all_hosts),
        "elapsed_sec": elapsed,
    }
    if errors:
        result["errors"] = errors
    log(f"[result] {domain}: {len(all_hosts)} hosts | ok={succeeded} | {elapsed}s", quiet)
    return result

# ============================================================
# CLI
# ============================================================

def emit(results: List[dict], args: argparse.Namespace) -> None:
    if args.format == "text":
        out_text = "".join(f"{h}\n" for res in results for h in res["subdomains"])
    else:
        payload = results[0] if len(results) == 1 else results
        out_text = json.dumps(payload, ensure_ascii=False,
                              indent=2 if args.pretty else None) + "\n"
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_text)
        except OSError as e:
            print(json.dumps({"error": f"output: {e}"}, ensure_ascii=False),
                  file=sys.stderr)
            sys.stdout.write(out_text)   # fallback: لا نفقد البيانات
            return
        log(f"[main] saved → {args.output}", args.quiet)
    else:
        sys.stdout.write(out_text)


def main(argv: Optional[List[str]] = None) -> int:
    # ضمان UTF-8 على ويندوز (منع انهيار الطباعة على cp1252)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except Exception:
            pass

    p = argparse.ArgumentParser(
        prog="subenum.py",
        description="تعداد نطاقات فرعية من Wayback + crt.sh + HackerTarget + OTX + URLScan.",
    )
    p.add_argument("domain", nargs="?", help="النطاق (أو من stdin)")
    p.add_argument("--file", help="ملف بنطاق في كل سطر")
    p.add_argument("--sources", default="wayback,crt,hackertarget,otx,urlscan",
                   help="قائمة مصادر مفصولة بفواصل (افتراضي: الكل)")
    p.add_argument("--limit", type=int, default=10000,
                   help="حد URLs لـ Wayback فقط (افتراضي 10000)")
    p.add_argument("--wayback-filter", default="statuscode:200",
                   help='فلتر CDX لحقل statuscode (افتراضي "statuscode:200"؛ "none" للتعطيل)')
    p.add_argument("--timeout", type=int, default=120, help="مهلة الشبكة (ثانية)")
    p.add_argument("--workers", type=int, default=4,
                   help="أقصى عدد مصادر متوازية (افتراضي 4)")
    p.add_argument("--include-apex", action="store_true",
                   help="تضمين النطاق الأساسي")
    p.add_argument("--exclude", help="regex لحذف المضيفين المطابقين (case-insensitive)")
    p.add_argument("--output", help="حفظ النتيجة إلى ملف بدل stdout")
    p.add_argument("--format", choices=["json", "text"], default="json")
    p.add_argument("--pretty", action="store_true", help="JSON منسّق")
    p.add_argument("--quiet", action="store_true", help="بلا رسائل تقدّم")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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

    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    sources = list(dict.fromkeys(sources))          # إزالة التكرار مع حفظ الترتيب
    if any(s not in SOURCES for s in sources):
        print(json.dumps({"error": f"unknown sources; valid={list(SOURCES)}"},
                         ensure_ascii=False), file=sys.stderr)
        return 2

    exclude_re: Optional[re.Pattern] = None
    if args.exclude:
        try:
            exclude_re = re.compile(args.exclude, re.IGNORECASE)
        except re.error as e:
            print(json.dumps({"error": f"invalid --exclude regex: {e}"},
                             ensure_ascii=False), file=sys.stderr)
            return 2

    wayback_filter = args.wayback_filter.strip()
    if wayback_filter.lower() == "none":
        wayback_filter = ""

    results: List[dict] = []
    any_success = False
    try:
        for domain in domains:
            res = fetch_subdomains(
                domain, sources, limit=args.limit, wayback_filter=wayback_filter,
                timeout=args.timeout, include_apex=args.include_apex,
                quiet=args.quiet, workers=args.workers,
            )
            if exclude_re:
                res["subdomains"] = [h for h in res["subdomains"]
                                     if not exclude_re.search(h)]
                res["count"] = len(res["subdomains"])
            results.append(res)
            any_success = any_success or bool(res["sources_ok"])
    except KeyboardInterrupt:
        print(json.dumps({"error": "interrupted"}, ensure_ascii=False), file=sys.stderr)
        return 130

    emit(results, args)
    return 0 if any_success else 1


if __name__ == "__main__":
    sys.exit(main())