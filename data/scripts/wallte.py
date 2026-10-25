#!/usr/bin/env python3
"""
allowance.py — قراءة allowance لعقد ERC-20 عبر eth_call.

مثال:
    python allowance.py 0xA0b8...eB48 0xOwner 0xSpender --pretty
    python allowance.py 0xToken 0xOwner 0xSpender --encode-only

المتطلبات:
    pip install eth-utils requests
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests
from eth_utils import is_address, keccak, to_checksum_address

# ============================================================
# ثوابت
# ============================================================

SELECTOR = keccak(text="allowance(address,address)")[:4].hex()  # dd62ed3e
UINT256_MAX = (1 << 256) - 1

DEFAULT_RPCS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://eth.drpc.org",
)

# ============================================================
# أخطاء مخصّصة
# ============================================================

class AllowanceError(Exception):
    """الخطأ الأساسي للأداة."""

class InvalidAddress(AllowanceError):
    pass

class RpcFailure(AllowanceError):
    pass

class UnsafeUrl(AllowanceError):
    pass

# ============================================================
# ترميز ABI
# ============================================================

def _pad_address(addr: str) -> str:
    """عنوان → 32 بايت hex بعد التحقق."""
    if not is_address(addr):
        raise InvalidAddress(f"عنوان غير صالح: {addr!r}")
    return addr[2:].lower().rjust(64, "0")


def encode_allowance(owner: str, spender: str) -> str:
    """يبني calldata: 0x + selector + owner + spender."""
    return "0x" + SELECTOR + _pad_address(owner) + _pad_address(spender)

# ============================================================
# حماية SSRF
# ============================================================

def _ensure_safe_url(url: str) -> None:
    """
    يرفض أي URL لا يمر عبر الشروط:
    - https فقط
    - host موجود
    - لا يشير إلى عنوان داخلي/خاص/loopback
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise UnsafeUrl(f"بروتوكول غير مسموح: {parsed.scheme!r}")
    if not parsed.hostname:
        raise UnsafeUrl("URL بدون host")

    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as e:
        raise UnsafeUrl(f"تعذّر حل DNS: {parsed.hostname}") from e

    for *_, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or
                ip.is_link_local or ip.is_reserved or ip.is_multicast):
            raise UnsafeUrl(f"عنوان محجوب: {ip}")

# ============================================================
# RPC
# ============================================================

def _eth_call(rpc_url: str, to: str, data: str, block: str = "latest") -> str:
    """استدعاء eth_call واحد. يرفع RpcFailure عند أي خطأ."""
    _ensure_safe_url(rpc_url)

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, block],
    }
    try:
        resp = requests.post(
            rpc_url,
            json=payload,
            timeout=15,
            verify=True,
            allow_redirects=False,  # منع bypass عبر redirect
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        raise RpcFailure(f"فشل الاتصال بـ {rpc_url}: {e}") from e

    try:
        body = resp.json()
    except ValueError as e:
        raise RpcFailure(f"استجابة غير JSON من {rpc_url}") from e

    if "error" in body:
        msg = body["error"].get("message", str(body["error"]))
        raise RpcFailure(f"RPC error من {rpc_url}: {msg}")

    result = body.get("result")
    if result is None:
        raise RpcFailure(f"استجابة بلا حقل result من {rpc_url}")
    return result


def call_with_fallback(
    to: str, data: str, block: str, rpcs: List[str],
) -> Tuple[str, str]:
    """يحاول كل RPC بالترتيب. يعيد (result, rpc_used)."""
    last_error: Optional[AllowanceError] = None
    for rpc in rpcs:
        try:
            return _eth_call(rpc, to, data, block), rpc
        except (RpcFailure, UnsafeUrl) as e:
            last_error = e
    raise RpcFailure(f"كل RPCs فشلت. آخر خطأ: {last_error}")

# ============================================================
# تحليل النتيجة
# ============================================================

def decode_uint256(raw: str) -> Optional[int]:
    """'0x' → None (لا بيانات). '0x0' → 0. غير ذلك → int."""
    if raw in ("0x", ""):
        return None
    try:
        value = int(raw, 16)
    except ValueError as e:
        raise RpcFailure(f"قيمة hex غير صالحة: {raw!r}") from e
    if not 0 <= value <= UINT256_MAX:
        raise RpcFailure(f"قيمة خارج نطاق uint256: {value}")
    return value


def classify(value: Optional[int]) -> str:
    if value is None:
        return "no_data"
    if value == 0:
        return "zero"
    if value == UINT256_MAX:
        return "unlimited"
    return "finite"

# ============================================================
# قلب المنطق
# ============================================================

def check_allowance(
    token: str, owner: str, spender: str,
    rpcs: List[str], block: str = "latest",
) -> Dict[str, Any]:
    """ينفّذ الاستدعاء ويعيد dict كامل."""
    token_c = to_checksum_address(token)
    owner_c = to_checksum_address(owner)
    spender_c = to_checksum_address(spender)

    data = encode_allowance(owner_c, spender_c)
    raw, rpc_used = call_with_fallback(token_c, data, block, rpcs)
    value = decode_uint256(raw)

    return {
        "token": token_c,
        "owner": owner_c,
        "spender": spender_c,
        "block": block,
        "allowance": value,
        "allowance_hex": None if value is None else hex(value),
        "classification": classify(value),
        "rpc_used": rpc_used,
        "selector": "0x" + SELECTOR,
        "calldata": data,
        "raw_result": raw,
    }

# ============================================================
# اختبار ذاتي
# ============================================================

def _self_test() -> int:
    ok = True

    if SELECTOR != "dd62ed3e":
        print(f"[FAIL] selector = {SELECTOR!r}", file=sys.stderr)
        ok = False
    else:
        print(f"[OK] selector = 0x{SELECTOR}")

    owner = "0x0000000000000000000000000000000000000001"
    spender = "0x0000000000000000000000000000000000000002"
    expected = (
        "0xdd62ed3e"
        + "0" * 63 + "1"
        + "0" * 63 + "2"
    )
    got = encode_allowance(owner, spender)
    if got != expected:
        print(f"[FAIL] calldata mismatch\n  got: {got}\n  exp: {expected}",
              file=sys.stderr)
        ok = False
    else:
        print("[OK] calldata")

    assert decode_uint256("0x") is None
    assert decode_uint256("0x0") == 0
    assert decode_uint256("0xff") == 255
    print("[OK] decode_uint256")

    return 0 if ok else 1

# ============================================================
# CLI
# ============================================================

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="allowance.py",
        description="قراءة allowance لعقد ERC-20 عبر eth_call.",
    )
    p.add_argument("token", nargs="?", help="عنوان عقد ERC-20")
    p.add_argument("owner", nargs="?", help="مالك الرصيد")
    p.add_argument("spender", nargs="?", help="المنفق المصرّح له")
    p.add_argument("--rpc", action="append", help="RPC URL (قابل للتكرار)")
    p.add_argument("--block", default="latest", help="رقم الكتلة (افتراضي latest)")
    p.add_argument("--pretty", action="store_true", help="JSON منسّق")
    p.add_argument("--quiet", action="store_true", help="إخراج مختصر")
    p.add_argument("--encode-only", action="store_true",
                   help="طباعة calldata فقط بدون اتصال")
    p.add_argument("--self-test", action="store_true", help="اختبار داخلي")
    return p


def _emit(obj: Dict[str, Any], pretty: bool) -> None:
    json.dump(obj, sys.stdout, ensure_ascii=False,
              indent=2 if pretty else None)
    sys.stdout.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.self_test:
        return _self_test()

    if not (args.token and args.owner and args.spender):
        _build_parser().print_help(sys.stderr)
        return 2

    try:
        if args.encode_only:
            _emit({"calldata": encode_allowance(args.owner, args.spender)},
                  args.pretty)
            return 0

        result = check_allowance(
            args.token, args.owner, args.spender,
            rpcs=args.rpc or list(DEFAULT_RPCS),
            block=args.block,
        )
        if args.quiet:
            result = {
                "allowance": result["allowance"],
                "classification": result["classification"],
            }
        _emit(result, args.pretty)
        return 0

    except InvalidAddress as e:
        _emit({"error": str(e), "kind": "invalid_address"}, args.pretty)
        return 2
    except (RpcFailure, UnsafeUrl) as e:
        _emit({"error": str(e), "kind": "rpc"}, args.pretty)
        return 1


if __name__ == "__main__":
    sys.exit(main())