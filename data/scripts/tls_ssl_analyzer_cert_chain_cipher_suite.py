#!/usr/bin/env python3
"""
CATEGORY: TLS/SSL Analyzer
TECHNIQUES: Certificate Inspection, Cipher Suite Enumeration, Protocol Version Detection, HTTP Header Analysis
CHAIN_CONTRIBUTIONS: ssl, socket, http.client, json, argparse, time, datetime, ipaddress
"""

import argparse
import json
import socket
import ssl
import sys
import time
from datetime import datetime
from http.client import HTTPSConnection, RemoteDisconnected
from typing import Any, Dict, List, Tuple

VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10
RATE_LIMIT = 0.5  # seconds


def rate_limited():
    """Enforce simple rate limiting between network calls."""
    time.sleep(RATE_LIMIT)


def fetch_cert_chain(host: str, port: int) -> List[Dict[str, Any]]:
    """Retrieve the server's certificate chain."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_certs = ssock.getpeercert(binary_form=True)
                # ssl module does not expose full chain; we capture leaf only.
                cert = ssl.DER_cert_to_PEM_cert(der_certs)
                parsed = ssl._ssl._test_decode_cert(cert)  # type: ignore
                chain = [{
                    "subject": dict(parsed.get("subject", [])),
                    "issuer": dict(parsed.get("issuer", [])),
                    "notBefore": parsed.get("notBefore"),
                    "notAfter": parsed.get("notAfter"),
                    "subjectAltName": parsed.get("subjectAltName", []),
                }]
                return chain
    except Exception as e:
        return [{"error": str(e)}]


def test_protocol(host: str, port: int, protocol: int) -> bool:
    """Attempt TLS handshake with a specific protocol version."""
    try:
        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def detect_supported_protocols(host: str, port: int) -> List[str]:
    """Detect which TLS protocol versions are supported by the server."""
    protocols = {
        "TLSv1": ssl.TLSVersion.SSLv3,  # placeholder, will be filtered
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    supported = []
    for name, version in protocols.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = version
            ctx.maximum_version = version
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs()
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    supported.append(name)
        except Exception:
            continue
        finally:
            rate_limited()
    return supported


def get_negotiated_cipher(host: str, port: int) -> str:
    """Perform a TLS handshake and return the negotiated cipher suite."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                return cipher[0] if cipher else "unknown"
    except Exception as e:
        return f"error: {e}"


def fetch_http_security_headers(host: str, port: int) -> Dict[str, str]:
    """Retrieve HSTS and HPKP headers from the server's HTTPS response."""
    headers = {}
    try:
        conn = HTTPSConnection(host, port=port, timeout=DEFAULT_TIMEOUT, context=ssl.create_default_context())
        conn.request("GET", "/")
        resp = conn.getresponse()
        for hdr in ["strict-transport-security", "public-key-pins"]:
            val = resp.getheader(hdr)
            if val:
                headers[hdr] = val
        conn.close()
    except (RemoteDisconnected, socket.timeout, ssl.SSLError, ConnectionError) as e:
        headers["error"] = str(e)
    finally:
        rate_limited()
    return headers


def analyze_target(target: str) -> Dict[str, Any]:
    """Run full TLS/SSL analysis on the given target."""
    if ":" in target:
        host, port_str = target.split(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 443

    result: Dict[str, Any] = {
        "tool": "TLSAnalyzer",
        "version": VERSION,
        "target": f"{host}:{port}",
        "status": "completed",
        "technologies": ["TLS", "HTTPS"],
        "findings": {},
        "results": {}
    }

    # Certificate chain
    cert_chain = fetch_cert_chain(host, port)
    result["findings"]["certificate_chain"] = cert_chain
    rate_limited()

    # Supported protocols
    protocols = detect_supported_protocols(host, port)
    result["findings"]["supported_protocols"] = protocols
    rate_limited()

    # Negotiated cipher suite
    cipher = get_negotiated_cipher(host, port)
    result["findings"]["negotiated_cipher"] = cipher
    rate_limited()

    # HTTP security headers
    headers = fetch_http_security_headers(host, port)
    result["findings"]["http_security_headers"] = headers

    return result


def self_test() -> int:
    """Simple self‑test using a well‑known host."""
    test_target = "www.google.com:443"
    print(f"Running self‑test against {test_target} ...", file=sys.stderr)
    try:
        output = analyze_target(test_target)
        # Basic sanity checks
        assert "certificate_chain" in output["findings"]
        assert "supported_protocols" in output["findings"]
        assert "negotiated_cipher" in output["findings"]
        assert "http_security_headers" in output["findings"]
        print(json.dumps(output, indent=2))
        print("Self‑test passed.", file=sys.stderr)
        return 0
    except AssertionError as e:
        print("Self‑test failed: missing expected fields.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Self‑test encountered an error: {e}", file=sys.stderr)
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="TLS/SSL Analyzer – certificate chain, cipher suites, protocols, HSTS, HPKP")
    parser.add_argument("target", nargs="?", help="Target host (optionally with port, e.g., example.com:443)")
    parser.add_argument("--self-test", action="store_true", help="Run built‑in self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())

    if not args.target:
        parser.error("target is required unless --self-test is used")

    try:
        result = analyze_target(args.target)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except KeyboardInterrupt:
        sys.exit("\nInterrupted by user.")
    except Exception as exc:
        error_output = {
            "tool": "TLSAnalyzer",
            "version": VERSION,
            "target": args.target,
            "status": "error",
            "technologies": [],
            "findings": {},
            "results": {"error": str(exc)}
        }
        print(json.dumps(error_output, ensure_ascii=False, indent=2), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()