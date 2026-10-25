#!/usr/bin/env python3
"""
CATEGORY: API
TECHNIQUES: Endpoint Discovery, Method Override, Mass Assignment Detection, Rate Limiting
CHAIN_CONTRIBUTIONS: Integrated with standard libraries only, no external binaries, safe request handling.
"""

import argparse
import json
import threading
import time
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urljoin, urlparse
import socket
import requests

# Global constants
DEFAULT_TIMEOUT = 10
RATE_DELAY = 0.5
USER_AGENT = "AutonomousForge-API-Fuzzer/1.0"

def safe_request(method, url, **kwargs):
    """Wrap requests to enforce timeout, headers, and error handling."""
    headers = kwargs.pop('headers', {})
    headers.setdefault('User-Agent', USER_AGENT)
    try:
        resp = requests.request(method, url, timeout=DEFAULT_TIMEOUT, headers=headers, **kwargs)
        time.sleep(RATE_DELAY)
        return resp
    except requests.RequestException as e:
        return None

def discover_endpoints(base_url, wordlist):
    """Brute‑force common endpoint names using a wordlist."""
    discovered = []
    for word in wordlist:
        endpoint = urljoin(base_url.rstrip('/') + '/', word.strip())
        resp = safe_request('GET', endpoint)
        if resp and resp.status_code in (200, 401, 403, 405):
            discovered.append(endpoint)
    return discovered

def method_override(endpoint):
    """Test which HTTP methods are accepted by an endpoint."""
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
    allowed = []
    for m in methods:
        resp = safe_request(m, endpoint)
        if resp and resp.status_code != 405:
            allowed.append(m)
    return allowed

def mass_assignment(endpoint, method):
    """Detect mass‑assignment vulnerabilities by sending extra JSON fields."""
    payload = {
        "username": "testuser",
        "email": "test@example.com",
        "admin": True,
        "isAdmin": True,
        "role": "superuser"
    }
    headers = {'Content-Type': 'application/json'}
    resp = safe_request(method, endpoint, json=payload, headers=headers)
    findings = []
    if resp and resp.headers.get('Content-Type', '').startswith('application/json'):
        try:
            data = resp.json()
            for key in ("admin", "isAdmin", "role"):
                if key in data and data[key] in (True, "superuser", "admin"):
                    findings.append(f"Mass assignment reflected for field '{key}'")
        except ValueError:
            pass
    return findings

def run_fuzzer(target, wordlist_path):
    result = {
        "tool": "ForgeAPI-Fuzzer",
        "version": "1.0",
        "target": target,
        "status": "completed",
        "technologies": [],
        "findings": [],
        "results": {}
    }

    # Load wordlist
    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        result["status"] = f"error loading wordlist: {e}"
        return result

    # 1. Endpoint discovery
    endpoints = discover_endpoints(target, words)
    result["results"]["endpoints"] = endpoints

    # 2. Method override per endpoint
    methods_map = {}
    for ep in endpoints:
        methods_map[ep] = method_override(ep)
    result["results"]["methods"] = methods_map

    # 3. Mass assignment checks
    mass_findings = {}
    for ep, methods in methods_map.items():
        for m in methods:
            # Only test methods that accept a body
            if m in ('POST', 'PUT', 'PATCH'):
                findings = mass_assignment(ep, m)
                if findings:
                    mass_findings.setdefault(ep, []).extend(findings)
    result["findings"] = mass_findings

    return result

# ------------------- Self‑test infrastructure ------------------- #

class MockHandler(BaseHTTPRequestHandler):
    def _set_json(self, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_GET(self):
        if self.path == '/public':
            self._set_json()
            self.wfile.write(b'{"message":"public"}')
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/admin':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
            except:
                data = {}
            # Echo back received JSON (simulating mass assignment)
            self._set_json()
            self.wfile.write(json.dumps(data).encode())
        else:
            self.send_error(404)

    def do_PUT(self):
        self.send_error(405)

    def do_DELETE(self):
        self.send_error(405)

    def log_message(self, format, *args):
        pass  # suppress console noise

def start_mock_server(port):
    server = HTTPServer(('127.0.0.1', port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def find_free_port():
    s = socket.socket()
    s.bind(('', 0))
    _, port = s.getsockname()
    s.close()
    return port

def self_test():
    port = find_free_port()
    server = start_mock_server(port)
    target = f'http://127.0.0.1:{port}'
    # Minimal wordlist covering our mock endpoints
    wordlist = ['public', 'admin', 'nonexistent']
    # Write temporary wordlist file
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tf:
        tf.write('\n'.join(wordlist))
        wordlist_path = tf.name
    try:
        result = run_fuzzer(target, wordlist_path)
        print(json.dumps(result, indent=2))
    finally:
        os.unlink(wordlist_path)
        server.shutdown()

def main():
    parser = argparse.ArgumentParser(description="ForgeAPI-Fuzzer – Multi‑function REST API security scanner")
    parser.add_argument("target", nargs='?', help="Base URL of the target API (e.g., https://api.example.com/)")
    parser.add_argument("-w", "--wordlist", default=None, help="Path to endpoint wordlist")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target or not args.wordlist:
        sys.stderr.write("error: target and wordlist are required unless --self-test is used\n")
        sys.exit(1)

    result = run_fuzzer(args.target, args.wordlist)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()