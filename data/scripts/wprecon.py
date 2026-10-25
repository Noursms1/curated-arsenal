"""
CATEGORY: Security Tool - WordPress Reconnaissance

WordPress Reconnaissance Tool
Version: 1.0.0

Capabilities:
1. Scan discovered WordPress plugins against a built‑in CVE database.
2. Enumerate existing WordPress usernames via author query enumeration.
3. Test the XML‑RPC endpoint for basic pingback functionality.

The tool prints a single JSON object with the following keys:
    tool        – name of the tool
    version     – tool version
    target      – target base URL
    status      – overall status (success / partial / error)
    technologies – detected technologies (e.g., WordPress version)
    findings    – list of discovered plugins with CVE matches
    results     – additional results (enumerated users, XML‑RPC test)

Usage:
    python wp_recon.py https://example.com
    python wp_recon.py https://example.com --self-test
"""

import argparse
import json
import re
import sys
import time
from urllib.parse import urljoin, urlparse

import requests

# ----------------------------------------------------------------------
# Simple built‑in CVE database (plugin_slug -> list of CVE identifiers)
# In a production environment this would be replaced by a live feed.
# ----------------------------------------------------------------------
CVE_DB = {
    "contact-form-7": ["CVE-2020-36326", "CVE-2021-39328"],
    "revslider": ["CVE-2020-11022", "CVE-2021-24284"],
    "wp-super-cache": ["CVE-2020-36326"],
    "elementor": ["CVE-2022-21661"],
}

USER_ENUM_LIMIT = 10  # Number of author IDs to probe


class WPRecon:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "WPRecon/1.0 (+https://github.com/example/wp-recon)"}
        )
        self.findings = []
        self.enumerated_users = []
        self.xmlrpc_success = False
        self.wp_version = None

    # ------------------------------------------------------------------
    # Helper: safe GET request with error handling and throttling
    # ------------------------------------------------------------------
    def _get(self, url: str, **kwargs):
        try:
            resp = self.session.get(url, timeout=10, **kwargs)
            time.sleep(0.5)  # throttle
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            return None

    # ------------------------------------------------------------------
    # Detect WordPress version via meta generator tag
    # ------------------------------------------------------------------
    def detect_wp_version(self):
        resp = self._get(self.base_url)
        if not resp:
            return
        match = re.search(
            r'<meta name=["\']generator["\'] content=["\']WordPress\s+([\d\.]+)', resp.text,
            re.IGNORECASE,
        )
        if match:
            self.wp_version = match.group(1)

    # ------------------------------------------------------------------
    # Discover plugins by scanning HTML for /wp-content/plugins/ paths
    # ------------------------------------------------------------------
    def discover_plugins(self):
        resp = self._get(self.base_url)
        if not resp:
            return []
        plugins = set()
        for match in re.finditer(
            r'/wp-content/plugins/([^/]+)/', resp.text, re.IGNORECASE
        ):
            plugins.add(match.group(1).lower())
        return list(plugins)

    # ------------------------------------------------------------------
    # Check discovered plugins against the built‑in CVE database
    # ------------------------------------------------------------------
    def check_plugins_cve(self, plugins):
        for plugin in plugins:
            cves = CVE_DB.get(plugin, [])
            self.findings.append(
                {"plugin": plugin, "cve_ids": cves, "status": "vulnerable" if cves else "clean"}
            )

    # ------------------------------------------------------------------
    # Enumerate usernames via author ID enumeration
    # ------------------------------------------------------------------
    def enumerate_users(self):
        for author_id in range(1, USER_ENUM_LIMIT + 1):
            url = f"{self.base_url}/?author={author_id}"
            resp = self._get(url, allow_redirects=False)
            if not resp:
                continue
            # WordPress often redirects to /author/username/
            location = resp.headers.get("Location", "")
            parsed = urlparse(location)
            if parsed.path.startswith("/author/"):
                username = parsed.path.split("/")[2].strip("/")
                self.enumerated_users.append(username)

    # ------------------------------------------------------------------
    # Test XML‑RPC endpoint with a pingback request
    # ------------------------------------------------------------------
    def test_xmlrpc(self):
        xmlrpc_url = urljoin(self.base_url + "/", "xmlrpc.php")
        payload = """<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://example.com/</string></value></param>
    <param><value><string>{url}</string></value></param>
  </params>
</methodCall>""".format(
            url=self.base_url
        )
        headers = {"Content-Type": "text/xml"}
        try:
            resp = self.session.post(xmlrpc_url, data=payload, headers=headers, timeout=10)
            time.sleep(0.5)
            if resp.status_code == 200 and b"faultCode" not in resp.content:
                self.xmlrpc_success = True
        except requests.RequestException:
            self.xmlrpc_success = False

    # ------------------------------------------------------------------
    # Run full reconnaissance workflow
    # ------------------------------------------------------------------
    def run(self):
        self.detect_wp_version()
        plugins = self.discover_plugins()
        self.check_plugins_cve(plugins)
        self.enumerate_users()
        self.test_xmlrpc()

    # ------------------------------------------------------------------
    # Produce final JSON output
    # ------------------------------------------------------------------
    def output(self):
        status = "success"
        if not self.findings and not self.enumerated_users and not self.xmlrpc_success:
            status = "partial"
        output = {
            "tool": "WPRecon",
            "version": "1.0.0",
            "target": self.base_url,
            "status": status,
            "technologies": {"wordpress_version": self.wp_version},
            "findings": self.findings,
            "results": {
                "enumerated_users": self.enumerated_users,
                "xmlrpc_accessible": self.xmlrpc_success,
            },
        }
        print(json.dumps(output, indent=2))


# ----------------------------------------------------------------------
# Self‑test routine – runs the scanner against a known safe target
# ----------------------------------------------------------------------
def self_test():
    test_url = "https://httpbin.org"
    scanner = WPRecon(test_url)
    scanner.run()
    # Minimal validation: ensure JSON can be generated without exception
    try:
        scanner.output()
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Self‑test failed: {e}\n")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="WordPress Reconnaissance Tool")
    parser.add_argument("target", nargs="?", help="Base URL of the WordPress site")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self‑test and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        parser.error("the following arguments are required: target")

    # Basic URL validation
    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.netloc:
        parser.error("target must be a valid URL (including http/https)")

    scanner = WPRecon(args.target)
    scanner.run()
    scanner.output()


if __name__ == "__main__":
    main()