# CATEGORY: Crypto - TLS Analysis Tool
import argparse
import json
import socket
import ssl
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

TOOL_NAME = "tls_analyzer"
VERSION = "1.0.0"
SLEEP_INTERVAL = 0.5

TLS_VERSIONS = {
    "TLSv1.0": ssl.TLSVersion.SSLv3,  # legacy fallback, will be rejected by modern servers
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

def sleep():
    time.sleep(SLEEP_INTERVAL)

def get_certificate(host, port):
    cert_info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = ssl.DER_cert_to_PEM_cert(der_cert)
                x509 = ssl._ssl._test_decode_cert(cert)  # internal helper for parsing
                cert_info = {
                    "subject": dict(x509.get("subject", [])),
                    "issuer": dict(x509.get("issuer", [])),
                    "notBefore": x509.get("notBefore"),
                    "notAfter": x509.get("notAfter"),
                    "serialNumber": x509.get("serialNumber"),
                    "version": x509.get("version"),
                }
    except Exception as e:
        cert_info = {"error": str(e)}
    finally:
        sleep()
    return cert_info

def check_tls_versions(host, port):
    supported = []
    for name, version in TLS_VERSIONS.items():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    supported.append(name)
        except Exception:
            pass
        finally:
            sleep()
    return supported

def get_cipher_suites(host, port):
    ciphers = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    ciphers.append(cipher[0])
    except Exception as e:
        ciphers.append(f"error: {e}")
    finally:
        sleep()
    return ciphers

def http_head_over_tls(host, port):
    url = f"https://{host}:{port}"
    result = {}
    try:
        req = Request(url, method="HEAD")
        with urlopen(req, timeout=5) as resp:
            result = {
                "status_code": resp.getcode(),
                "headers": dict(resp.getheaders()),
            }
    except HTTPError as e:
        result = {"error": f"HTTP error {e.code}"}
    except URLError as e:
        result = {"error": str(e.reason)}
    except Exception as e:
        result = {"error": str(e)}
    finally:
        sleep()
    return result

def analyze_target(target):
    if ":" in target:
        host, port_str = target.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443
    else:
        host = target
        port = 443

    findings = []
    results = {}

    cert = get_certificate(host, port)
    results["certificate"] = cert
    if "error" in cert:
        findings.append("Failed to retrieve certificate.")
    else:
        findings.append("Certificate retrieved successfully.")

    versions = check_tls_versions(host, port)
    results["supported_tls_versions"] = versions
    if versions:
        findings.append(f"Supported TLS versions: {', '.join(versions)}")
    else:
        findings.append("No TLS versions succeeded.")

    ciphers = get_cipher_suites(host, port)
    results["cipher_suites"] = ciphers
    if any("error" in c for c in ciphers):
        findings.append("Cipher suite enumeration encountered errors.")
    else:
        findings.append(f"Cipher suite: {', '.join(ciphers)}")

    http_result = http_head_over_tls(host, port)
    results["http_head"] = http_result
    if "error" in http_result:
        findings.append("HTTP HEAD request failed.")
    else:
        findings.append("HTTP HEAD request succeeded.")

    status = "success" if not any("error" in v for v in [cert, http_result]) else "partial_failure"

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }
    return output

def self_test():
    test_target = "www.google.com:443"
    result = analyze_target(test_target)
    print(json.dumps(result, indent=2))

def main():
    parser = argparse.ArgumentParser(description="TLS analysis utility")
    parser.add_argument("target", nargs="?", help="Target host[:port] to analyze")
    parser.add_argument("--self-test", action="store_true", help="Run self‑test against a known endpoint")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        sys.stderr.write("Error: target is required unless --self-test is used.\n")
        sys.exit(1)

    result = analyze_target(args.target)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()