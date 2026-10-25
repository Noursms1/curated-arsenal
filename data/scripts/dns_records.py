# CATEGORY: Recon - DNS Records Tool
import argparse
import json
import sys
import time
import socket

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
except ImportError:
    sys.stderr.write("Missing required library 'dnspython'. Install with pip install dnspython\n")
    sys.exit(1)


TOOL_NAME = "dns_recon_tool"
VERSION = "1.0"


def is_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def safe_resolve(resolver, qname, rdtype):
    try:
        answer = resolver.resolve(qname, rdtype, raise_on_no_answer=False)
        time.sleep(0.5)
        if answer.rrset is None:
            return []
        return [rdata.to_text() for rdata in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        time.sleep(0.5)
        return []
    except Exception:
        time.sleep(0.5)
        return []


def perform_dns_queries(target):
    resolver = dns.resolver.Resolver()
    results = {}
    findings = []

    # A record
    a_records = safe_resolve(resolver, target, "A")
    if a_records:
        results["A"] = a_records
        findings.append("A")
    # AAAA record
    aaaa_records = safe_resolve(resolver, target, "AAAA")
    if aaaa_records:
        results["AAAA"] = aaaa_records
        findings.append("AAAA")
    # MX record
    mx_records = safe_resolve(resolver, target, "MX")
    if mx_records:
        results["MX"] = mx_records
        findings.append("MX")
    # TXT record
    txt_records = safe_resolve(resolver, target, "TXT")
    if txt_records:
        results["TXT"] = txt_records
        findings.append("TXT")
    # NS record
    ns_records = safe_resolve(resolver, target, "NS")
    if ns_records:
        results["NS"] = ns_records
        findings.append("NS")
    # PTR record (reverse DNS) if target is IP
    if is_ip(target):
        try:
            rev_name = dns.reversename.from_address(target)
            ptr_records = safe_resolve(resolver, rev_name, "PTR")
            if ptr_records:
                results["PTR"] = ptr_records
                findings.append("PTR")
        except Exception:
            pass

    return findings, results


def build_output(target, status, findings, results):
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))


def run_self_test():
    test_target = "example.com"
    findings, results = perform_dns_queries(test_target)
    status = "success" if findings else "error"
    build_output(test_target, status, findings, results)


def main():
    parser = argparse.ArgumentParser(description="DNS Reconnaissance Tool")
    parser.add_argument("target", nargs="?", help="Domain name or IP address to query")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    if not args.target:
        sys.stderr.write("Error: target argument is required\n")
        parser.print_help()
        sys.exit(1)

    findings, results = perform_dns_queries(args.target)
    status = "success" if findings else "error"
    build_output(args.target, status, findings, results)


if __name__ == "__main__":
    main()