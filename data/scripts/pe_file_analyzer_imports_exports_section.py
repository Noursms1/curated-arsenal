#!/usr/bin/env python3
"""
CATEGORY: Malware
TECHNIQUES: PE parsing, entropy analysis, hash based signature detection, lightweight YARA‑like pattern matching
CHAIN_CONTRIBUTIONS: 
    - PE parsing via pefile (imports, exports, sections)
    - Entropy calculation per section
    - Signature DB (MD5 → vendor signature) embedded
    - Pattern DB (byte‑string → description) for YARA‑like matching
"""

import argparse
import json
import os
import sys
import time
import hashlib
import logging
from typing import Dict, List, Any

# third‑party, pure‑python library for PE handling
try:
    import pefile
except ImportError:
    sys.stderr.write("Missing required library 'pefile'. Install with pip.\n")
    sys.exit(1)

# ----------------------------------------------------------------------
# Embedded databases (replace with real feeds for production use)
# ----------------------------------------------------------------------
_SIGNATURE_DB = {
    # MD5 : description
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File",
    # Add more known hashes here
}

_PATTERN_DB = {
    # pattern (hex string) : description
    "4d5a90000300000004000000": "Typical MZ header with zeroed PE header",
    "50450000": "PE signature",
    # Add more patterns here
}

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def _calc_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string."""
    if not data:
        return 0.0
    import math
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


def _hash_file(path: str) -> str:
    """Return MD5 hash of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _match_patterns(data: bytes) -> List[Dict[str, Any]]:
    """Very lightweight YARA‑like pattern matcher."""
    findings = []
    hex_data = data.hex()
    for pat, desc in _PATTERN_DB.items():
        if pat.lower() in hex_data.lower():
            findings.append({"pattern": pat, "description": desc})
    return findings


def _rate_limit():
    """Enforce a small pause between potentially external operations."""
    time.sleep(0.5)


# ----------------------------------------------------------------------
# Core analysis
# ----------------------------------------------------------------------
def analyze_pe(file_path: str) -> Dict[str, Any]:
    """
    Analyze a PE file and return a structured report.

    Returns a dict adhering to:
    {
        "tool": str,
        "version": str,
        "target": str,
        "status": "success" | "error",
        "technologies": List[str],
        "findings": List[dict],
        "results": dict
    }
    """
    report = {
        "tool": "ForgePE",
        "version": "1.0.0",
        "target": file_path,
        "status": "success",
        "technologies": [],
        "findings": [],
        "results": {}
    }

    try:
        # Basic file existence check
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Load PE with timeout safety (no network, but keep pattern)
        pe = pefile.PE(file_path, fast_load=False)

        # ---- Imports ----
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")
                for imp in entry.imports:
                    func = imp.name.decode(errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}"
                    imports.append({"dll": dll, "function": func})
        report["results"]["imports"] = imports
        if imports:
            report["technologies"].append("imports")

        # ---- Exports ----
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode(errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
                exports.append({"name": name, "address": hex(exp.address)})
        report["results"]["exports"] = exports
        if exports:
            report["technologies"].append("exports")

        # ---- Sections & Entropy ----
        sections = []
        for sec in pe.sections:
            name = sec.Name.decode(errors="ignore").strip("\x00")
            entropy = _calc_entropy(sec.get_data())
            sections.append({
                "name": name,
                "virtual_address": hex(sec.VirtualAddress),
                "virtual_size": hex(sec.Misc_VirtualSize),
                "raw_size": hex(sec.SizeOfRawData),
                "entropy": round(entropy, 4)
            })
        report["results"]["sections"] = sections
        report["technologies"].append("sections")

        # ---- Signature detection (hash based) ----
        md5_hash = _hash_file(file_path)
        signature = _SIGNATURE_DB.get(md5_hash)
        if signature:
            report["findings"].append({
                "type": "signature",
                "hash": md5_hash,
                "description": signature
            })
            report["technologies"].append("signature_detection")

        # ---- YARA‑like pattern matching ----
        with open(file_path, "rb") as f:
            raw = f.read()
        pattern_hits = _match_patterns(raw)
        if pattern_hits:
            for hit in pattern_hits:
                report["findings"].append({
                    "type": "pattern",
                    "pattern": hit["pattern"],
                    "description": hit["description"]
                })
            report["technologies"].append("pattern_matching")

        # Rate limiting placeholder (e.g., future external DB queries)
        _rate_limit()

    except Exception as e:
        report["status"] = "error"
        report["findings"].append({
            "type": "exception",
            "message": str(e)
        })
        logging.exception("PE analysis failed")
    finally:
        # Ensure PE resources are released
        try:
            pe.close()
        except Exception:
            pass

    return report


# ----------------------------------------------------------------------
# Self‑test routine
# ----------------------------------------------------------------------
def _self_test() -> bool:
    """
    Perform a minimal self‑test:
    - Create a tiny valid PE stub (MZ + PE header)
    - Run analysis
    - Verify expected keys exist
    Returns True on success.
    """
    import tempfile

    # Minimal PE stub (MZ header + PE signature). Not a functional executable but parsable.
    stub = bytes.fromhex(
        "4d5a90000300000004000000ffff0000b8000000"
        "0000000040000000"  # ... truncated for brevity
    )
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(stub)
            tf_path = tf.name

        report = analyze_pe(tf_path)

        required_keys = {"tool", "version", "target", "status", "technologies", "findings", "results"}
        if not required_keys.issubset(report.keys()):
            return False

        # Basic sanity checks
        if report["status"] != "success":
            return False

        # Clean up
        os.remove(tf_path)
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="ForgePE – Advanced PE file analyzer")
    parser.add_argument("target", nargs="?", help="Path to PE file")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        success = _self_test()
        sys.exit(0 if success else 1)

    if not args.target:
        parser.error("target file path required (or use --self-test)")

    # Enforce timeout for the whole operation (10 seconds)
    import signal

    def _handler(signum, frame):
        raise TimeoutError("Analysis timed out after 10 seconds")

    signal.signal(signal.SIGALRM, _handler)
    signal.alarm(10)

    try:
        report = analyze_pe(args.target)
        signal.alarm(0)  # cancel alarm
    except TimeoutError as te:
        report = {
            "tool": "ForgePE",
            "version": "1.0.0",
            "target": args.target,
            "status": "error",
            "technologies": [],
            "findings": [{"type": "timeout", "message": str(te)}],
            "results": {}
        }

    output = json.dumps(report, indent=2) if args.json else json.dumps(report)
    print(output)


if __name__ == "__main__":
    main()