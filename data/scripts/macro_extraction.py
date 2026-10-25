# CATEGORY: Malware
import argparse
import hashlib
import json
import os
import sys
import time
import zipfile
import tempfile
import logging
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
except ImportError:
    VBA_Parser = None

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
LOGGER = logging.getLogger(__name__)

TOOL_NAME = "MacroExtractor"
VERSION = "1.0.0"

def compute_sha256(file_path):
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        LOGGER.error(f"Hash error for {file_path}: {e}")
        return None

def extract_macros(file_path):
    """Extract VBA macros from Office files using oletools if available."""
    findings = []
    if not VBA_Parser:
        LOGGER.warning("oletools not available, falling back to zip-based extraction for OpenXML files.")
        return fallback_extract(file_path, findings)

    try:
        parser = VBA_Parser(file_path)
        if not parser.detect_vba_macros():
            return findings  # No macros found
        for (filename, stream_path, vba_filename, vba_code) in parser.extract_all_macros():
            findings.append({
                "filename": filename,
                "stream_path": stream_path,
                "vba_filename": vba_filename,
                "code": vba_code
            })
        parser.close()
    except Exception as e:
        LOGGER.error(f"Macro extraction error for {file_path}: {e}")
    return findings

def fallback_extract(file_path, findings):
    """Very basic macro extraction for OpenXML (docx, xlsm, pptm) by searching for VBA code in zip."""
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            for name in z.namelist():
                if name.lower().endswith('.bin') and 'vba' in name.lower():
                    data = z.read(name).decode(errors='ignore')
                    findings.append({
                        "filename": os.path.basename(file_path),
                        "stream_path": name,
                        "vba_filename": name,
                        "code": data
                    })
    except Exception as e:
        LOGGER.error(f"Fallback extraction failed for {file_path}: {e}")
    return findings

def vt_lookup(sha256_hash, api_key):
    """Query VirusTotal for a file hash."""
    if not requests:
        LOGGER.warning("requests library not available, skipping VT lookup.")
        return None
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        time.sleep(0.5)  # rate limiting
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats
        else:
            LOGGER.info(f"VT lookup returned {resp.status_code} for hash {sha256_hash}")
            return None
    except Exception as e:
        LOGGER.error(f"VT lookup error for hash {sha256_hash}: {e}")
        return None

def process_file(file_path, vt_key=None):
    """Process a single file: hash, macro extraction, optional VT."""
    result = {
        "file": str(file_path),
        "sha256": None,
        "macros": [],
        "vt_stats": None
    }
    sha256 = compute_sha256(file_path)
    result["sha256"] = sha256
    macros = extract_macros(file_path)
    result["macros"] = macros
    if vt_key and sha256:
        vt = vt_lookup(sha256, vt_key)
        result["vt_stats"] = vt
    return result

def scan_path(target_path, vt_key=None):
    """Recursively scan files under target_path."""
    findings = []
    target = Path(target_path)
    if target.is_file():
        findings.append(process_file(target, vt_key))
    else:
        for root, _, files in os.walk(target):
            for f in files:
                fp = Path(root) / f
                findings.append(process_file(fp, vt_key))
    return findings

def self_test():
    """Run internal self‑test without external files."""
    LOGGER.info("Starting self‑test...")
    # Create a temporary minimal OpenXML file with a dummy macro binary
    with tempfile.TemporaryDirectory() as td:
        doc_path = Path(td) / "test.docm"
        with zipfile.ZipFile(doc_path, 'w') as z:
            # Add a dummy vbaProject.bin
            dummy_macro = b"Attribute VB_Name = \"Module1\"\nSub AutoOpen()\nMsgBox \"Hello\"\nEnd Sub"
            z.writestr("word/vbaProject.bin", dummy_macro)
        # Process the temporary file
        result = process_file(doc_path)
        # Build JSON output
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": str(doc_path),
            "status": "self-test",
            "findings": len(result["macros"]),
            "results": result
        }
        print(json.dumps(output, indent=2))
    LOGGER.info("Self‑test completed.")

def main():
    parser = argparse.ArgumentParser(description="Macro extraction tool")
    parser.add_argument("target", nargs="?", help="File or directory to scan")
    parser.add_argument("--vt-key", help="VirusTotal API key for hash lookup")
    parser.add_argument("--self-test", action="store_true", help="Run self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        LOGGER.error("Target path is required unless --self-test is used.")
        sys.exit(1)

    findings = scan_path(args.target, vt_key=args.vt_key)
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": "completed",
        "findings": sum(len(r["macros"]) for r in findings),
        "results": findings
    }
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()