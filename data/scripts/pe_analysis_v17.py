# CATEGORY: Malware
# PREMORTEM:
# failure_mode: Missing required third‑party library (pefile) causing ImportError at runtime
# failure_mode: Unchecked large PE files leading to excessive memory consumption or long processing time
# failure_mode: Network request to external reputation service fails or exceeds rate limits, causing hangs or crashes
# early_warning: ImportError on pefile import, process memory usage > 200 MB, consecutive request exceptions > 3

import argparse
import hashlib
import json
import os
import sys
import time
import tempfile
import threading

# Optional network reputation lookup (VirusTotal)
import requests

# Attempt to import pefile, provide clear error if unavailable
try:
    import pefile
except ImportError as e:
    sys.stderr.write("Critical dependency missing: pefile library is required.\n")
    sys.exit(1)

TOOL_NAME = "PEAnalyzer"
VERSION = "1.0.0"

def compute_hash(file_path):
    """Compute SHA256 hash of the file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
    except Exception as e:
        return None, str(e)
    return sha256.hexdigest(), None

def extract_headers(pe):
    """Extract a subset of PE header information."""
    hdr = pe.FILE_HEADER
    opt = pe.OPTIONAL_HEADER
    return {
        "Machine": hex(hdr.Machine),
        "NumberOfSections": hdr.NumberOfSections,
        "TimeDateStamp": hdr.TimeDateStamp,
        "EntryPoint": hex(opt.AddressOfEntryPoint),
        "ImageBase": hex(opt.ImageBase),
        "Subsystem": hex(opt.Subsystem),
        "DLLCharacteristics": hex(opt.DLLCharacteristics),
    }

def list_imports(pe):
    """List imported DLLs and their functions."""
    imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = [imp.name.decode(errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}" for imp in entry.imports]
            imports[dll_name] = funcs
    return imports

def query_virustotal(hash_value, api_key):
    """Query VirusTotal for a file hash reputation."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        time.sleep(0.5)  # rate‑limit courtesy
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
            }, None
        elif response.status_code == 404:
            return {"error": "Hash not found in VirusTotal"}, None
        else:
            return None, f"Unexpected status {response.status_code}"
    except Exception as exc:
        return None, str(exc)

def analyze_pe(file_path):
    findings = {}
    results = {}
    status = "success"

    # Compute hash
    file_hash, err = compute_hash(file_path)
    if err:
        status = "error"
        findings["hash_error"] = err
        return status, findings, results

    findings["sha256"] = file_hash

    # Load PE
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
        ])
    except Exception as e:
        status = "error"
        findings["pe_load_error"] = str(e)
        return status, findings, results

    # Header extraction
    try:
        results["headers"] = extract_headers(pe)
    except Exception as e:
        findings["header_error"] = str(e)

    # Imports
    try:
        results["imports"] = list_imports(pe)
    except Exception as e:
        findings["import_error"] = str(e)

    # Optional: VirusTotal reputation
    api_key = os.getenv("VT_API_KEY")
    if api_key:
        vt_result, vt_err = query_virustotal(file_hash, api_key)
        if vt_err:
            findings["virustotal_error"] = vt_err
        else:
            results["virustotal"] = vt_result

    return status, findings, results

def self_test():
    """Run a minimal self‑test using an in‑memory tiny PE stub."""
    # Tiny PE stub (MZ header + minimal PE header, not executable)
    tiny_pe = bytes.fromhex(
        "4d5a90000300000004000000ffff0000b8000000"
        "0000000040000000"
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(tiny_pe)
        tmp_path = tmp.name

    try:
        status, findings, results = analyze_pe(tmp_path)
        os.remove(tmp_path)
        test_pass = status == "success" and "sha256" in findings
    except Exception:
        test_pass = False

    return {"self_test_passed": test_pass, "status": status, "findings": findings, "results": results}

def main():
    parser = argparse.ArgumentParser(description="PE analysis tool")
    parser.add_argument("target", nargs="?", help="Path to PE file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target if args.target else None,
        "status": "unknown",
        "findings": {},
        "results": {}
    }

    if args.self_test:
        test_res = self_test()
        output.update(test_res)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(0)

    if not args.target:
        parser.error("target file path is required unless --self-test is used")

    if not os.path.isfile(args.target):
        output["status"] = "error"
        output["findings"]["file_error"] = "File does not exist"
        print(json.dumps(output, ensure_ascii=False, indent=2))
        sys.exit(1)

    status, findings, results = analyze_pe(args.target)
    output["status"] = status
    output["findings"] = findings
    output["results"] = results

    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    # Guard against unexpected exceptions crashing the tool
    try:
        main()
    except Exception as e:
        err_output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "fatal_error",
            "findings": {"exception": str(e)},
            "results": {}
        }
        print(json.dumps(err_output, ensure_ascii=False, indent=2))
        sys.exit(1)