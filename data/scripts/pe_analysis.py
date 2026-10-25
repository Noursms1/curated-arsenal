# CATEGORY: Malware
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import pefile

try:
    import requests
except ImportError:
    requests = None  # Network features will be disabled if requests is unavailable


TOOL_NAME = "PEAnalyzer"
VERSION = "1.0.0"


def compute_hashes(file_path: Path):
    """Return MD5 and SHA256 hashes of the file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha256.update(chunk)
    except Exception as e:
        raise RuntimeError(f"Hash computation failed: {e}")
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def extract_pe_info(file_path: Path):
    """Extract basic PE header information, sections and imports."""
    try:
        pe = pefile.PE(str(file_path), fast_load=False)
    except pefile.PEFormatError as e:
        raise RuntimeError(f"PE parsing failed: {e}")

    header = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
    }

    sections = [
        {
            "name": sec.Name.decode(errors="ignore").strip("\x00"),
            "virtual_address": hex(sec.VirtualAddress),
            "virtual_size": sec.Misc_VirtualSize,
            "raw_size": sec.SizeOfRawData,
        }
        for sec in pe.sections
    ]

    imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = [imp.name.decode(errors="ignore") if imp.name else f"ord_{imp.ordinal}" for imp in entry.imports]
            imports[dll_name] = funcs

    return {"header": header, "sections": sections, "imports": imports}


def query_virustotal(sha256: str, api_key: str):
    """Query VirusTotal for a given SHA256 hash."""
    if not requests:
        return {"error": "requests library not available"}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        time.sleep(0.5)
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"vt_stats": stats}
    except Exception as e:
        return {"vt_error": str(e)}


def analyze_file(file_path: Path, vt_api_key: str = None):
    findings = []
    results = {}

    # Capability 1: Compute hashes
    try:
        hashes = compute_hashes(file_path)
        results["hashes"] = hashes
    except Exception as e:
        findings.append(str(e))
        return "error", findings, results

    # Capability 2: Extract PE info
    try:
        pe_info = extract_pe_info(file_path)
        results["pe_info"] = pe_info
    except Exception as e:
        findings.append(str(e))
        return "error", findings, results

    # Capability 3: VirusTotal lookup (optional network call)
    if vt_api_key:
        vt_result = query_virustotal(hashes["sha256"], vt_api_key)
        results["virustotal"] = vt_result
        if "vt_error" in vt_result:
            findings.append(f"VT lookup failed: {vt_result['vt_error']}")
        else:
            stats = vt_result.get("vt_stats", {})
            if stats.get("malicious", 0) > 0:
                findings.append("File flagged as malicious by VirusTotal")
    else:
        findings.append("VT API key not provided; skipping online reputation check")

    status = "success" if not findings else "warning"
    return status, findings, results


def self_test():
    """Run a minimal self‑test without external files."""
    dummy_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00PE\x00\x00"
    dummy_path = Path("dummy_pe.bin")
    try:
        dummy_path.write_bytes(dummy_content)
        status, findings, results = analyze_file(dummy_path)
    finally:
        if dummy_path.exists():
            dummy_path.unlink()
    test_output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": status,
        "findings": findings,
        "results": results,
    }
    print(json.dumps(test_output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="PE analysis tool")
    parser.add_argument("target", nargs="?", help="Path to PE file")
    parser.add_argument("--vt-api-key", help="VirusTotal API key for online lookup")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        sys.stderr.write("Error: target file required\n")
        sys.exit(1)

    target_path = Path(args.target)
    if not target_path.is_file():
        sys.stderr.write(f"Error: file not found – {target_path}\n")
        sys.exit(1)

    status, findings, results = analyze_file(target_path, vt_api_key=args.vt_api_key)

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": str(target_path),
        "status": status,
        "findings": findings,
        "results": results,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()