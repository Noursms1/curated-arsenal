# CATEGORY: Malware - PE Analysis Tool
import argparse
import hashlib
import json
import os
import sys
import time
import traceback

import pefile

try:
    import requests
except ImportError:
    requests = None  # Network capabilities will be disabled if requests is unavailable


TOOL_NAME = "PEAnalyzer"
VERSION = "1.0.0"
VT_API_URL = "https://www.virustotal.com/api/v3/files/{}"
VT_API_KEY_ENV = "VT_API_KEY"


def compute_hashes(filepath):
    hashes = {"md5": None, "sha1": None, "sha256": None}
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            hashes["md5"] = hashlib.md5(data).hexdigest()
            hashes["sha1"] = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes["error"] = str(e)
    return hashes


def extract_imports(filepath):
    imports = []
    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore")
                functions = [imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                             for imp in entry.imports]
                imports.append({"dll": dll_name, "functions": functions})
    except pefile.PEFormatError:
        imports.append({"error": "Not a valid PE file"})
    except Exception as e:
        imports.append({"error": str(e)})
    return imports


def extract_sections(filepath):
    sections = []
    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories()
        for sec in pe.sections:
            name = sec.Name.decode(errors="ignore").strip("\x00")
            entropy = sec.get_entropy()
            sections.append({
                "name": name,
                "virtual_address": hex(sec.VirtualAddress),
                "size": sec.SizeOfRawData,
                "entropy": round(entropy, 3)
            })
    except pefile.PEFormatError:
        sections.append({"error": "Not a valid PE file"})
    except Exception as e:
        sections.append({"error": str(e)})
    return sections


def query_virustotal(sha256):
    if not requests:
        return {"error": "requests library not available"}
    api_key = os.getenv(VT_API_KEY_ENV)
    if not api_key:
        return {"error": f"Environment variable {VT_API_KEY_ENV} not set"}
    headers = {"x-apikey": api_key}
    url = VT_API_URL.format(sha256)
    time.sleep(0.5)  # rate‑limit compliance
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        return {
            "malicious": attributes.get("malicious_votes", 0),
            "harmless": attributes.get("harmless_votes", 0),
            "undetected": attributes.get("undetected_votes", 0),
            "total": attributes.get("total_votes", 0)
        }
    except Exception as e:
        return {"error": str(e)}


def analyze_pe(filepath):
    result = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": filepath,
        "status": "success",
        "findings": [],
        "results": {}
    }

    if not os.path.isfile(filepath):
        result["status"] = "error"
        result["findings"].append(f"File not found: {filepath}")
        return result

    hashes = compute_hashes(filepath)
    result["results"]["hashes"] = hashes
    if "error" in hashes:
        result["findings"].append("Failed to compute hashes")
    else:
        result["findings"].append("Hashes computed")

    imports = extract_imports(filepath)
    result["results"]["imports"] = imports
    if any("error" in imp for imp in imports):
        result["findings"].append("Import extraction failed or not a PE")
    else:
        result["findings"].append(f"Found {len(imports)} imported DLL(s)")

    sections = extract_sections(filepath)
    result["results"]["sections"] = sections
    if any("error" in sec for sec in sections):
        result["findings"].append("Section extraction failed or not a PE")
    else:
        result["findings"].append(f"Found {len(sections)} section(s)")

    # Optional VirusTotal lookup
    sha256 = hashes.get("sha256")
    if sha256 and not hashes.get("error"):
        vt_report = query_virustotal(sha256)
        result["results"]["virustotal"] = vt_report
        if vt_report.get("error"):
            result["findings"].append("VirusTotal lookup failed")
        else:
            result["findings"].append("VirusTotal report retrieved")
    else:
        result["results"]["virustotal"] = {"error": "SHA256 unavailable"}

    return result


def self_test():
    test_file = __file__  # use the script itself as a non‑PE test case
    print(json.dumps({
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": test_file,
        "status": "self-test",
        "findings": ["Running self‑test on script file (expected non‑PE)"],
        "results": analyze_pe(test_file)["results"]
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(description="PE analysis utility")
    parser.add_argument("target", nargs="?", help="Path to PE file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": ["No target file specified"],
            "results": {}
        }, indent=2))
        return

    try:
        output = analyze_pe(args.target)
    except Exception as exc:
        output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": args.target,
            "status": "error",
            "findings": [f"Unhandled exception: {str(exc)}", traceback.format_exc()],
            "results": {}
        }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()