# CATEGORY: Malware
import argparse
import hashlib
import json
import sys
import time
import tempfile
from pathlib import Path

try:
    import requests
except ImportError:
    print(json.dumps({
        "tool": "macro_extractor",
        "version": "1.0",
        "target": "",
        "status": "error",
        "findings": ["Missing required library: requests"],
        "results": {}
    }))
    sys.exit(1)

try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML
except ImportError:
    print(json.dumps({
        "tool": "macro_extractor",
        "version": "1.0",
        "target": "",
        "status": "error",
        "findings": ["Missing required library: oletools"],
        "results": {}
    }))
    sys.exit(1)


TOOL_NAME = "macro_extractor"
VERSION = "1.0"
SLEEP_INTERVAL = 0.5
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/files"


def compute_sha256(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
    except Exception as e:
        return ""
    return sha256.hexdigest()


def extract_macros(file_path: Path):
    """Extract VBA macros using oletools."""
    findings = []
    macros = []
    try:
        parser = VBA_Parser(str(file_path))
    except Exception as e:
        findings.append(f"Failed to open file with VBA_Parser: {e}")
        return findings, macros

    if not parser.detect_vba_macros():
        findings.append("No VBA macros detected.")
        parser.close()
        return findings, macros

    try:
        for (filename, stream_path, vba_filename, vba_code) in parser.extract_all_macros():
            macros.append({
                "filename": filename,
                "stream_path": stream_path,
                "vba_filename": vba_filename,
                "code": vba_code
            })
        findings.append(f"Extracted {len(macros)} macro(s).")
    except Exception as e:
        findings.append(f"Error during macro extraction: {e}")
    finally:
        parser.close()
    return findings, macros


def analyze_macro_code(code: str):
    """Simple static analysis for suspicious patterns."""
    suspicious = []
    indicators = [
        "AutoOpen", "AutoExec", "Shell", "CreateObject", "WScript.Shell",
        "Environ", "URLDownloadToFile", "FileSystemObject", "Execute", "Eval"
    ]
    for indicator in indicators:
        if indicator.lower() in code.lower():
            suspicious.append(indicator)
    return suspicious


def query_virustotal(file_hash: str):
    """Query VirusTotal for a file hash (if API key provided via env)."""
    api_key = ""  # Insert your VirusTotal API key here or read from env
    if not api_key:
        return {"error": "VirusTotal API key not configured."}
    headers = {"x-apikey": api_key}
    url = f"{VIRUSTOTAL_API}/{file_hash}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        time.sleep(SLEEP_INTERVAL)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"VT returned status {response.status_code}"}
    except Exception as e:
        return {"error": f"Exception during VT query: {e}"}


def build_output(target: str, status: str, findings, results):
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results
    }
    print(json.dumps(output, indent=2))


def process_file(file_path: Path):
    findings = []
    results = {}

    if not file_path.is_file():
        findings.append("Target path is not a file.")
        build_output(str(file_path), "error", findings, results)
        return

    sha256 = compute_sha256(file_path)
    if not sha256:
        findings.append("Failed to compute SHA256.")
        build_output(str(file_path), "error", findings, results)
        return
    results["sha256"] = sha256

    macro_findings, macros = extract_macros(file_path)
    findings.extend(macro_findings)
    results["macros"] = macros

    suspicious_indicators = []
    for macro in macros:
        suspicious = analyze_macro_code(macro["code"])
        if suspicious:
            suspicious_indicators.append({
                "vba_filename": macro["vba_filename"],
                "indicators": suspicious
            })
    if suspicious_indicators:
        findings.append(f"Suspicious indicators found in {len(suspicious_indicators)} macro(s).")
        results["suspicious"] = suspicious_indicators

    vt_result = query_virustotal(sha256)
    results["virustotal"] = vt_result

    build_output(str(file_path), "success", findings, results)


def self_test():
    """Run a simple self‑test using a temporary Office‑like file with a macro."""
    sample_vba = """
    Sub AutoOpen()
        Dim x As Object
        Set x = CreateObject("WScript.Shell")
        x.Run "calc.exe"
    End Sub
    """
    # Create a minimal OLE file using oletools helper (not a real Office file but sufficient for parser)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
        tmp_path = Path(tmp.name)
        # Write a dummy OLE header + macro stream (very simplified)
        tmp.write(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")  # OLE magic
        # The macro extraction will likely fail, but we can still test hash and flow
    try:
        process_file(tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Macro extraction and analysis tool")
    parser.add_argument("target", nargs="?", help="Path to the Office document")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        build_output("", "error", ["No target file specified."], {})
        return

    process_file(Path(args.target))


if __name__ == "__main__":
    main()