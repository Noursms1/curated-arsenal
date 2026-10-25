# CATEGORY: Cloud - Azure Blob Storage Tool
import argparse
import json
import sys
import time
from typing import List, Dict, Any

try:
    from azure.storage.blob import BlobServiceClient, ContainerClient, BlobClient
except ImportError:
    sys.stderr.write("Missing required package 'azure-storage-blob'. Install with pip.\n")
    sys.exit(1)


TOOL_NAME = "AzureBlobInspector"
VERSION = "1.0.0"


def safe_sleep():
    time.sleep(0.5)


def list_containers(service: BlobServiceClient) -> List[str]:
    containers = []
    try:
        for container in service.list_containers():
            containers.append(container.name)
            safe_sleep()
    except Exception as e:
        raise RuntimeError(f"Error listing containers: {e}")
    return containers


def list_blobs(service: BlobServiceClient, container_name: str) -> List[str]:
    blobs = []
    try:
        container_client: ContainerClient = service.get_container_client(container_name)
        for blob in container_client.list_blobs():
            blobs.append(blob.name)
            safe_sleep()
    except Exception as e:
        raise RuntimeError(f"Error listing blobs in container '{container_name}': {e}")
    return blobs


def get_blob_properties(service: BlobServiceClient, container_name: str, blob_name: str) -> Dict[str, Any]:
    try:
        blob_client: BlobClient = service.get_blob_client(container=container_name, blob=blob_name)
        props = blob_client.get_blob_properties()
        safe_sleep()
        return {
            "size": props.size,
            "content_type": props.content_settings.content_type,
            "last_modified": props.last_modified.isoformat(),
            "etag": props.etag,
            "blob_type": props.blob_type,
        }
    except Exception as e:
        raise RuntimeError(f"Error getting properties for blob '{blob_name}' in container '{container_name}': {e}")


def perform_inspection(account_url: str, credential: str) -> Dict[str, Any]:
    findings = []
    results = {}
    status = "success"

    try:
        service = BlobServiceClient(account_url=account_url, credential=credential)
    except Exception as e:
        return {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": account_url,
            "status": "error",
            "findings": [f"Failed to create BlobServiceClient: {e}"],
            "results": {}
        }

    try:
        containers = list_containers(service)
        results["containers"] = containers
        findings.append(f"Found {len(containers)} container(s).")
    except Exception as e:
        status = "error"
        findings.append(str(e))
        containers = []

    for container in containers[:3]:  # limit to first 3 containers for brevity
        try:
            blobs = list_blobs(service, container)
            results.setdefault("blobs", {})[container] = blobs
            findings.append(f"Container '{container}' has {len(blobs)} blob(s).")
        except Exception as e:
            status = "error"
            findings.append(str(e))
            continue

        for blob in blobs[:3]:  # limit to first 3 blobs per container
            try:
                props = get_blob_properties(service, container, blob)
                results.setdefault("blob_properties", {}).setdefault(container, {})[blob] = props
                findings.append(f"Blob '{blob}' properties retrieved.")
            except Exception as e:
                status = "error"
                findings.append(str(e))

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": account_url,
        "status": status,
        "findings": findings,
        "results": results
    }


def self_test() -> bool:
    # Basic sanity checks without external network calls
    try:
        # Test import
        import importlib
        importlib.import_module("azure.storage.blob")
        # Test JSON output format
        dummy_output = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": "https://example.blob.core.windows.net/",
            "status": "success",
            "findings": [],
            "results": {}
        }
        json.dumps(dummy_output)
    except Exception:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Azure Blob Storage inspection tool")
    parser.add_argument("--account-url", help="Azure Blob Storage account URL (e.g., https://myaccount.blob.core.windows.net/)")
    parser.add_argument("--credential", help="Credential string (SAS token or account key). Use empty string for anonymous access.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test and exit")
    args = parser.parse_args()

    if args.self_test:
        if self_test():
            print(json.dumps({
                "tool": TOOL_NAME,
                "version": VERSION,
                "target": "self-test",
                "status": "success",
                "findings": ["Self‑test passed."],
                "results": {}
            }))
            sys.exit(0)
        else:
            print(json.dumps({
                "tool": TOOL_NAME,
                "version": VERSION,
                "target": "self-test",
                "status": "error",
                "findings": ["Self‑test failed."],
                "results": {}
            }))
            sys.exit(1)

    if not args.account_url:
        sys.stderr.write("Error: --account-url is required.\n")
        sys.exit(1)

    credential = args.credential if args.credential is not None else None
    output = perform_inspection(args.account_url, credential)
    print(json.dumps(output, default=str))


if __name__ == "__main__":
    main()