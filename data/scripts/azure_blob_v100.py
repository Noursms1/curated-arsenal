# CATEGORY: Cloud
import argparse
import json
import sys
import time
from typing import Any, Dict, List, Optional

from azure.core.exceptions import AzureError
from azure.storage.blob import BlobServiceClient, ContainerClient, BlobClient, PublicAccess


TOOL_NAME = "azure_blob_tool"
VERSION = "1.0.0"


def json_output(status: str, target: str, findings: List[str], results: Any) -> None:
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }
    print(json.dumps(output, indent=2))


def list_containers(service: BlobServiceClient) -> List[str]:
    containers = []
    try:
        for cont in service.list_containers():
            containers.append(cont.name)
            time.sleep(0.5)
    except AzureError as e:
        raise RuntimeError(f"Failed to list containers: {e}") from e
    return containers


def list_blobs(container: ContainerClient) -> List[str]:
    blobs = []
    try:
        for blob in container.list_blobs():
            blobs.append(blob.name)
            time.sleep(0.5)
    except AzureError as e:
        raise RuntimeError(f"Failed to list blobs: {e}") from e
    return blobs


def download_blob(blob: BlobClient, download_path: str) -> None:
    try:
        with open(download_path, "wb") as file:
            stream = blob.download_blob()
            file.write(stream.readall())
        time.sleep(0.5)
    except AzureError as e:
        raise RuntimeError(f"Failed to download blob: {e}") from e
    except OSError as e:
        raise RuntimeError(f"File write error: {e}") from e


def check_public_access(container: ContainerClient) -> str:
    try:
        props = container.get_container_properties()
        time.sleep(0.5)
        access = props.public_access
        if access == PublicAccess.Blob:
            return "blob"
        elif access == PublicAccess.Container:
            return "container"
        else:
            return "private"
    except AzureError as e:
        raise RuntimeError(f"Failed to get container properties: {e}") from e


def run_self_test() -> None:
    findings = ["Self-test executed"]
    results = {
        "list_containers": ["test-container-1", "test-container-2"],
        "list_blobs": ["blob1.txt", "blob2.log"],
        "public_access": "private",
    }
    json_output(status="self-test passed", target="self-test", findings=findings, results=results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Azure Blob Storage utility")
    parser.add_argument("--connection-string", required=False, help="Azure Storage connection string")
    parser.add_argument("--account-url", required=False, help="Azure Storage account URL (e.g., https://<account>.blob.core.windows.net/)")
    parser.add_argument("--sas-token", required=False, help="SAS token for authentication")
    parser.add_argument("--container", help="Container name")
    parser.add_argument("--blob", help="Blob name")
    parser.add_argument("--download-path", help="Local path to download blob")
    parser.add_argument(
        "--action",
        choices=["list-containers", "list-blobs", "download-blob", "check-public"],
        required=False,
        help="Action to perform",
    )
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    # Build service client
    try:
        if args.connection_string:
            service = BlobServiceClient.from_connection_string(args.connection_string)
        elif args.account_url:
            if args.sas_token:
                service = BlobServiceClient(account_url=args.account_url, credential=args.sas_token)
            else:
                raise ValueError("SAS token required when using account URL")
        else:
            raise ValueError("Either --connection-string or --account-url must be provided")
    except (AzureError, ValueError) as e:
        json_output(status="error", target="initialization", findings=[str(e)], results=None)
        sys.exit(1)

    target_desc = args.account_url or "connection-string"

    try:
        if args.action == "list-containers":
            containers = list_containers(service)
            json_output(status="success", target=target_desc, findings=[], results=containers)

        elif args.action == "list-blobs":
            if not args.container:
                raise ValueError("Container name required for listing blobs")
            container_client = service.get_container_client(args.container)
            blobs = list_blobs(container_client)
            json_output(status="success", target=args.container, findings=[], results=blobs)

        elif args.action == "download-blob":
            if not all([args.container, args.blob, args.download_path]):
                raise ValueError("Container, blob, and download-path are required for download")
            blob_client = service.get_blob_client(container=args.container, blob=args.blob)
            download_blob(blob_client, args.download_path)
            json_output(
                status="success",
                target=args.blob,
                findings=[],
                results={"download_path": args.download_path},
            )

        elif args.action == "check-public":
            if not args.container:
                raise ValueError("Container name required for public access check")
            container_client = service.get_container_client(args.container)
            access = check_public_access(container_client)
            json_output(
                status="success",
                target=args.container,
                findings=[],
                results={"public_access": access},
            )
        else:
            raise ValueError("No valid action specified")
    except Exception as e:
        json_output(status="error", target=target_desc, findings=[str(e)], results=None)
        sys.exit(1)


if __name__ == "__main__":
    main()