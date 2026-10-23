#!/usr/bin/env python3
"""Download public benchmark datasets described by ``benchmarks/manifests``.

Raw datasets contain real phone numbers and personal messages, so downloads go
to ``benchmarks/data`` which is gitignored. Nothing here is bundled into the
package or committed.

Usage:
    python -m benchmarks.download --list
    python -m benchmarks.download uci_sms
    python -m benchmarks.download --all
"""

from __future__ import annotations

import argparse
import io
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

from .evaluate import DATA_DIR, list_manifests, load_manifest

# Optional local copies we can stage without a network round-trip.
LOCAL_FALLBACKS = {
    "sms_5971": Path(
        "/Users/nori/Downloads/SMS PHISHING DATASET FOR MACHINE LEARNING AND "
        "PATTERN RECOGNITION/Dataset_5971.csv"
    ),
}

# Files we expect after extraction, keyed by manifest name.
EXTRACTED_FILES = {
    "uci_sms": {"SMSSpamCollection": "uci_sms/SMSSpamCollection"},
    "enron_spam": {"enron_spam_data.csv": "enron_spam/enron_spam_data.csv"},
}


def _download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - fixed manifest URLs
        payload = response.read()
    destination.write_bytes(payload)
    print(f"  saved {destination} ({len(payload):,} bytes)")


def _extract_zip(payload: bytes, name: str) -> None:
    target = DATA_DIR / name
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        archive.extractall(target)
    print(f"  extracted into {target}")


def _extract_zip_from_url(url: str, name: str) -> None:
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=180) as response:  # noqa: S310
        payload = response.read()
    _extract_zip(payload, name)


def download(name: str) -> bool:
    manifest = load_manifest(next(path for path in list_manifests() if path.stem == name))
    file_path = DATA_DIR / manifest["file"]

    if file_path.exists():
        print(f"{name}: already present at {file_path}")
        return True

    download_url = manifest.get("download")
    if name in EXTRACTED_FILES and download_url:
        _extract_zip_from_url(download_url, name)
        return file_path.exists()

    if name in LOCAL_FALLBACKS and LOCAL_FALLBACKS[name].exists():
        file_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(LOCAL_FALLBACKS[name], file_path)
        print(f"{name}: copied local file to {file_path}")
        return True

    if not download_url:
        print(f"{name}: no download URL and no local copy found", file=sys.stderr)
        return False

    _download(download_url, file_path)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("datasets", nargs="*", help="manifest names without .json")
    parser.add_argument("--all", action="store_true", help="download every manifest")
    parser.add_argument("--list", action="store_true", help="list manifests and whether data is present")
    args = parser.parse_args()

    manifests = list_manifests()
    if args.list or (not args.datasets and not args.all):
        for path in manifests:
            manifest = load_manifest(path)
            status = "present" if (DATA_DIR / manifest["file"]).exists() else "missing"
            print(f"  {path.stem:<24} {status:<8} {manifest.get('description', '')}")
        return 0

    names = [path.stem for path in manifests] if args.all else args.datasets
    failures = 0
    for name in names:
        if name not in {path.stem for path in manifests}:
            print(f"unknown dataset: {name}", file=sys.stderr)
            failures += 1
            continue
        if not download(name):
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
