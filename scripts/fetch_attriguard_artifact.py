"""Fetch and verify the official AttriGuard artifact without vendoring it."""

from __future__ import annotations

import argparse
from hashlib import md5, sha256
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
from urllib.request import Request, urlopen
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    DEFAULT_ARTIFACT_MANIFEST,
    AttriGuardIntegrationError,
    load_artifact_manifest,
    verify_official_artifact,
)


def _hashes(path: Path) -> tuple[str, str]:
    sha_digest = sha256()
    md5_digest = md5()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha_digest.update(chunk)
            md5_digest.update(chunk)
    return sha_digest.hexdigest(), md5_digest.hexdigest()


def _validate_archive(path: Path, manifest: dict) -> None:
    source = manifest["source"]
    if path.stat().st_size != source["archive_size_bytes"]:
        raise AttriGuardIntegrationError("Downloaded archive size mismatch")
    actual_sha256, actual_md5 = _hashes(path)
    if actual_sha256 != source["archive_sha256"]:
        raise AttriGuardIntegrationError("Downloaded archive SHA-256 mismatch")
    if actual_md5 != source["archive_md5"]:
        raise AttriGuardIntegrationError("Downloaded archive MD5 mismatch")


def _safe_extract(archive: Path, destination: Path) -> None:
    with ZipFile(archive) as bundle:
        for info in bundle.infolist():
            relative = PurePosixPath(info.filename)
            if relative.is_absolute() or ".." in relative.parts:
                raise AttriGuardIntegrationError(
                    f"Unsafe path in official artifact archive: {info.filename}"
                )
            unix_mode = info.external_attr >> 16
            if stat.S_IFMT(unix_mode) == stat.S_IFLNK:
                raise AttriGuardIntegrationError(
                    f"Symlink is not allowed in official artifact archive: {info.filename}"
                )
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            with bundle.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def fetch(destination: Path, manifest_path: Path) -> dict:
    manifest = load_artifact_manifest(manifest_path)
    destination = destination.resolve()
    if destination.exists():
        raise AttriGuardIntegrationError(
            f"Destination already exists; use --verify-only or choose a new path: {destination}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=".attriguard-fetch-", dir=destination.parent)
    ).resolve()
    try:
        archive = temporary / manifest["source"]["archive_name"]
        request = Request(
            manifest["source"]["download_url"],
            headers={"User-Agent": "attriguard-gitinject-evaluation/1"},
        )
        with urlopen(request, timeout=60) as response, archive.open("wb") as output:
            shutil.copyfileobj(response, output)
        _validate_archive(archive, manifest)
        _safe_extract(archive, temporary)
        verified = verify_official_artifact(temporary, manifest_path)
        os.replace(temporary, destination)
        temporary = None
        return {
            "artifact_id": manifest["artifact_id"],
            "destination": str(destination),
            "archive_sha256": manifest["source"]["archive_sha256"],
            "verified_roles": sorted(verified),
            "core_byte_identical": True,
        }
    finally:
        if temporary is not None and temporary.exists():
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch or verify the byte-pinned official AttriGuard artifact"
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=ROOT / "tmp" / "attriguard-official",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_ARTIFACT_MANIFEST,
    )
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_only:
            verified = verify_official_artifact(args.destination, args.manifest)
            result = {
                "destination": str(args.destination.resolve()),
                "verified_roles": sorted(verified),
                "core_byte_identical": True,
            }
        else:
            result = fetch(args.destination, args.manifest)
    except (AttriGuardIntegrationError, OSError) as error:
        print(f"AttriGuard artifact operation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
