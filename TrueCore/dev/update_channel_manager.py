from __future__ import annotations

import argparse
import json
import os

from TrueCore.utils.release_signing import (
    SIGNATURE_ALGORITHM,
    ensure_signing_keypair,
    public_key_id,
    sign_manifest,
)


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_ROOT = os.path.abspath(os.path.join(PROJECT_ROOT, ".."))

VERSION_JSON_PATH = os.path.join(REPO_ROOT, "version.json")
VERSION_DEV_JSON_PATH = os.path.join(REPO_ROOT, "version-dev.json")

DEV_SYSTEM_DIR = os.path.join(PROJECT_ROOT, "dev_system")
ASSETS_DIR = os.path.join(PROJECT_ROOT, "launcher", "assets")
SIGNING_PRIVATE_KEY_PATH = os.path.join(DEV_SYSTEM_DIR, "release_signing_private.pem")
SIGNING_PUBLIC_KEY_PATH = os.path.join(ASSETS_DIR, "release_signing_public.pem")


def load_manifest(path):
    with open(path, "r", encoding="utf-8") as handle:
        return dict(json.load(handle) or {})


def write_manifest(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4, ensure_ascii=True)
    return path


def build_signed_channel_manifest(
    source_manifest,
    *,
    channel,
    version=None,
    download=None,
    sha256=None,
    size=None,
    build_id=None,
    published_at=None,
):
    payload = dict(source_manifest or {})
    original_channel = str(payload.get("channel") or "production").strip().lower() or "production"

    if version:
        payload["version"] = str(version).strip()
    if download:
        payload["download"] = str(download).strip()
    if sha256:
        payload["sha256"] = str(sha256).strip().lower()
    if size is not None:
        payload["size"] = int(size)
    if build_id:
        payload["build_id"] = str(build_id).strip()
    if published_at:
        payload["published_at"] = str(published_at).strip()

    payload["channel"] = str(channel).strip().lower()
    payload["promoted_from_channel"] = original_channel

    private_signing_key, public_signing_key, _ = ensure_signing_keypair(
        SIGNING_PRIVATE_KEY_PATH,
        SIGNING_PUBLIC_KEY_PATH,
    )
    payload["signature_algorithm"] = SIGNATURE_ALGORITHM
    payload["signature_key_id"] = public_key_id(public_signing_key)
    payload["signature"] = sign_manifest(payload, private_signing_key)
    return payload


def seed_dev_manifest_from_production(
    *,
    version=None,
    download=None,
    sha256=None,
    size=None,
    build_id=None,
    published_at=None,
    output_manifest_path=None,
):
    source_manifest = load_manifest(VERSION_JSON_PATH)
    output_manifest_path = output_manifest_path or VERSION_DEV_JSON_PATH
    payload = build_signed_channel_manifest(
        source_manifest,
        channel="dev",
        version=version,
        download=download,
        sha256=sha256,
        size=size,
        build_id=build_id,
        published_at=published_at,
    )
    write_manifest(output_manifest_path, payload)
    return output_manifest_path, payload


def parse_args():
    parser = argparse.ArgumentParser(
        description="Manage TrueCore update-channel manifests.",
    )
    parser.add_argument(
        "action",
        choices=["seed-dev"],
        help="Seed or refresh version-dev.json from the production manifest.",
    )
    parser.add_argument("--version", dest="version")
    parser.add_argument("--download", dest="download")
    parser.add_argument("--sha256", dest="sha256")
    parser.add_argument("--size", dest="size", type=int)
    parser.add_argument("--build-id", dest="build_id")
    parser.add_argument("--published-at", dest="published_at")
    parser.add_argument("--output", dest="output_manifest_path", default=VERSION_DEV_JSON_PATH)
    return parser.parse_args()


def main():
    args = parse_args()

    if args.action == "seed-dev":
        path, payload = seed_dev_manifest_from_production(
            version=args.version,
            download=args.download,
            sha256=args.sha256,
            size=args.size,
            build_id=args.build_id,
            published_at=args.published_at,
            output_manifest_path=args.output_manifest_path,
        )
        print(f"Dev manifest written: {path}")
        print(f"Version: {payload.get('version')}")
        print(f"Download: {payload.get('download')}")
        print(f"Channel: {payload.get('channel')}")


if __name__ == "__main__":
    main()
