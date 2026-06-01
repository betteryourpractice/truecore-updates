from __future__ import annotations

import json
import os

from TrueCore.utils.runtime_info import runtime_data_path


PRIVATE_DEV_CHANNEL_CONFIG_PATH = runtime_data_path("dev_system", "private_dev_channel.json")
DEFAULT_PRIVATE_DEV_CHANNEL_CONFIG = {
    "enabled": False,
    "owner": "",
    "repo": "",
    "ref": "main",
    "manifest_path": "version-dev.json",
    "token": "",
    "asset_name_template": "TrueCore_{release_tag}.zip",
}
GITHUB_API_VERSION = "2022-11-28"


def _normalized_text(value, fallback=""):
    return str(value or fallback).strip() or fallback


def normalize_private_dev_channel_config(data):
    source = dict(data or {})
    payload = dict(DEFAULT_PRIVATE_DEV_CHANNEL_CONFIG)
    payload.update(source)
    payload["enabled"] = bool(payload.get("enabled"))
    payload["owner"] = _normalized_text(payload.get("owner"))
    payload["repo"] = _normalized_text(payload.get("repo"))
    payload["ref"] = _normalized_text(payload.get("ref"), "main")
    payload["manifest_path"] = _normalized_text(payload.get("manifest_path"), "version-dev.json")
    payload["token"] = _normalized_text(payload.get("token"))
    payload["asset_name_template"] = _normalized_text(
        payload.get("asset_name_template"),
        DEFAULT_PRIVATE_DEV_CHANNEL_CONFIG["asset_name_template"],
    )
    return payload


def ensure_private_dev_channel_config():
    os.makedirs(os.path.dirname(PRIVATE_DEV_CHANNEL_CONFIG_PATH), exist_ok=True)
    if os.path.exists(PRIVATE_DEV_CHANNEL_CONFIG_PATH):
        return PRIVATE_DEV_CHANNEL_CONFIG_PATH

    with open(PRIVATE_DEV_CHANNEL_CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(DEFAULT_PRIVATE_DEV_CHANNEL_CONFIG, handle, indent=4)
    return PRIVATE_DEV_CHANNEL_CONFIG_PATH


def load_private_dev_channel_config():
    ensure_private_dev_channel_config()
    try:
        with open(PRIVATE_DEV_CHANNEL_CONFIG_PATH, "r", encoding="utf-8") as handle:
            return normalize_private_dev_channel_config(json.load(handle))
    except Exception:
        return normalize_private_dev_channel_config({})


def save_private_dev_channel_config(data):
    payload = normalize_private_dev_channel_config(data)
    os.makedirs(os.path.dirname(PRIVATE_DEV_CHANNEL_CONFIG_PATH), exist_ok=True)
    with open(PRIVATE_DEV_CHANNEL_CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4)
    return payload


def update_private_dev_channel_config(changes):
    current = load_private_dev_channel_config()
    payload = dict(current)
    payload.update(dict(changes or {}))
    return save_private_dev_channel_config(payload)


def is_private_dev_channel_enabled(config=None):
    payload = normalize_private_dev_channel_config(config or load_private_dev_channel_config())
    return bool(
        payload.get("enabled")
        and payload.get("owner")
        and payload.get("repo")
        and payload.get("token")
    )


def get_private_dev_repo_slug(config=None):
    payload = normalize_private_dev_channel_config(config or load_private_dev_channel_config())
    owner = payload.get("owner")
    repo = payload.get("repo")
    if not owner or not repo:
        return None
    return f"{owner}/{repo}"


def build_private_dev_contents_api_url(config=None):
    payload = normalize_private_dev_channel_config(config or load_private_dev_channel_config())
    repo_slug = get_private_dev_repo_slug(payload)
    if not repo_slug:
        return None
    manifest_path = payload.get("manifest_path") or "version-dev.json"
    ref = payload.get("ref") or "main"
    return f"https://api.github.com/repos/{repo_slug}/contents/{manifest_path}?ref={ref}"


def build_private_dev_release_by_tag_api_url(release_tag, config=None):
    payload = normalize_private_dev_channel_config(config or load_private_dev_channel_config())
    repo_slug = get_private_dev_repo_slug(payload)
    if not repo_slug:
        return None
    return f"https://api.github.com/repos/{repo_slug}/releases/tags/{release_tag}"


def build_github_api_headers(token, accept="application/vnd.github+json"):
    token = _normalized_text(token)
    headers = {
        "Accept": accept,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers
