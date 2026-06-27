from __future__ import annotations

from TrueCore.utils.private_dev_channel import get_private_dev_repo_slug, is_private_dev_channel_enabled


PUBLIC_OFFICE_REPO_SLUG = "betteryourpractice/truecore-updates"
PUBLIC_OFFICE_REPO_URL = f"https://github.com/{PUBLIC_OFFICE_REPO_SLUG}"


def normalize_git_remote_url(url):
    normalized = str(url or "").strip()
    if not normalized:
        return ""
    normalized = normalized.replace("\\", "/")
    if normalized.lower().startswith("git@github.com:"):
        normalized = f"https://github.com/{normalized.split(':', 1)[1]}"
    if normalized.lower().endswith(".git"):
        normalized = normalized[:-4]
    return normalized.rstrip("/").lower()


def extract_github_repo_slug(url):
    normalized = normalize_git_remote_url(url)
    prefix = "https://github.com/"
    if not normalized.startswith(prefix):
        return None
    slug = normalized[len(prefix):].strip("/")
    return slug or None


def is_public_office_repo_url(url):
    return extract_github_repo_slug(url) == PUBLIC_OFFICE_REPO_SLUG


def evaluate_release_lane(build_channel, origin_url, *, private_dev_config=None, public_dev_channel_enabled=False):
    normalized_origin = normalize_git_remote_url(origin_url)
    origin_repo_slug = extract_github_repo_slug(normalized_origin)
    private_dev_repo_slug = get_private_dev_repo_slug(private_dev_config or {})

    payload = {
        "build_channel": str(build_channel or "").strip().lower(),
        "origin_url": normalized_origin,
        "origin_repo_slug": origin_repo_slug,
        "private_dev_repo_slug": private_dev_repo_slug,
        "source_publish_allowed": False,
        "private_dev_publish_expected": False,
        "errors": [],
        "warnings": [],
    }

    if payload["build_channel"] == "production":
        if not is_public_office_repo_url(normalized_origin):
            payload["errors"].append(
                "Production publish is only allowed from the public office repo origin."
            )
            return payload

        payload["source_publish_allowed"] = True
        return payload

    if payload["build_channel"] != "dev":
        payload["errors"].append(f"Unsupported build channel: {build_channel}")
        return payload

    if not public_dev_channel_enabled:
        payload["private_dev_publish_expected"] = True
        if not is_private_dev_channel_enabled(private_dev_config or {}):
            payload["errors"].append(
                "Private DEV channel is not fully configured, so DEV publish cannot continue."
            )
        if private_dev_repo_slug == PUBLIC_OFFICE_REPO_SLUG:
            payload["errors"].append(
                "Private DEV release repo is pointed at the public office repo, which is not allowed."
            )

    if is_public_office_repo_url(normalized_origin):
        payload["warnings"].append(
            "DEV source publish is disabled because the current origin is the public office repo."
        )
        payload["source_publish_allowed"] = False
        return payload

    if normalized_origin:
        payload["source_publish_allowed"] = True
    else:
        payload["warnings"].append(
            "No git origin was detected, so DEV source changes will stay local."
        )

    return payload
