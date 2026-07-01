import unittest

from TrueCore.utils.release_lane_guard import (
    DEV_SOURCE_REMOTE_CANDIDATES,
    PUBLIC_OFFICE_REPO_URL,
    PRODUCTION_SOURCE_REMOTE_CANDIDATES,
    evaluate_release_lane,
    extract_github_repo_slug,
    is_public_office_repo_url,
    normalize_git_remote_url,
    resolve_source_remote_name,
)


class ReleaseLaneGuardTests(unittest.TestCase):

    def test_normalizes_github_urls(self):
        self.assertEqual(
            normalize_git_remote_url("git@github.com:betteryourpractice/truecore-updates.git"),
            PUBLIC_OFFICE_REPO_URL,
        )
        self.assertEqual(
            extract_github_repo_slug("https://github.com/betteryourpractice/truecore-dev-updates.git"),
            "betteryourpractice/truecore-dev-updates",
        )
        self.assertTrue(is_public_office_repo_url("https://github.com/betteryourpractice/truecore-updates.git"))

    def test_resolve_source_remote_name_prefers_named_lane_remotes(self):
        self.assertEqual(
            resolve_source_remote_name("production", ["origin", "office-source"]),
            PRODUCTION_SOURCE_REMOTE_CANDIDATES[0],
        )
        self.assertEqual(resolve_source_remote_name("production", ["origin"]), "origin")
        self.assertEqual(
            resolve_source_remote_name("dev", ["origin", "dev-source"]),
            DEV_SOURCE_REMOTE_CANDIDATES[0],
        )
        self.assertEqual(resolve_source_remote_name("dev", ["origin"]), "")

    def test_production_publish_requires_public_office_source_remote(self):
        allowed = evaluate_release_lane(
            "production",
            PUBLIC_OFFICE_REPO_URL,
            source_remote_name="office-source",
        )
        self.assertTrue(allowed["source_publish_allowed"])
        self.assertFalse(allowed["errors"])

        blocked = evaluate_release_lane(
            "production",
            "https://github.com/betteryourpractice/truecore-dev-source.git",
            source_remote_name="office-source",
        )
        self.assertFalse(blocked["source_publish_allowed"])
        self.assertTrue(blocked["errors"])

    def test_dev_publish_warns_when_no_dev_source_remote_is_configured(self):
        payload = evaluate_release_lane(
            "dev",
            "",
            private_dev_config={
                "enabled": True,
                "owner": "betteryourpractice",
                "repo": "truecore-dev-updates",
                "token": "abc123",
            },
        )
        self.assertFalse(payload["source_publish_allowed"])
        self.assertFalse(payload["errors"])
        self.assertTrue(payload["warnings"])
        self.assertTrue(payload["private_dev_publish_expected"])

    def test_dev_publish_rejects_dev_source_remote_pointing_to_public_office_repo(self):
        payload = evaluate_release_lane(
            "dev",
            PUBLIC_OFFICE_REPO_URL,
            source_remote_name="dev-source",
            private_dev_config={
                "enabled": True,
                "owner": "betteryourpractice",
                "repo": "truecore-dev-updates",
                "token": "abc123",
            },
        )
        self.assertTrue(payload["errors"])

    def test_dev_publish_rejects_private_repo_pointing_to_public_office_repo(self):
        payload = evaluate_release_lane(
            "dev",
            "https://github.com/betteryourpractice/truecore-dev-source.git",
            source_remote_name="dev-source",
            private_dev_config={
                "enabled": True,
                "owner": "betteryourpractice",
                "repo": "truecore-updates",
                "token": "abc123",
            },
        )
        self.assertTrue(payload["errors"])


if __name__ == "__main__":
    unittest.main()
