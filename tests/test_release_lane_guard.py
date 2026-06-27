import unittest

from TrueCore.utils.release_lane_guard import (
    PUBLIC_OFFICE_REPO_URL,
    evaluate_release_lane,
    extract_github_repo_slug,
    is_public_office_repo_url,
    normalize_git_remote_url,
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

    def test_production_publish_requires_public_office_origin(self):
        allowed = evaluate_release_lane("production", PUBLIC_OFFICE_REPO_URL)
        self.assertTrue(allowed["source_publish_allowed"])
        self.assertFalse(allowed["errors"])

        blocked = evaluate_release_lane(
            "production",
            "https://github.com/betteryourpractice/truecore-dev-source.git",
        )
        self.assertFalse(blocked["source_publish_allowed"])
        self.assertTrue(blocked["errors"])

    def test_dev_publish_disables_source_push_from_public_office_origin(self):
        payload = evaluate_release_lane(
            "dev",
            PUBLIC_OFFICE_REPO_URL,
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

    def test_dev_publish_rejects_private_repo_pointing_to_public_office_repo(self):
        payload = evaluate_release_lane(
            "dev",
            "https://github.com/betteryourpractice/truecore-dev-source.git",
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
