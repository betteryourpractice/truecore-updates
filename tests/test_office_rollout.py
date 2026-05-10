import os
import tempfile
import unittest
from unittest.mock import patch

from TrueCore.core import office_rollout


class OfficeRolloutTests(unittest.TestCase):

    def test_build_rollout_summary_tracks_progress_and_actions(self):
        profile = office_rollout.normalize_office_profile({
            "organization_id": "org-1",
            "office_id": "office-a",
            "office_name": "Office A",
            "credential_policy": {"username_hint": "office.alpha"},
            "onboarding": {
                "docs_kit_exported_at": "2026-05-09T10:00:00Z",
                "first_packet_analyzed_at": "2026-05-09T10:05:00Z",
            },
        })

        summary = office_rollout.build_rollout_summary(
            profile,
            packet_count=3,
            outcome_count=0,
            imported_snapshot_count=0,
        )

        self.assertEqual(summary["band"], "operational")
        self.assertEqual(summary["completed_steps"], 4)
        self.assertTrue(summary["docs_kit_exported"])
        self.assertFalse(summary["first_real_outcome_recorded"])
        self.assertTrue(any("Record at least one real packet outcome" in item for item in summary["recommended_actions"]))

    def test_record_milestones_persist_to_profile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_path = os.path.join(temp_dir, "office_profile.json")

            with patch.object(office_rollout, "OFFICE_PROFILE_PATH", profile_path):
                office_rollout.ensure_office_profile()
                office_rollout.record_office_profile_confirmed()
                office_rollout.record_docs_kit_exported()
                office_rollout.record_packet_analyzed()
                office_rollout.record_real_outcome()

                profile = office_rollout.load_office_profile()

            onboarding = dict(profile.get("onboarding") or {})
            self.assertTrue(onboarding.get("office_profile_confirmed_at"))
            self.assertTrue(onboarding.get("docs_kit_exported_at"))
            self.assertTrue(onboarding.get("first_packet_analyzed_at"))
            self.assertTrue(onboarding.get("first_real_outcome_at"))


if __name__ == "__main__":
    unittest.main()
