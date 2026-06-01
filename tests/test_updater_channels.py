import unittest

from TrueCore.launcher import updater


class UpdaterChannelTests(unittest.TestCase):

    def test_resolve_update_source_defaults_to_production(self):
        channel, url = updater.resolve_update_source()
        self.assertEqual(channel, "production")
        self.assertEqual(url, updater.PRODUCTION_UPDATE_URL)

    def test_resolve_update_source_supports_dev_channel(self):
        channel, url = updater.resolve_update_source("dev")
        self.assertEqual(channel, "dev")
        self.assertEqual(url, updater.DEV_UPDATE_URL)

    def test_resolve_update_source_accepts_custom_url(self):
        channel, url = updater.resolve_update_source("https://example.com/custom.json")
        self.assertEqual(channel, "custom")
        self.assertEqual(url, "https://example.com/custom.json")


if __name__ == "__main__":
    unittest.main()
