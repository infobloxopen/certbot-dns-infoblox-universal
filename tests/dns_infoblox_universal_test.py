import unittest
from unittest.mock import MagicMock, patch

from certbot_dns_infoblox_universal.dns_infoblox_universal import Authenticator


class TestAuthenticator(unittest.TestCase):

    def setUp(self):
        config = MagicMock()  # Mock the config object
        name = "infoblox"  # Provide a name
        self.authenticator = Authenticator(config, name)
        self.authenticator.credentials = MagicMock()  # Mock the credentials attribute
        self.authenticator.credentials.conf.side_effect = lambda key: {
            "api_key": "1234567",
            "view": "test",
        }[key]

    @patch("certbot_dns_infoblox.dns_infoblox.bloxone_client.ApiClient")
    @patch("certbot_dns_infoblox.dns_infoblox.bloxone_client.Configuration")
    def test_get_infoblox_client(self, mock_config, mock_api_client):
        mock_config.return_value = MagicMock()
        mock_api_client.return_value = MagicMock()

        client = self.authenticator._get_infoblox_client()

        self.assertIsNotNone(client)
        mock_config.assert_called_once()
        mock_api_client.assert_called_once()

    @patch("certbot_dns_infoblox.dns_infoblox.ViewApi")
    @patch("certbot_dns_infoblox.dns_infoblox.AuthZoneApi")
    def test_get_infoblox_record(self, mock_auth_zone_api, mock_view_api):
        mock_view_api.return_value.list.return_value = (
            MagicMock(),
            ({"id": "view-id"}, "test"),
        )
        mock_auth_zone_api.return_value.list.return_value = MagicMock(
            results=[MagicMock(id="zone-id")]
            # mock_auth_zone_api.return_value.list.return_value = MagicMock(results=[{'id': 'zone-id'}])
        )
        domain = "example.com"
        validation_name = "_acme-challenge.example.com"
        validation = "dummy-validation"

        record = self.authenticator._get_infoblox_record(
            domain, validation_name, validation
        )

        self.assertEqual(record["name"], validation_name)
        self.assertEqual(record["type"], "TXT")
        self.assertEqual(record["rdata"]["text"], validation)
        self.assertEqual(record["zone"], "zone-id")
        self.assertEqual(record["ttl"], self.authenticator.ttl)

    @patch("certbot_dns_infoblox.dns_infoblox.RecordApi")
    @patch("certbot_dns_infoblox.dns_infoblox.ViewApi")
    @patch("certbot_dns_infoblox.dns_infoblox.AuthZoneApi")
    def test_perform(self, mock_auth_zone_api, mock_view_api, mock_record_api):
        mock_view_api.return_value.list.return_value = (
            MagicMock(),
            ({"id": "view-id"}, "test"),
        )
        mock_auth_zone_api.return_value.list.return_value = MagicMock(
            results=[MagicMock(id="zone-id")]
        )
        mock_record_api.return_value.create.return_value = MagicMock(
            result=MagicMock(id="txt-id")
        )

        domain = "example.com"
        validation_name = "_acme-challenge.example.com"
        validation = "dummy-validation"

        self.authenticator._perform(domain, validation_name, validation)

        self.assertIn("txt-id", self.authenticator.infotxts)
        mock_record_api.return_value.create.assert_called_once()

    @patch("certbot_dns_infoblox.dns_infoblox.RecordApi")
    def test_cleanup(self, mock_record_api):
        self.authenticator.infotxts = ["txt-id"]

        domain = "example.com"
        validation_name = "_acme-challenge.example.com"
        validation = "dummy-validation"

        self.authenticator._cleanup(domain, validation_name, validation)

        self.assertNotIn("txt-id", self.authenticator.infotxts)
        mock_record_api.return_value.delete.assert_called_once_with(id="txt-id")


if __name__ == "__main__":
    unittest.main()
