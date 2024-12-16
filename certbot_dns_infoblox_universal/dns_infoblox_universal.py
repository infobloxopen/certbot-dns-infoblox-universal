"""DNS Authenticator for Infoblox Universal."""

import logging
import time

import bloxone_client
import zope.interface
from certbot import interfaces
from certbot.plugins import dns_common
from dns_config import AuthZoneApi, ViewApi
from dns_data import RecordApi

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Infoblox Universal using the Infoblox REST API."""

    description = "Obtain certificates using a DNS TXT record (Infoblox Universal)."
    ttl = 300

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.csp_url = "https://stage.csp.infoblox.com"
        self.infoclient = None
        self.infotxts = []

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=10
        )
        add(
            "credentials",
            help="Infoblox credentials INI file.",
            default="/etc/letsencrypt/infoblox.ini",
        )

    def more_info(self):
        return (
            "This plugin configures a DNS TXT record to respond to a "
            "dns-01 challenge using the bloxone Infoblox Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Bloxone Infoblox credentials INI file",
            {
                "api_key": "API Key for Bloxone Infoblox REST API.",
                "view": "View to use for TXT  record entries ",
            },
        )

    def _get_infoblox_client(self):
        if not self.infoclient:
            config = bloxone_client.Configuration(
                csp_url=self.csp_url,
                api_key=self.credentials.conf("api_key"),
                client_name="certbot",
            )
            self.infoclient = bloxone_client.ApiClient(config)
        return self.infoclient

    def _get_infoblox_record(self, domain, validation_name, validation):
        self._get_infoblox_client()
        # get view identifier
        view_name = self.credentials.conf("view") or "default"

        result, _ = ViewApi(self.infoclient).list(
            filter=f'name=="{view_name}"', inherit="full"
        )

        if not result[1]:
            raise ValueError(f"View '{view_name}' not found.")
        view_id = result[1][0].id

        zones = AuthZoneApi(self.infoclient).list(
            filter=f'fqdn=="{domain}"', inherit="full"
        )

        zone_id = next(
            (zone.id for zone in zones.results if zone.view == view_id), None
        )

        if not zone_id:
            raise ValueError(f"Zone '{domain}' not found.")

        return {
            "name": validation_name,
            "type": "TXT",
            "rdata": {"text": validation},
            "name_in_zone": validation_name.split(".", 1)[0],
            "zone": zone_id,
            "ttl": self.ttl,
            "comment": f"{time.strftime('%Y-%m-%d %H:%M:%S')}: "
            f"certbot-auto for {domain}",
        }

    def _perform(self, domain, validation_name, validation):
        self._get_infoblox_client()

        txt = RecordApi(self.infoclient).create(
            body=self._get_infoblox_record(domain, validation_name, validation)
        )
        self.infotxts.append(txt.result.id)

    def _cleanup(self, domain, validation_name, validation):
        self._get_infoblox_client()
        if not self.infotxts:
            return
        for txt in self.infotxts:
            RecordApi(self.infoclient).delete(id=txt)
            self.infotxts.remove(txt)
