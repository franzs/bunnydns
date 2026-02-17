"""Bunny DNS API client."""

from __future__ import annotations

from typing import Any

import requests

from ._helpers import _enum_to_int
from .enums import (
    CERTIFICATE_KEY_TYPE_BY_INT,
    LOG_ANONYMIZATION_TYPE_BY_INT,
    CertificateKeyType,
    LogAnonymizationType,
)
from .exceptions import (
    BunnyDNSAPIError,
    BunnyDNSAuthenticationError,
    BunnyDNSNotFoundError,
)
from .models import (
    DnsRecord,
    DnsRecordInput,
    DnsSecDsRecord,
    DnsZone,
    DnsZoneImportResult,
    DnsZoneList,
)

_BASE_URL = "https://api.bunny.net"


class BunnyDNS:
    """Client for the Bunny.net DNS API.

    Parameters
    ----------
    access_key:
        Your Bunny.net API access key.
    base_url:
        Override the default API base URL (useful for testing).
    timeout:
        HTTP request timeout in seconds.

    Example
    -------
    >>> client = BunnyDNS(access_key="your-api-key")
    >>> zones = client.list_dns_zones()
    >>> for zone in zones.items:
    ...     print(zone.domain)
    """

    def __init__(
        self,
        access_key: str,
        base_url: str = _BASE_URL,
        timeout: int = 30,
    ) -> None:
        self._access_key = access_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "AccessKey": self._access_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    # -- internal helpers ---------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        text_body: str | None = None,
        raw_response: bool = False,
    ) -> Any:
        """Send an HTTP request and return the parsed JSON response."""
        url = f"{self._base_url}{path}"

        kwargs: dict[str, Any] = {
            "method": method,
            "url": url,
            "params": params,
            "timeout": self._timeout,
        }

        if text_body is not None:
            kwargs["data"] = text_body
            kwargs["headers"] = {"Content-Type": "text/plain"}
        else:
            kwargs["json"] = json_body

        response = self._session.request(**kwargs)
        self._raise_for_status(response)
        if raw_response:
            return response.text
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    @staticmethod
    def _raise_for_status(response: requests.Response) -> None:
        if response.ok:
            return
        msg = response.text or response.reason or ""
        if response.status_code == 401:
            raise BunnyDNSAuthenticationError(msg)
        if response.status_code == 404:
            raise BunnyDNSNotFoundError(msg)
        raise BunnyDNSAPIError(response.status_code, msg)

    # -- DNS Zone endpoints -------------------------------------------------

    def list_dns_zones(
        self,
        page: int = 1,
        per_page: int = 1000,
        search: str | None = None,
    ) -> DnsZoneList:
        """Retrieve a paginated list of DNS zones on the account.

        Parameters
        ----------
        page:
            Page number (default ``1``).
        per_page:
            Number of items per page (``5`` – ``1000``, default ``1000``).
        search:
            Optional search term to filter results by domain name.
        """
        if not 5 <= per_page <= 1000:
            raise ValueError("per_page must be between 5 and 1000")
        params: dict[str, Any] = {"page": page, "perPage": per_page}
        if search is not None:
            params["search"] = search
        data = self._request("GET", "/dnszone", params=params)
        return DnsZoneList.from_dict(data)

    def add_dns_zone(
        self,
        domain: str,
        records: list[DnsRecordInput] | None = None,
    ) -> DnsZone:
        """Create a new DNS zone.

        Parameters
        ----------
        domain:
            The domain name for the new zone.
        records:
            Optional list of DNS records to create together with the zone.
        """
        body: dict[str, Any] = {"Domain": domain}
        if records is not None:
            body["Records"] = [r.to_dict() for r in records]
        data = self._request("POST", "/dnszone", json_body=body)
        return DnsZone.from_dict(data)

    def get_dns_zone(self, zone_id: int) -> DnsZone:
        """Retrieve a single DNS zone by its ID.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone to retrieve.
        """
        data = self._request("GET", f"/dnszone/{zone_id}")
        return DnsZone.from_dict(data)

    def update_dns_zone(
        self,
        zone_id: int,
        custom_nameservers_enabled: bool | None = None,
        nameserver1: str | None = None,
        nameserver2: str | None = None,
        soa_email: str | None = None,
        logging_enabled: bool | None = None,
        logging_ip_anonymization_enabled: bool | None = None,
        log_anonymization_type: LogAnonymizationType | None = None,
        certificate_key_type: CertificateKeyType | None = None,
    ) -> DnsZone:
        """Update the settings of an existing DNS zone.

        Only non-``None`` parameters will be included in the update request.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone to update.
        custom_nameservers_enabled:
            Enable or disable custom nameservers.
        nameserver1:
            The first custom nameserver.
        nameserver2:
            The second custom nameserver.
        soa_email:
            The SOA email address for the zone.
        logging_enabled:
            Enable or disable query logging.
        logging_ip_anonymization_enabled:
            Enable or disable IP anonymization in logs.
        log_anonymization_type:
            The type of log anonymization to apply.
        certificate_key_type:
            The private key type for wildcard certificates.
        """
        body: dict[str, Any] = {}
        if custom_nameservers_enabled is not None:
            body["CustomNameserversEnabled"] = custom_nameservers_enabled
        if nameserver1 is not None:
            body["Nameserver1"] = nameserver1
        if nameserver2 is not None:
            body["Nameserver2"] = nameserver2
        if soa_email is not None:
            body["SoaEmail"] = soa_email
        if logging_enabled is not None:
            body["LoggingEnabled"] = logging_enabled
        if logging_ip_anonymization_enabled is not None:
            body["LoggingIPAnonymizationEnabled"] = logging_ip_anonymization_enabled
        if log_anonymization_type is not None:
            body["LogAnonymizationType"] = _enum_to_int(
                log_anonymization_type, LOG_ANONYMIZATION_TYPE_BY_INT
            )
        if certificate_key_type is not None:
            body["CertificateKeyType"] = _enum_to_int(
                certificate_key_type, CERTIFICATE_KEY_TYPE_BY_INT
            )
        data = self._request("POST", f"/dnszone/{zone_id}", json_body=body)
        return DnsZone.from_dict(data)

    def delete_dns_zone(self, zone_id: int) -> None:
        """Delete a DNS zone.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone to delete.
        """
        self._request("DELETE", f"/dnszone/{zone_id}")

    def export_dns_zone(self, zone_id: int) -> str:
        """Export a DNS zone as a BIND zone file.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone to export.
        """
        result: str = self._request(
            "GET", f"/dnszone/{zone_id}/export", raw_response=True
        )
        return result

    def check_dns_zone_availability(self, domain: str) -> bool:
        """Check if a DNS zone is available to be added.

        Parameters
        ----------
        domain:
            The domain name to check availability for.
        """
        data: dict[str, Any] = self._request(
            "POST", "/dnszone/checkavailability", json_body={"Name": domain}
        )
        return bool(data.get("Available", False))

    def import_dns_records(
        self, zone_id: int, zone_file: str
    ) -> DnsZoneImportResult:
        """Import DNS records from a BIND zone file.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone to import records into.
        zone_file:
            The zone file content as a string.
        """
        data = self._request(
            "POST", f"/dnszone/{zone_id}/import", text_body=zone_file
        )
        return DnsZoneImportResult.from_dict(data)

    # -- DNS Record endpoints -----------------------------------------------

    def add_dns_record(self, zone_id: int, record: DnsRecordInput) -> DnsRecord:
        """Add a DNS record to a zone.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone to add the record to.
        record:
            The DNS record data to create.
        """
        data = self._request(
            "PUT", f"/dnszone/{zone_id}/records", json_body=record.to_dict()
        )
        return DnsRecord.from_dict(data)

    def update_dns_record(
        self, zone_id: int, record_id: int, record: DnsRecordInput
    ) -> None:
        """Update an existing DNS record.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone that contains the record.
        record_id:
            The ID of the DNS record to update.
        record:
            The updated DNS record data.
        """
        if record.id is None:
            record.id = record_id
        self._request(
            "POST",
            f"/dnszone/{zone_id}/records/{record_id}",
            json_body=record.to_dict(),
        )

    def delete_dns_record(self, zone_id: int, record_id: int) -> None:
        """Delete a DNS record from a zone.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone that contains the record.
        record_id:
            The ID of the DNS record to delete.
        """
        self._request("DELETE", f"/dnszone/{zone_id}/records/{record_id}")

    # -- DNSSEC endpoints ---------------------------------------------------

    def enable_dnssec(self, zone_id: int) -> DnsSecDsRecord:
        """Enable DNSSEC on a DNS zone.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone for which DNSSEC will be enabled.
        """
        data = self._request("POST", f"/dnszone/{zone_id}/dnssec")
        return DnsSecDsRecord.from_dict(data)

    def disable_dnssec(self, zone_id: int) -> DnsSecDsRecord:
        """Disable DNSSEC on a DNS zone.

        Parameters
        ----------
        zone_id:
            The ID of the DNS zone for which DNSSEC will be disabled.
        """
        data = self._request("DELETE", f"/dnszone/{zone_id}/dnssec")
        return DnsSecDsRecord.from_dict(data)
