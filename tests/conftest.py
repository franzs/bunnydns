"""Shared test fixtures."""

import pytest
import responses

from bunnydns import BunnyDNS


@pytest.fixture
def access_key() -> str:
    return "test-api-key-12345"


@pytest.fixture
def base_url() -> str:
    return "https://api.bunny.net"


@pytest.fixture
def client(access_key: str, base_url: str) -> BunnyDNS:
    return BunnyDNS(access_key=access_key, base_url=base_url)


@pytest.fixture
def mocked_responses():
    """Activate the responses mock and yield it for adding responses."""
    with responses.RequestsMock() as rsps:
        yield rsps


# ---------------------------------------------------------------------------
# Reusable sample data
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_record_data() -> dict:
    return {
        "Id": 101,
        "Type": 0,
        "Ttl": 300,
        "Value": "1.2.3.4",
        "Name": "www",
        "Weight": 0,
        "Priority": 0,
        "Port": 0,
        "Flags": 0,
        "Tag": None,
        "Accelerated": False,
        "AcceleratedPullZoneId": 0,
        "LinkName": None,
        "IPGeoLocationInfo": None,
        "GeolocationInfo": None,
        "MonitorStatus": 0,
        "MonitorType": 0,
        "GeolocationLatitude": 0.0,
        "GeolocationLongitude": 0.0,
        "EnviromentalVariables": None,
        "LatencyZone": None,
        "SmartRoutingType": 0,
        "Disabled": False,
        "Comment": "Test record",
        "AutoSslIssuance": False,
        "AccelerationStatus": 0,
    }


@pytest.fixture
def sample_record_data_full() -> dict:
    return {
        "Id": 202,
        "Type": 0,
        "Ttl": 60,
        "Value": "5.6.7.8",
        "Name": "api",
        "Weight": 100,
        "Priority": 10,
        "Port": 8080,
        "Flags": 128,
        "Tag": "issue",
        "Accelerated": True,
        "AcceleratedPullZoneId": 999,
        "LinkName": "my-link",
        "IPGeoLocationInfo": {
            "ASN": 13335,
            "CountryCode": "US",
            "Country": "United States",
            "OrganizationName": "Cloudflare Inc",
            "City": "San Francisco",
        },
        "GeolocationInfo": {
            "Latitude": 37.7749,
            "Longitude": -122.4194,
            "Country": "United States",
            "City": "San Francisco",
        },
        "MonitorStatus": 1,
        "MonitorType": 2,
        "GeolocationLatitude": 37.7749,
        "GeolocationLongitude": -122.4194,
        "EnviromentalVariables": [
            {"Name": "ENV_KEY", "Value": "env_value"},
            {"Name": "ANOTHER", "Value": "val2"},
        ],
        "LatencyZone": "europe",
        "SmartRoutingType": 1,
        "Disabled": False,
        "Comment": "Full record",
        "AutoSslIssuance": True,
        "AccelerationStatus": 3,
    }


@pytest.fixture
def sample_zone_data(sample_record_data: dict) -> dict:
    return {
        "Id": 12345,
        "Domain": "example.com",
        "Records": [sample_record_data],
        "DateModified": "2024-01-15T10:30:00Z",
        "DateCreated": "2024-01-01T00:00:00Z",
        "NameserversDetected": True,
        "CustomNameserversEnabled": False,
        "Nameserver1": "ns1.bunny.net",
        "Nameserver2": "ns2.bunny.net",
        "SoaEmail": "admin@example.com",
        "NameserversNextCheck": "2024-01-16T10:30:00Z",
        "LoggingEnabled": True,
        "LoggingIPAnonymizationEnabled": True,
        "LogAnonymizationType": 0,
        "DnsSecEnabled": False,
        "CertificateKeyType": 0,
    }


@pytest.fixture
def sample_zone_list_data(sample_zone_data: dict) -> dict:
    return {
        "CurrentPage": 1,
        "TotalItems": 1,
        "HasMoreItems": False,
        "Items": [sample_zone_data],
    }


@pytest.fixture
def sample_dnssec_data() -> dict:
    return {
        "Enabled": True,
        "DsRecord": "example.com. 3600 IN DS 12345 13 2 ABCDEF...",
        "Digest": "ABCDEF1234567890",
        "DigestType": "SHA-256",
        "Algorithm": 13,
        "PublicKey": "BASE64PUBLICKEY==",
        "KeyTag": 12345,
        "Flags": 257,
        "DsConfigured": False,
    }


@pytest.fixture
def sample_import_result_data() -> dict:
    return {
        "RecordsSuccessful": 10,
        "RecordsFailed": 2,
        "RecordsSkipped": 1,
    }
