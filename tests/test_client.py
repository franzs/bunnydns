"""Tests for the BunnyDNS client."""

import json

import pytest
import responses

from bunnydns import (
    BunnyDNS,
    BunnyDNSAPIError,
    BunnyDNSAuthenticationError,
    BunnyDNSNotFoundError,
    CertificateKeyType,
    DnsRecordInput,
    LogAnonymizationType,
    RecordType,
)


# ---------------------------------------------------------------------------
# Client initialization
# ---------------------------------------------------------------------------
class TestClientInit:
    def test_default_base_url(self, access_key):
        client = BunnyDNS(access_key=access_key)
        assert client._base_url == "https://api.bunny.net"

    def test_custom_base_url(self, access_key):
        client = BunnyDNS(access_key=access_key, base_url="https://custom.api.net/")
        assert client._base_url == "https://custom.api.net"

    def test_session_headers(self, client, access_key):
        assert client._session.headers["AccessKey"] == access_key
        assert client._session.headers["Accept"] == "application/json"

    def test_custom_timeout(self, access_key):
        client = BunnyDNS(access_key=access_key, timeout=60)
        assert client._timeout == 60


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------
class TestErrorHandling:
    def test_401_raises_authentication_error(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone",
            json={"Message": "Unauthorized"},
            status=401,
        )
        with pytest.raises(BunnyDNSAuthenticationError):
            client.list_dns_zones()

    def test_404_raises_not_found_error(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone/99999",
            json={"Message": "Not Found"},
            status=404,
        )
        with pytest.raises(BunnyDNSNotFoundError):
            client.get_dns_zone(zone_id=99999)

    def test_500_raises_api_error(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone",
            json={"Message": "Internal Server Error"},
            status=500,
        )
        with pytest.raises(BunnyDNSAPIError) as exc_info:
            client.list_dns_zones()
        assert exc_info.value.status_code == 500

    def test_400_raises_api_error(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.PUT,
            f"{base_url}/dnszone/123/records",
            json={"ErrorKey": "validation", "Message": "Invalid record"},
            status=400,
        )
        with pytest.raises(BunnyDNSAPIError) as exc_info:
            client.add_dns_record(
                zone_id=123,
                record=DnsRecordInput(type=RecordType.A, value="invalid"),
            )
        assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# list_dns_zones
# ---------------------------------------------------------------------------
class TestListDnsZones:
    def test_success(self, client, mocked_responses, base_url, sample_zone_list_data):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone",
            json=sample_zone_list_data,
            status=200,
        )
        result = client.list_dns_zones()
        assert result.current_page == 1
        assert result.total_items == 1
        assert len(result.items) == 1
        assert result.items[0].domain == "example.com"

    def test_query_params(self, client, mocked_responses, base_url, sample_zone_list_data):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone",
            json=sample_zone_list_data,
            status=200,
        )
        client.list_dns_zones(page=2, per_page=50, search="example")
        request = mocked_responses.calls[0].request
        assert "page=2" in request.url
        assert "perPage=50" in request.url
        assert "search=example" in request.url

    def test_default_params(self, client, mocked_responses, base_url, sample_zone_list_data):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone",
            json=sample_zone_list_data,
            status=200,
        )
        client.list_dns_zones()
        request = mocked_responses.calls[0].request
        assert "page=1" in request.url
        assert "perPage=1000" in request.url

    def test_per_page_too_low_raises(self, client):
        with pytest.raises(ValueError, match="per_page must be between 5 and 1000"):
            client.list_dns_zones(per_page=4)

    def test_per_page_too_high_raises(self, client):
        with pytest.raises(ValueError, match="per_page must be between 5 and 1000"):
            client.list_dns_zones(per_page=1001)

    def test_per_page_boundary(self, client, mocked_responses, base_url, sample_zone_list_data):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone",
            json=sample_zone_list_data,
            status=200,
        )
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone",
            json=sample_zone_list_data,
            status=200,
        )
        client.list_dns_zones(per_page=5)
        client.list_dns_zones(per_page=1000)


# ---------------------------------------------------------------------------
# add_dns_zone
# ---------------------------------------------------------------------------
class TestAddDnsZone:
    def test_success(self, client, mocked_responses, base_url, sample_zone_data):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone",
            json=sample_zone_data,
            status=201,
        )
        zone = client.add_dns_zone(domain="example.com")
        assert zone.domain == "example.com"
        assert zone.id == 12345

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body["Domain"] == "example.com"

    def test_with_records(self, client, mocked_responses, base_url, sample_zone_data):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone",
            json=sample_zone_data,
            status=201,
        )
        records = [
            DnsRecordInput(type=RecordType.A, name="www", value="1.2.3.4", ttl=300),
        ]
        client.add_dns_zone(domain="example.com", records=records)

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert "Records" in body
        assert len(body["Records"]) == 1
        assert body["Records"][0]["Type"] == 0

    def test_without_records(self, client, mocked_responses, base_url, sample_zone_data):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone",
            json=sample_zone_data,
            status=201,
        )
        client.add_dns_zone(domain="example.com")

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert "Records" not in body


# ---------------------------------------------------------------------------
# get_dns_zone
# ---------------------------------------------------------------------------
class TestGetDnsZone:
    def test_success(self, client, mocked_responses, base_url, sample_zone_data):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone/12345",
            json=sample_zone_data,
            status=200,
        )
        zone = client.get_dns_zone(zone_id=12345)
        assert zone.id == 12345
        assert zone.domain == "example.com"

    def test_not_found(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone/99999",
            status=404,
        )
        with pytest.raises(BunnyDNSNotFoundError):
            client.get_dns_zone(zone_id=99999)


# ---------------------------------------------------------------------------
# update_dns_zone
# ---------------------------------------------------------------------------
class TestUpdateDnsZone:
    def test_success(self, client, mocked_responses, base_url, sample_zone_data):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345",
            json=sample_zone_data,
            status=200,
        )
        zone = client.update_dns_zone(
            zone_id=12345,
            logging_enabled=True,
            soa_email="new@example.com",
        )
        assert zone.id == 12345

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body["LoggingEnabled"] is True
        assert body["SoaEmail"] == "new@example.com"

    def test_only_sends_non_none_fields(
        self, client, mocked_responses, base_url, sample_zone_data
    ):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345",
            json=sample_zone_data,
            status=200,
        )
        client.update_dns_zone(zone_id=12345, soa_email="test@test.com")

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body == {"SoaEmail": "test@test.com"}

    def test_log_anonymization_type_as_int(
        self, client, mocked_responses, base_url, sample_zone_data
    ):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345",
            json=sample_zone_data,
            status=200,
        )
        client.update_dns_zone(
            zone_id=12345,
            log_anonymization_type=LogAnonymizationType.DROP,
        )

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body["LogAnonymizationType"] == 1

    def test_certificate_key_type_as_int(
        self, client, mocked_responses, base_url, sample_zone_data
    ):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345",
            json=sample_zone_data,
            status=200,
        )
        client.update_dns_zone(
            zone_id=12345,
            certificate_key_type=CertificateKeyType.RSA,
        )

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body["CertificateKeyType"] == 1


# ---------------------------------------------------------------------------
# delete_dns_zone
# ---------------------------------------------------------------------------
class TestDeleteDnsZone:
    def test_success(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.DELETE,
            f"{base_url}/dnszone/12345",
            status=204,
        )
        client.delete_dns_zone(zone_id=12345)

    def test_not_found(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.DELETE,
            f"{base_url}/dnszone/99999",
            status=404,
        )
        with pytest.raises(BunnyDNSNotFoundError):
            client.delete_dns_zone(zone_id=99999)


# ---------------------------------------------------------------------------
# export_dns_zone
# ---------------------------------------------------------------------------
class TestExportDnsZone:
    def test_success(self, client, mocked_responses, base_url):
        zone_file = "$ORIGIN example.com.\n@ 300 IN A 1.2.3.4\n"
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone/12345/export",
            body=zone_file,
            status=200,
            content_type="text/plain",
        )
        result = client.export_dns_zone(zone_id=12345)
        assert result == zone_file

    def test_returns_string(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone/12345/export",
            body="zone data",
            status=200,
            content_type="text/plain",
        )
        result = client.export_dns_zone(zone_id=12345)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# check_dns_zone_availability
# ---------------------------------------------------------------------------
class TestCheckDnsZoneAvailability:
    def test_available(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/checkavailability",
            json={"Available": True},
            status=200,
        )
        assert client.check_dns_zone_availability("example.com") is True

    def test_not_available(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/checkavailability",
            json={"Available": False},
            status=200,
        )
        assert client.check_dns_zone_availability("example.com") is False

    def test_request_body(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/checkavailability",
            json={"Available": True},
            status=200,
        )
        client.check_dns_zone_availability("test.org")

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body == {"Name": "test.org"}


# ---------------------------------------------------------------------------
# import_dns_records
# ---------------------------------------------------------------------------
class TestImportDnsRecords:
    def test_success(self, client, mocked_responses, base_url, sample_import_result_data):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345/import",
            json=sample_import_result_data,
            status=200,
        )
        zone_file = "@ 300 IN A 1.2.3.4"
        result = client.import_dns_records(zone_id=12345, zone_file=zone_file)
        assert result.records_successful == 10
        assert result.records_failed == 2
        assert result.records_skipped == 1

    def test_sends_plain_text(self, client, mocked_responses, base_url, sample_import_result_data):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345/import",
            json=sample_import_result_data,
            status=200,
        )
        zone_file = "@ 300 IN A 1.2.3.4\nwww 300 IN CNAME example.com."
        client.import_dns_records(zone_id=12345, zone_file=zone_file)

        request = mocked_responses.calls[0].request
        assert request.body == zone_file
        assert "text/plain" in request.headers.get("Content-Type", "")


# ---------------------------------------------------------------------------
# add_dns_record
# ---------------------------------------------------------------------------
class TestAddDnsRecord:
    def test_success(self, client, mocked_responses, base_url, sample_record_data):
        mocked_responses.add(
            responses.PUT,
            f"{base_url}/dnszone/12345/records",
            json=sample_record_data,
            status=201,
        )
        record = client.add_dns_record(
            zone_id=12345,
            record=DnsRecordInput(type=RecordType.A, name="www", value="1.2.3.4", ttl=300),
        )
        assert record.id == 101
        assert record.value == "1.2.3.4"

    def test_request_body(self, client, mocked_responses, base_url, sample_record_data):
        mocked_responses.add(
            responses.PUT,
            f"{base_url}/dnszone/12345/records",
            json=sample_record_data,
            status=201,
        )
        client.add_dns_record(
            zone_id=12345,
            record=DnsRecordInput(
                type=RecordType.CNAME,
                name="alias",
                value="example.com",
                ttl=3600,
            ),
        )
        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body["Type"] == 2  # CNAME
        assert body["Name"] == "alias"
        assert body["Value"] == "example.com"
        assert body["Ttl"] == 3600


# ---------------------------------------------------------------------------
# update_dns_record
# ---------------------------------------------------------------------------
class TestUpdateDnsRecord:
    def test_success(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345/records/101",
            status=204,
        )
        client.update_dns_record(
            zone_id=12345,
            record_id=101,
            record=DnsRecordInput(value="5.6.7.8", ttl=600),
        )

    def test_auto_sets_id(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345/records/101",
            status=204,
        )
        inp = DnsRecordInput(value="5.6.7.8")
        assert inp.id is None

        client.update_dns_record(zone_id=12345, record_id=101, record=inp)

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body["Id"] == 101
        assert inp.id == 101

    def test_preserves_existing_id(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345/records/101",
            status=204,
        )
        inp = DnsRecordInput(id=101, value="5.6.7.8")
        client.update_dns_record(zone_id=12345, record_id=101, record=inp)

        request = mocked_responses.calls[0].request
        body = json.loads(request.body)
        assert body["Id"] == 101


# ---------------------------------------------------------------------------
# delete_dns_record
# ---------------------------------------------------------------------------
class TestDeleteDnsRecord:
    def test_success(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.DELETE,
            f"{base_url}/dnszone/12345/records/101",
            status=204,
        )
        client.delete_dns_record(zone_id=12345, record_id=101)

    def test_not_found(self, client, mocked_responses, base_url):
        mocked_responses.add(
            responses.DELETE,
            f"{base_url}/dnszone/12345/records/99999",
            status=404,
        )
        with pytest.raises(BunnyDNSNotFoundError):
            client.delete_dns_record(zone_id=12345, record_id=99999)


# ---------------------------------------------------------------------------
# enable_dnssec
# ---------------------------------------------------------------------------
class TestEnableDnssec:
    def test_success(self, client, mocked_responses, base_url, sample_dnssec_data):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345/dnssec",
            json=sample_dnssec_data,
            status=200,
        )
        ds = client.enable_dnssec(zone_id=12345)
        assert ds.enabled is True
        assert ds.algorithm == 13
        assert ds.key_tag == 12345
        assert ds.ds_record is not None

    def test_request_has_no_body(self, client, mocked_responses, base_url, sample_dnssec_data):
        mocked_responses.add(
            responses.POST,
            f"{base_url}/dnszone/12345/dnssec",
            json=sample_dnssec_data,
            status=200,
        )
        client.enable_dnssec(zone_id=12345)

        request = mocked_responses.calls[0].request
        assert request.body is None


# ---------------------------------------------------------------------------
# disable_dnssec
# ---------------------------------------------------------------------------
class TestDisableDnssec:
    def test_success(self, client, mocked_responses, base_url):
        data = {
            "Enabled": False,
            "DsRecord": None,
            "Digest": None,
            "DigestType": None,
            "Algorithm": 0,
            "PublicKey": None,
            "KeyTag": 0,
            "Flags": 0,
            "DsConfigured": False,
        }
        mocked_responses.add(
            responses.DELETE,
            f"{base_url}/dnszone/12345/dnssec",
            json=data,
            status=200,
        )
        ds = client.disable_dnssec(zone_id=12345)
        assert ds.enabled is False
        assert ds.ds_record is None


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------
class TestAuthHeader:
    def test_access_key_sent_in_header(
        self, client, mocked_responses, base_url, access_key, sample_zone_list_data
    ):
        mocked_responses.add(
            responses.GET,
            f"{base_url}/dnszone",
            json=sample_zone_list_data,
            status=200,
        )
        client.list_dns_zones()

        request = mocked_responses.calls[0].request
        assert request.headers["AccessKey"] == access_key
