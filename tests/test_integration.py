"""Integration tests against the live Bunny DNS API.

These tests require a valid Bunny.net API access key set via the
environment variable ``BUNNY_API_KEY``.

Run with:
    BUNNY_API_KEY=your-key pytest tests/test_integration.py -v

To also run the DNSSEC tests (slower, may affect live zones):
    BUNNY_API_KEY=your-key BUNNY_TEST_DNSSEC=1 pytest tests/test_integration.py -v

A temporary DNS zone will be created and cleaned up automatically.
"""

import os
import time
import uuid

import pytest

from bunnydns import (
    BunnyDNS,
    BunnyDNSAPIError,
    BunnyDNSAuthenticationError,
    BunnyDNSNotFoundError,
    CertificateKeyType,
    DnsRecordInput,
    DnsSecDsRecord,
    LogAnonymizationType,
    RecordType,
)
from bunnydns.models import (
    DnsRecord,
    DnsZone,
    DnsZoneImportResult,
    DnsZoneList,
)

# ---------------------------------------------------------------------------
# Markers & fixtures
# ---------------------------------------------------------------------------

BUNNY_API_KEY = os.environ.get("BUNNY_API_KEY")
BUNNY_TEST_DNSSEC = os.environ.get("BUNNY_TEST_DNSSEC", "").lower() in ("1", "true", "yes")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not BUNNY_API_KEY,
        reason="BUNNY_API_KEY environment variable not set",
    ),
]


def _unique_domain() -> str:
    """Generate a unique throwaway domain for testing."""
    uid = uuid.uuid4().hex[:12]
    return f"test-{uid}.example-bunnydns-test.com"


@pytest.fixture(scope="module")
def client() -> BunnyDNS:
    """Create a shared client for the entire test module."""
    assert BUNNY_API_KEY is not None
    return BunnyDNS(access_key=BUNNY_API_KEY)


@pytest.fixture(scope="module")
def test_zone(client: BunnyDNS):
    """Create a temporary DNS zone for testing and clean up afterwards.

    This fixture is module-scoped so the zone is reused across all tests
    in this file, keeping API calls to a minimum.
    """
    domain = _unique_domain()
    zone = client.add_dns_zone(domain=domain)
    yield zone
    # Teardown: delete the zone
    try:
        client.delete_dns_zone(zone_id=zone.id)
    except BunnyDNSAPIError:
        pass  # Best effort cleanup


# ---------------------------------------------------------------------------
# Zone listing
# ---------------------------------------------------------------------------
class TestListDnsZonesIntegration:
    def test_list_returns_zone_list(self, client: BunnyDNS):
        result = client.list_dns_zones()
        assert isinstance(result, DnsZoneList)
        assert isinstance(result.current_page, int)
        assert isinstance(result.total_items, int)
        assert isinstance(result.has_more_items, bool)
        assert isinstance(result.items, list)

    def test_list_with_pagination(self, client: BunnyDNS):
        result = client.list_dns_zones(page=1, per_page=5)
        assert result.current_page == 1
        assert len(result.items) <= 5

    def test_list_with_search(self, client: BunnyDNS, test_zone: DnsZone):
        result = client.list_dns_zones(search=test_zone.domain)
        assert result.total_items >= 1
        domains = [z.domain for z in result.items]
        assert test_zone.domain in domains

    def test_list_search_no_results(self, client: BunnyDNS):
        result = client.list_dns_zones(search="this-domain-should-not-exist-xyz123.com")
        assert result.total_items == 0
        assert result.items == []


# ---------------------------------------------------------------------------
# Zone creation & retrieval
# ---------------------------------------------------------------------------
class TestZoneLifecycleIntegration:
    def test_created_zone_has_expected_fields(self, test_zone: DnsZone):
        assert isinstance(test_zone, DnsZone)
        assert test_zone.id > 0
        assert test_zone.domain is not None
        assert test_zone.date_created is not None
        assert test_zone.date_modified is not None
        assert test_zone.nameservers_next_check is not None
        assert isinstance(test_zone.nameservers_detected, bool)
        assert isinstance(test_zone.custom_nameservers_enabled, bool)
        assert isinstance(test_zone.logging_enabled, bool)
        assert isinstance(test_zone.logging_ip_anonymization_enabled, bool)
        assert isinstance(test_zone.dns_sec_enabled, bool)

    def test_get_zone_by_id(self, client: BunnyDNS, test_zone: DnsZone):
        zone = client.get_dns_zone(zone_id=test_zone.id)
        assert zone.id == test_zone.id
        assert zone.domain == test_zone.domain

    def test_get_zone_returns_enums(self, client: BunnyDNS, test_zone: DnsZone):
        zone = client.get_dns_zone(zone_id=test_zone.id)
        # These should parse without error
        if zone.log_anonymization_type is not None:
            assert isinstance(zone.log_anonymization_type, LogAnonymizationType)
        if zone.certificate_key_type is not None:
            assert isinstance(zone.certificate_key_type, CertificateKeyType)

    def test_get_nonexistent_zone_raises(self, client: BunnyDNS):
        with pytest.raises(BunnyDNSNotFoundError):
            client.get_dns_zone(zone_id=999999999)


# ---------------------------------------------------------------------------
# Zone update
# ---------------------------------------------------------------------------
class TestUpdateZoneIntegration:
    def test_update_soa_email(self, client: BunnyDNS, test_zone: DnsZone):
        updated = client.update_dns_zone(
            zone_id=test_zone.id,
            soa_email="test@example.com",
        )
        assert updated.soa_email == "test@example.com"

    def test_update_logging(self, client: BunnyDNS, test_zone: DnsZone):
        updated = client.update_dns_zone(
            zone_id=test_zone.id,
            logging_enabled=True,
            logging_ip_anonymization_enabled=True,
            log_anonymization_type=LogAnonymizationType.DROP,
        )
        assert updated.logging_enabled is True
        assert updated.logging_ip_anonymization_enabled is True
        assert updated.log_anonymization_type == LogAnonymizationType.DROP

        # Reset
        client.update_dns_zone(
            zone_id=test_zone.id,
            logging_enabled=False,
            logging_ip_anonymization_enabled=True,
            log_anonymization_type=LogAnonymizationType.ONE_DIGIT,
        )

    def test_update_certificate_key_type(self, client: BunnyDNS, test_zone: DnsZone):
        updated = client.update_dns_zone(
            zone_id=test_zone.id,
            certificate_key_type=CertificateKeyType.RSA,
        )
        assert updated.certificate_key_type == CertificateKeyType.RSA

        # Reset
        client.update_dns_zone(
            zone_id=test_zone.id,
            certificate_key_type=CertificateKeyType.ECDSA,
        )


# ---------------------------------------------------------------------------
# Zone availability
# ---------------------------------------------------------------------------
class TestCheckAvailabilityIntegration:
    def test_existing_zone_not_available(self, client: BunnyDNS, test_zone: DnsZone):
        assert test_zone.domain is not None
        available = client.check_dns_zone_availability(test_zone.domain)
        assert available is False

    def test_random_domain_available(self, client: BunnyDNS):
        domain = _unique_domain()
        available = client.check_dns_zone_availability(domain)
        assert available is True


# ---------------------------------------------------------------------------
# DNS Records CRUD
# ---------------------------------------------------------------------------
class TestDnsRecordLifecycleIntegration:
    """Test the full lifecycle: add → read → update → delete."""

    def test_add_a_record(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.A,
                name="test-a",
                value="192.0.2.1",
                ttl=300,
            ),
        )
        assert isinstance(record, DnsRecord)
        assert record.id > 0
        assert record.type == RecordType.A
        assert record.value == "192.0.2.1"
        assert record.name == "test-a"
        assert record.ttl == 300

        # Cleanup
        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_add_aaaa_record(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.AAAA,
                name="test-aaaa",
                value="2001:db8::1",
                ttl=300,
            ),
        )
        assert record.type == RecordType.AAAA
        assert record.value == "2001:db8::1"

        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_add_cname_record(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.CNAME,
                name="test-cname",
                value="example.com",
                ttl=3600,
            ),
        )
        assert record.type == RecordType.CNAME

        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_add_mx_record(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.MX,
                name="",
                value="mail.example.com",
                ttl=3600,
                priority=10,
            ),
        )
        assert record.type == RecordType.MX
        assert record.priority == 10

        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_add_txt_record(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.TXT,
                name="",
                value="v=spf1 include:example.com ~all",
                ttl=3600,
            ),
        )
        assert record.type == RecordType.TXT

        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_add_caa_record(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.CAA,
                name="",
                value="letsencrypt.org",
                ttl=3600,
                flags=0,
                tag="issue",
            ),
        )
        assert record.type == RecordType.CAA

        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_add_record_with_comment(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.A,
                name="test-comment",
                value="192.0.2.2",
                ttl=300,
                comment="Integration test record",
            ),
        )
        assert record.comment == "Integration test record"

        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_add_disabled_record(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.A,
                name="test-disabled",
                value="192.0.2.3",
                ttl=300,
                disabled=True,
            ),
        )
        assert record.disabled is True

        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_update_record(self, client: BunnyDNS, test_zone: DnsZone):
        # Create
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.A,
                name="test-update",
                value="192.0.2.10",
                ttl=300,
            ),
        )

        # Update
        client.update_dns_record(
            zone_id=test_zone.id,
            record_id=record.id,
            record=DnsRecordInput(
                value="192.0.2.20",
                ttl=600,
                comment="Updated via integration test",
            ),
        )

        # Verify by re-fetching the zone
        zone = client.get_dns_zone(zone_id=test_zone.id)
        updated_record = next((r for r in zone.records if r.id == record.id), None)
        assert updated_record is not None
        assert updated_record.value == "192.0.2.20"
        assert updated_record.ttl == 600
        assert updated_record.comment == "Updated via integration test"

        # Cleanup
        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_delete_record(self, client: BunnyDNS, test_zone: DnsZone):
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.A,
                name="test-delete",
                value="192.0.2.99",
                ttl=300,
            ),
        )

        # Delete
        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

        # Verify it's gone
        zone = client.get_dns_zone(zone_id=test_zone.id)
        found = any(r.id == record.id for r in zone.records)
        assert found is False

    def test_delete_nonexistent_record_raises(self, client: BunnyDNS, test_zone: DnsZone):
        with pytest.raises((BunnyDNSNotFoundError, BunnyDNSAPIError)):
            client.delete_dns_record(zone_id=test_zone.id, record_id=999999999)

    def test_records_visible_in_zone(self, client: BunnyDNS, test_zone: DnsZone):
        """Add multiple records and verify they appear when fetching the zone."""
        record_ids = []
        for i in range(3):
            record = client.add_dns_record(
                zone_id=test_zone.id,
                record=DnsRecordInput(
                    type=RecordType.A,
                    name=f"test-multi-{i}",
                    value=f"192.0.2.{10 + i}",
                    ttl=300,
                ),
            )
            record_ids.append(record.id)

        zone = client.get_dns_zone(zone_id=test_zone.id)
        zone_record_ids = {r.id for r in zone.records}
        for rid in record_ids:
            assert rid in zone_record_ids

        # Cleanup
        for rid in record_ids:
            client.delete_dns_record(zone_id=test_zone.id, record_id=rid)


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------
class TestExportImportIntegration:
    def test_export_zone(self, client: BunnyDNS, test_zone: DnsZone):
        # Add a record so the export has content
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.A,
                name="test-export",
                value="192.0.2.50",
                ttl=300,
            ),
        )

        zone_file = client.export_dns_zone(zone_id=test_zone.id)
        assert isinstance(zone_file, str)
        assert len(zone_file) > 0
        # The zone file should contain the domain or record data
        assert "192.0.2.50" in zone_file

        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_import_records(self, client: BunnyDNS, test_zone: DnsZone):
        assert test_zone.domain is not None

        zone_file = (
            f"test-import1.{test_zone.domain}. 300 IN A 192.0.2.60\n"
            f"test-import2.{test_zone.domain}. 300 IN A 192.0.2.61\n"
        )

        result = client.import_dns_records(zone_id=test_zone.id, zone_file=zone_file)
        assert isinstance(result, DnsZoneImportResult)
        assert isinstance(result.records_successful, int)
        assert isinstance(result.records_failed, int)
        assert isinstance(result.records_skipped, int)
        assert result.records_successful >= 0

        # Cleanup imported records
        zone = client.get_dns_zone(zone_id=test_zone.id)
        for record in zone.records:
            if record.name and record.name.startswith("test-import"):
                client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

    def test_export_import_round_trip(self, client: BunnyDNS, test_zone: DnsZone):
        """Export a zone, then import it back and verify no failures."""
        # Add a known record
        record = client.add_dns_record(
            zone_id=test_zone.id,
            record=DnsRecordInput(
                type=RecordType.A,
                name="test-roundtrip",
                value="192.0.2.70",
                ttl=300,
            ),
        )

        # Export
        zone_file = client.export_dns_zone(zone_id=test_zone.id)
        assert len(zone_file) > 0

        # Clean up the record before importing
        client.delete_dns_record(zone_id=test_zone.id, record_id=record.id)

        # Import
        result = client.import_dns_records(zone_id=test_zone.id, zone_file=zone_file)
        assert result.records_failed == 0

        # Cleanup
        zone = client.get_dns_zone(zone_id=test_zone.id)
        for rec in zone.records:
            if rec.name and rec.name == "test-roundtrip":
                client.delete_dns_record(zone_id=test_zone.id, record_id=rec.id)


# ---------------------------------------------------------------------------
# DNSSEC
# ---------------------------------------------------------------------------
class TestDnssecIntegration:
    """DNSSEC tests are opt-in via BUNNY_TEST_DNSSEC=1."""

    pytestmark = pytest.mark.skipif(
        not BUNNY_TEST_DNSSEC,
        reason="BUNNY_TEST_DNSSEC environment variable not set",
    )

    def test_enable_dnssec(self, client: BunnyDNS, test_zone: DnsZone):
        ds = client.enable_dnssec(zone_id=test_zone.id)
        assert isinstance(ds, DnsSecDsRecord)
        assert ds.enabled is True
        assert ds.algorithm > 0
        assert ds.key_tag >= 0
        assert isinstance(ds.flags, int)
        assert isinstance(ds.ds_configured, bool)

    def test_enable_dnssec_returns_ds_record(self, client: BunnyDNS, test_zone: DnsZone):
        ds = client.enable_dnssec(zone_id=test_zone.id)
        # After enabling, we should get DS record information
        if ds.ds_record is not None:
            assert isinstance(ds.ds_record, str)
            assert len(ds.ds_record) > 0
        if ds.digest is not None:
            assert isinstance(ds.digest, str)
        if ds.public_key is not None:
            assert isinstance(ds.public_key, str)

    def test_disable_dnssec(self, client: BunnyDNS, test_zone: DnsZone):
        # Ensure enabled first
        client.enable_dnssec(zone_id=test_zone.id)
        time.sleep(1)  # Brief pause to let the API process

        ds = client.disable_dnssec(zone_id=test_zone.id)
        assert isinstance(ds, DnsSecDsRecord)
        assert ds.enabled is False

    def test_dnssec_reflected_in_zone(self, client: BunnyDNS, test_zone: DnsZone):
        # Enable
        client.enable_dnssec(zone_id=test_zone.id)
        time.sleep(1)
        zone = client.get_dns_zone(zone_id=test_zone.id)
        assert zone.dns_sec_enabled is True

        # Disable
        client.disable_dnssec(zone_id=test_zone.id)
        time.sleep(1)
        zone = client.get_dns_zone(zone_id=test_zone.id)
        assert zone.dns_sec_enabled is False


# ---------------------------------------------------------------------------
# Zone create & delete (standalone)
# ---------------------------------------------------------------------------
class TestZoneCreateDeleteIntegration:
    """Test creating and deleting a zone independently of the shared fixture."""

    def test_create_and_delete_zone(self, client: BunnyDNS):
        domain = _unique_domain()

        # Create
        zone = client.add_dns_zone(domain=domain)
        assert zone.id > 0
        assert zone.domain == domain

        # Verify exists
        fetched = client.get_dns_zone(zone_id=zone.id)
        assert fetched.id == zone.id

        # Delete
        client.delete_dns_zone(zone_id=zone.id)

        # Verify deleted
        with pytest.raises(BunnyDNSNotFoundError):
            client.get_dns_zone(zone_id=zone.id)

    def test_create_zone_with_initial_records(self, client: BunnyDNS):
        domain = _unique_domain()
        zone = client.add_dns_zone(
            domain=domain,
            records=[
                DnsRecordInput(
                    type=RecordType.A,
                    name="www",
                    value="192.0.2.1",
                    ttl=300,
                ),
                DnsRecordInput(
                    type=RecordType.TXT,
                    name="",
                    value="v=spf1 -all",
                    ttl=3600,
                ),
            ],
        )
        assert zone.id > 0

        # Verify records were created
        fetched = client.get_dns_zone(zone_id=zone.id)
        record_types = [r.type for r in fetched.records]
        assert RecordType.A in record_types
        assert RecordType.TXT in record_types

        # Cleanup
        client.delete_dns_zone(zone_id=zone.id)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
class TestAuthenticationIntegration:
    def test_invalid_key_raises(self):
        bad_client = BunnyDNS(access_key="invalid-key-12345")
        with pytest.raises(BunnyDNSAuthenticationError):
            bad_client.list_dns_zones()
