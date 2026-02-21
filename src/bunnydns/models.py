"""Data models returned by the Bunny DNS API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._helpers import _enum_to_int, _parse_dt, _parse_enum
from .enums import (
    ACCELERATION_STATUS_BY_INT,
    CERTIFICATE_KEY_TYPE_BY_INT,
    LOG_ANONYMIZATION_TYPE_BY_INT,
    MONITOR_STATUS_BY_INT,
    MONITOR_TYPE_BY_INT,
    RECORD_TYPE_BY_INT,
    SMART_ROUTING_TYPE_BY_INT,
    AccelerationStatus,
    CertificateKeyType,
    LogAnonymizationType,
    MonitorStatus,
    MonitorType,
    RecordType,
    SmartRoutingType,
)


# ---------------------------------------------------------------------------
# Nested structures
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class IPGeoLocationInfo:
    """Geolocation / ASN information for an IP address."""

    asn: int
    country_code: str | None = None
    country: str | None = None
    organization_name: str | None = None
    city: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> IPGeoLocationInfo | None:
        if not data:
            return None
        return cls(
            asn=data.get("ASN", 0),
            country_code=data.get("CountryCode"),
            country=data.get("Country"),
            organization_name=data.get("OrganizationName"),
            city=data.get("City"),
        )


@dataclass(frozen=True)
class GeolocationInfo:
    """Latitude / longitude geolocation information."""

    latitude: float
    longitude: float
    country: str | None = None
    city: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> GeolocationInfo | None:
        if not data:
            return None
        return cls(
            latitude=data.get("Latitude", 0.0),
            longitude=data.get("Longitude", 0.0),
            country=data.get("Country"),
            city=data.get("City"),
        )


@dataclass(frozen=True)
class EnvironmentalVariable:
    """Key / value pair attached to a Script record."""

    name: str | None = None
    value: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> EnvironmentalVariable | None:
        if not data:
            return None
        return cls(name=data.get("Name"), value=data.get("Value"))


# ---------------------------------------------------------------------------
# Input model
# ---------------------------------------------------------------------------
@dataclass
class DnsRecordInput:
    """DNS record data used when creating or updating zones/records via the API."""

    id: int | None = None
    type: RecordType | None = None
    ttl: int | None = None
    value: str | None = None
    name: str | None = None
    weight: int | None = None
    priority: int | None = None
    flags: int | None = None
    tag: str | None = None
    port: int | None = None
    pull_zone_id: int | None = None
    script_id: int | None = None
    accelerated: bool | None = None
    monitor_type: MonitorType | None = None
    geolocation_latitude: float | None = None
    geolocation_longitude: float | None = None
    latency_zone: str | None = None
    smart_routing_type: SmartRoutingType | None = None
    disabled: bool | None = None
    environmental_variables: list[EnvironmentalVariable] | None = None
    comment: str | None = None
    auto_ssl_issuance: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict suitable for the Bunny API JSON body.

        Only non-``None`` fields are included.
        """
        data: dict[str, Any] = {}
        if self.id is not None:
            data["Id"] = self.id
        if self.type is not None:
            data["Type"] = _enum_to_int(self.type, RECORD_TYPE_BY_INT)
        if self.ttl is not None:
            data["Ttl"] = self.ttl
        if self.value is not None:
            data["Value"] = self.value
        if self.name is not None:
            data["Name"] = self.name
        if self.weight is not None:
            data["Weight"] = self.weight
        if self.priority is not None:
            data["Priority"] = self.priority
        if self.flags is not None:
            if not 0 <= self.flags <= 255:
                raise ValueError("flags must be between 0 and 255")
            data["Flags"] = self.flags
        if self.tag is not None:
            data["Tag"] = self.tag
        if self.port is not None:
            data["Port"] = self.port
        if self.pull_zone_id is not None:
            data["PullZoneId"] = self.pull_zone_id
        if self.script_id is not None:
            data["ScriptId"] = self.script_id
        if self.accelerated is not None:
            data["Accelerated"] = self.accelerated
        if self.monitor_type is not None:
            data["MonitorType"] = _enum_to_int(self.monitor_type, MONITOR_TYPE_BY_INT)
        if self.geolocation_latitude is not None:
            data["GeolocationLatitude"] = self.geolocation_latitude
        if self.geolocation_longitude is not None:
            data["GeolocationLongitude"] = self.geolocation_longitude
        if self.latency_zone is not None:
            data["LatencyZone"] = self.latency_zone
        if self.smart_routing_type is not None:
            data["SmartRoutingType"] = _enum_to_int(
                self.smart_routing_type, SMART_ROUTING_TYPE_BY_INT
            )
        if self.disabled is not None:
            data["Disabled"] = self.disabled
        if self.environmental_variables is not None:
            data["EnviromentalVariables"] = [
                {"Name": ev.name, "Value": ev.value} for ev in self.environmental_variables
            ]
        if self.comment is not None:
            data["Comment"] = self.comment
        if self.auto_ssl_issuance is not None:
            data["AutoSslIssuance"] = self.auto_ssl_issuance
        return data


# ---------------------------------------------------------------------------
# DNS Record
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DnsRecord:
    """A single DNS record inside a zone."""

    id: int
    ttl: int
    weight: int
    priority: int
    port: int
    accelerated: bool
    accelerated_pull_zone_id: int
    geolocation_latitude: float
    geolocation_longitude: float
    disabled: bool
    auto_ssl_issuance: bool
    type: RecordType | None = None
    value: str | None = None
    name: str | None = None
    flags: int = 0
    tag: str | None = None
    link_name: str | None = None
    ip_geo_location_info: IPGeoLocationInfo | None = None
    geolocation_info: GeolocationInfo | None = None
    monitor_status: MonitorStatus | None = None
    monitor_type: MonitorType | None = None
    environmental_variables: list[EnvironmentalVariable] = field(default_factory=list)
    latency_zone: str | None = None
    smart_routing_type: SmartRoutingType | None = None
    comment: str | None = None
    acceleration_status: AccelerationStatus | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsRecord:
        env_vars_raw = data.get("EnviromentalVariables") or []
        env_vars = [
            ev
            for ev in (EnvironmentalVariable.from_dict(e) for e in env_vars_raw)
            if ev is not None
        ]
        return cls(
            id=data.get("Id", 0),
            ttl=data.get("Ttl", 0),
            weight=data.get("Weight", 0),
            priority=data.get("Priority", 0),
            port=data.get("Port", 0),
            accelerated=data.get("Accelerated", False),
            accelerated_pull_zone_id=data.get("AcceleratedPullZoneId", 0),
            geolocation_latitude=data.get("GeolocationLatitude", 0.0),
            geolocation_longitude=data.get("GeolocationLongitude", 0.0),
            disabled=data.get("Disabled", False),
            auto_ssl_issuance=data.get("AutoSslIssuance", False),
            type=_parse_enum(RecordType, data.get("Type"), RECORD_TYPE_BY_INT),
            value=data.get("Value"),
            name=data.get("Name"),
            flags=data.get("Flags", 0),
            tag=data.get("Tag"),
            link_name=data.get("LinkName"),
            ip_geo_location_info=IPGeoLocationInfo.from_dict(data.get("IPGeoLocationInfo")),
            geolocation_info=GeolocationInfo.from_dict(data.get("GeolocationInfo")),
            monitor_status=_parse_enum(
                MonitorStatus, data.get("MonitorStatus"), MONITOR_STATUS_BY_INT
            ),
            monitor_type=_parse_enum(MonitorType, data.get("MonitorType"), MONITOR_TYPE_BY_INT),
            environmental_variables=env_vars,
            latency_zone=data.get("LatencyZone"),
            smart_routing_type=_parse_enum(
                SmartRoutingType,
                data.get("SmartRoutingType"),
                SMART_ROUTING_TYPE_BY_INT,
            ),
            comment=data.get("Comment"),
            acceleration_status=_parse_enum(
                AccelerationStatus,
                data.get("AccelerationStatus"),
                ACCELERATION_STATUS_BY_INT,
            ),
        )


# ---------------------------------------------------------------------------
# DNS Zone
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DnsZone:
    """Represents a single DNS zone."""

    id: int
    date_modified: datetime | None
    date_created: datetime | None
    nameservers_detected: bool
    custom_nameservers_enabled: bool
    nameservers_next_check: datetime | None
    logging_enabled: bool
    logging_ip_anonymization_enabled: bool
    dns_sec_enabled: bool
    domain: str | None = None
    records: list[DnsRecord] = field(default_factory=list)
    nameserver1: str | None = None
    nameserver2: str | None = None
    soa_email: str | None = None
    log_anonymization_type: LogAnonymizationType | None = None
    certificate_key_type: CertificateKeyType | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsZone:
        records_raw = data.get("Records") or []
        records = [DnsRecord.from_dict(r) for r in records_raw]
        return cls(
            id=data.get("Id", 0),
            date_modified=_parse_dt(data.get("DateModified")),
            date_created=_parse_dt(data.get("DateCreated")),
            nameservers_detected=data.get("NameserversDetected", False),
            custom_nameservers_enabled=data.get("CustomNameserversEnabled", False),
            nameservers_next_check=_parse_dt(data.get("NameserversNextCheck")),
            logging_enabled=data.get("LoggingEnabled", False),
            logging_ip_anonymization_enabled=data.get("LoggingIPAnonymizationEnabled", False),
            dns_sec_enabled=data.get("DnsSecEnabled", False),
            domain=data.get("Domain"),
            records=records,
            nameserver1=data.get("Nameserver1"),
            nameserver2=data.get("Nameserver2"),
            soa_email=data.get("SoaEmail"),
            log_anonymization_type=_parse_enum(
                LogAnonymizationType,
                data.get("LogAnonymizationType"),
                LOG_ANONYMIZATION_TYPE_BY_INT,
            ),
            certificate_key_type=_parse_enum(
                CertificateKeyType,
                data.get("CertificateKeyType"),
                CERTIFICATE_KEY_TYPE_BY_INT,
            ),
        )


# ---------------------------------------------------------------------------
# Paginated list
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DnsZoneList:
    """Paginated list of :class:`DnsZone` objects."""

    current_page: int
    total_items: int
    has_more_items: bool
    items: list[DnsZone] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsZoneList:
        items_raw = data.get("Items") or []
        items = [DnsZone.from_dict(z) for z in items_raw]
        return cls(
            current_page=data.get("CurrentPage", 0),
            total_items=data.get("TotalItems", 0),
            has_more_items=data.get("HasMoreItems", False),
            items=items,
        )


# ---------------------------------------------------------------------------
# Import result
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DnsZoneImportResult:
    """Result of a DNS zone import operation."""

    records_successful: int
    records_failed: int
    records_skipped: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsZoneImportResult:
        return cls(
            records_successful=data.get("RecordsSuccessful", 0),
            records_failed=data.get("RecordsFailed", 0),
            records_skipped=data.get("RecordsSkipped", 0),
        )


# ---------------------------------------------------------------------------
# DNSSEC
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DnsSecDsRecord:
    """DNSSEC DS record information for a DNS zone."""

    enabled: bool
    algorithm: int
    key_tag: int
    flags: int
    ds_configured: bool
    ds_record: str | None = None
    digest: str | None = None
    digest_type: str | None = None
    public_key: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsSecDsRecord:
        return cls(
            enabled=data.get("Enabled", False),
            algorithm=data.get("Algorithm", 0),
            key_tag=data.get("KeyTag", 0),
            flags=data.get("Flags", 0),
            ds_configured=data.get("DsConfigured", False),
            ds_record=data.get("DsRecord"),
            digest=data.get("Digest"),
            digest_type=data.get("DigestType"),
            public_key=data.get("PublicKey"),
        )
