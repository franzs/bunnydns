"""Enumerations used across the Bunny DNS API."""

from __future__ import annotations

import enum


class RecordType(enum.Enum):
    """DNS record type."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    TXT = "TXT"
    MX = "MX"
    REDIRECT = "Redirect"
    FLATTEN = "Flatten"
    PULLZONE = "PullZone"
    SRV = "SRV"
    CAA = "CAA"
    PTR = "PTR"
    SCRIPT = "Script"
    NS = "NS"
    SVCB = "SVCB"
    HTTPS = "HTTPS"
    TLSA = "TLSA"


RECORD_TYPE_BY_INT: dict[int, RecordType] = {
    0: RecordType.A,
    1: RecordType.AAAA,
    2: RecordType.CNAME,
    3: RecordType.TXT,
    4: RecordType.MX,
    5: RecordType.REDIRECT,
    6: RecordType.FLATTEN,
    7: RecordType.PULLZONE,
    8: RecordType.SRV,
    9: RecordType.CAA,
    10: RecordType.PTR,
    11: RecordType.SCRIPT,
    12: RecordType.NS,
    13: RecordType.SVCB,
    14: RecordType.HTTPS,
    15: RecordType.TLSA,
}


class MonitorStatus(enum.Enum):
    """Health-monitor status of a DNS record."""

    UNKNOWN = "Unknown"
    ONLINE = "Online"
    OFFLINE = "Offline"


MONITOR_STATUS_BY_INT: dict[int, MonitorStatus] = {
    0: MonitorStatus.UNKNOWN,
    1: MonitorStatus.ONLINE,
    2: MonitorStatus.OFFLINE,
}


class MonitorType(enum.Enum):
    """Health-monitor type of a DNS record."""

    NONE = "None"
    PING = "Ping"
    HTTP = "Http"
    MONITOR = "Monitor"


MONITOR_TYPE_BY_INT: dict[int, MonitorType] = {
    0: MonitorType.NONE,
    1: MonitorType.PING,
    2: MonitorType.HTTP,
    3: MonitorType.MONITOR,
}


class SmartRoutingType(enum.Enum):
    """Smart routing mode for a DNS record."""

    NONE = "None"
    LATENCY = "Latency"
    GEOLOCATION = "Geolocation"


SMART_ROUTING_TYPE_BY_INT: dict[int, SmartRoutingType] = {
    0: SmartRoutingType.NONE,
    1: SmartRoutingType.LATENCY,
    2: SmartRoutingType.GEOLOCATION,
}


class AccelerationStatus(enum.Enum):
    """Acceleration status of a DNS record."""

    NONE = "None"
    PENDING = "Pending"
    PROCESSING = "Processing"
    COMPLETED = "Completed"
    FAILED = "Failed"


ACCELERATION_STATUS_BY_INT: dict[int, AccelerationStatus] = {
    0: AccelerationStatus.NONE,
    1: AccelerationStatus.PENDING,
    2: AccelerationStatus.PROCESSING,
    3: AccelerationStatus.COMPLETED,
    4: AccelerationStatus.FAILED,
}


class LogAnonymizationType(enum.Enum):
    """Log anonymization mode for a DNS zone."""

    ONE_DIGIT = "OneDigit"
    DROP = "Drop"


LOG_ANONYMIZATION_TYPE_BY_INT: dict[int, LogAnonymizationType] = {
    0: LogAnonymizationType.ONE_DIGIT,
    1: LogAnonymizationType.DROP,
}


class CertificateKeyType(enum.Enum):
    """Private-key type used for automatic TLS certificates."""

    ECDSA = "Ecdsa"
    RSA = "Rsa"


CERTIFICATE_KEY_TYPE_BY_INT: dict[int, CertificateKeyType] = {
    0: CertificateKeyType.ECDSA,
    1: CertificateKeyType.RSA,
}
