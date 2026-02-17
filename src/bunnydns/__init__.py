"""Bunny DNS API client for Python.

Example
-------
>>> from bunnydns import BunnyDNS
>>> client = BunnyDNS(access_key="your-api-key")
>>> zones = client.list_dns_zones()
"""

from .client import BunnyDNS
from .enums import (
    AccelerationStatus,
    CertificateKeyType,
    LogAnonymizationType,
    MonitorStatus,
    MonitorType,
    RecordType,
    SmartRoutingType,
)
from .exceptions import (
    BunnyDNSAPIError,
    BunnyDNSAuthenticationError,
    BunnyDNSError,
    BunnyDNSNotFoundError,
)
from .models import (
    DnsRecord,
    DnsRecordInput,
    DnsSecDsRecord,
    DnsZone,
    DnsZoneImportResult,
    DnsZoneList,
    EnvironmentalVariable,
    GeolocationInfo,
    IPGeoLocationInfo,
)

__version__ = "0.1.0"

__all__ = [
    # Client
    "BunnyDNS",
    # Models
    "DnsRecord",
    "DnsRecordInput",
    "DnsSecDsRecord",
    "DnsZone",
    "DnsZoneImportResult",
    "DnsZoneList",
    "EnvironmentalVariable",
    "GeolocationInfo",
    "IPGeoLocationInfo",
    # Enums
    "AccelerationStatus",
    "CertificateKeyType",
    "LogAnonymizationType",
    "MonitorStatus",
    "MonitorType",
    "RecordType",
    "SmartRoutingType",
    # Exceptions
    "BunnyDNSAPIError",
    "BunnyDNSAuthenticationError",
    "BunnyDNSError",
    "BunnyDNSNotFoundError",
    # Version
    "__version__",
]
