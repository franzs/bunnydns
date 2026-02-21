"""Tests for enum parsing and conversion."""

import pytest

from bunnydns._helpers import _enum_to_int, _parse_enum
from bunnydns.enums import (
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
# _parse_enum
# ---------------------------------------------------------------------------
class TestParseEnum:
    """Tests for the _parse_enum helper."""

    def test_none_returns_none(self):
        assert _parse_enum(RecordType, None) is None

    def test_string_value_match(self):
        assert _parse_enum(RecordType, "A") == RecordType.A
        assert _parse_enum(RecordType, "AAAA") == RecordType.AAAA
        assert _parse_enum(RecordType, "CNAME") == RecordType.CNAME

    def test_string_name_match_case_insensitive(self):
        assert _parse_enum(RecordType, "redirect") == RecordType.REDIRECT

    def test_integer_with_map(self):
        assert _parse_enum(RecordType, 0, RECORD_TYPE_BY_INT) == RecordType.A
        assert _parse_enum(RecordType, 4, RECORD_TYPE_BY_INT) == RecordType.MX
        assert _parse_enum(RecordType, 15, RECORD_TYPE_BY_INT) == RecordType.TLSA

    def test_integer_without_map_raises(self):
        with pytest.raises(ValueError, match="Unknown integer 0"):
            _parse_enum(RecordType, 0)

    def test_unknown_integer_raises(self):
        with pytest.raises(ValueError, match="Unknown integer 99"):
            _parse_enum(RecordType, 99, RECORD_TYPE_BY_INT)

    def test_unknown_string_raises(self):
        with pytest.raises(ValueError, match="Unknown value 'BOGUS'"):
            _parse_enum(RecordType, "BOGUS")

    def test_unsupported_type_raises(self):
        with pytest.raises(TypeError, match="Cannot convert"):
            _parse_enum(RecordType, [1, 2, 3])


class TestParseEnumRecordType:
    """Test all RecordType integer mappings."""

    @pytest.mark.parametrize(
        "int_val, expected",
        [
            (0, RecordType.A),
            (1, RecordType.AAAA),
            (2, RecordType.CNAME),
            (3, RecordType.TXT),
            (4, RecordType.MX),
            (5, RecordType.REDIRECT),
            (6, RecordType.FLATTEN),
            (7, RecordType.PULLZONE),
            (8, RecordType.SRV),
            (9, RecordType.CAA),
            (10, RecordType.PTR),
            (11, RecordType.SCRIPT),
            (12, RecordType.NS),
            (13, RecordType.SVCB),
            (14, RecordType.HTTPS),
            (15, RecordType.TLSA),
        ],
    )
    def test_record_type_from_int(self, int_val, expected):
        assert _parse_enum(RecordType, int_val, RECORD_TYPE_BY_INT) == expected


class TestParseEnumMonitorStatus:
    @pytest.mark.parametrize(
        "int_val, expected",
        [
            (0, MonitorStatus.UNKNOWN),
            (1, MonitorStatus.ONLINE),
            (2, MonitorStatus.OFFLINE),
        ],
    )
    def test_from_int(self, int_val, expected):
        assert _parse_enum(MonitorStatus, int_val, MONITOR_STATUS_BY_INT) == expected

    @pytest.mark.parametrize("str_val", ["Unknown", "Online", "Offline"])
    def test_from_string(self, str_val):
        result = _parse_enum(MonitorStatus, str_val, MONITOR_STATUS_BY_INT)
        assert result is not None
        assert result.value == str_val


class TestParseEnumMonitorType:
    @pytest.mark.parametrize(
        "int_val, expected",
        [
            (0, MonitorType.NONE),
            (1, MonitorType.PING),
            (2, MonitorType.HTTP),
            (3, MonitorType.MONITOR),
        ],
    )
    def test_from_int(self, int_val, expected):
        assert _parse_enum(MonitorType, int_val, MONITOR_TYPE_BY_INT) == expected


class TestParseEnumSmartRoutingType:
    @pytest.mark.parametrize(
        "int_val, expected",
        [
            (0, SmartRoutingType.NONE),
            (1, SmartRoutingType.LATENCY),
            (2, SmartRoutingType.GEOLOCATION),
        ],
    )
    def test_from_int(self, int_val, expected):
        assert _parse_enum(SmartRoutingType, int_val, SMART_ROUTING_TYPE_BY_INT) == expected


class TestParseEnumAccelerationStatus:
    @pytest.mark.parametrize(
        "int_val, expected",
        [
            (0, AccelerationStatus.NONE),
            (1, AccelerationStatus.PENDING),
            (2, AccelerationStatus.PROCESSING),
            (3, AccelerationStatus.COMPLETED),
            (4, AccelerationStatus.FAILED),
        ],
    )
    def test_from_int(self, int_val, expected):
        assert _parse_enum(AccelerationStatus, int_val, ACCELERATION_STATUS_BY_INT) == expected


class TestParseEnumLogAnonymizationType:
    @pytest.mark.parametrize(
        "int_val, expected",
        [
            (0, LogAnonymizationType.ONE_DIGIT),
            (1, LogAnonymizationType.DROP),
        ],
    )
    def test_from_int(self, int_val, expected):
        assert (
            _parse_enum(LogAnonymizationType, int_val, LOG_ANONYMIZATION_TYPE_BY_INT) == expected
        )


class TestParseEnumCertificateKeyType:
    @pytest.mark.parametrize(
        "int_val, expected",
        [
            (0, CertificateKeyType.ECDSA),
            (1, CertificateKeyType.RSA),
        ],
    )
    def test_from_int(self, int_val, expected):
        assert _parse_enum(CertificateKeyType, int_val, CERTIFICATE_KEY_TYPE_BY_INT) == expected


# ---------------------------------------------------------------------------
# _enum_to_int
# ---------------------------------------------------------------------------
class TestEnumToInt:
    """Tests for the _enum_to_int helper."""

    def test_record_type_round_trip(self):
        for int_val, member in RECORD_TYPE_BY_INT.items():
            assert _enum_to_int(member, RECORD_TYPE_BY_INT) == int_val

    def test_monitor_type_round_trip(self):
        for int_val, member in MONITOR_TYPE_BY_INT.items():
            assert _enum_to_int(member, MONITOR_TYPE_BY_INT) == int_val

    def test_smart_routing_type_round_trip(self):
        for int_val, member in SMART_ROUTING_TYPE_BY_INT.items():
            assert _enum_to_int(member, SMART_ROUTING_TYPE_BY_INT) == int_val

    def test_log_anonymization_type_round_trip(self):
        for int_val, member in LOG_ANONYMIZATION_TYPE_BY_INT.items():
            assert _enum_to_int(member, LOG_ANONYMIZATION_TYPE_BY_INT) == int_val

    def test_certificate_key_type_round_trip(self):
        for int_val, member in CERTIFICATE_KEY_TYPE_BY_INT.items():
            assert _enum_to_int(member, CERTIFICATE_KEY_TYPE_BY_INT) == int_val

    def test_wrong_map_raises(self):
        with pytest.raises(ValueError, match="No integer mapping found"):
            _enum_to_int(RecordType.A, MONITOR_TYPE_BY_INT)
