"""Internal helper functions."""

from __future__ import annotations

import enum
from collections.abc import Mapping
from datetime import datetime
from typing import Any, TypeVar

E = TypeVar("E", bound=enum.Enum)


def _parse_enum(
    enum_cls: type[E],
    value: Any,
    int_map: Mapping[int, E] | None = None,
) -> E | None:
    """Return an *enum_cls* member from a string, int, or ``None``."""
    if value is None:
        return None
    if isinstance(value, int):
        if int_map and value in int_map:
            return int_map[value]
        raise ValueError(f"Unknown integer {value} for {enum_cls.__name__}")
    if isinstance(value, str):
        for member in enum_cls:
            if member.value == value:
                return member
        upper = value.upper()
        for member in enum_cls:
            if member.name == upper:
                return member
        raise ValueError(f"Unknown value '{value}' for {enum_cls.__name__}")
    raise TypeError(f"Cannot convert {type(value)} to {enum_cls.__name__}")


def _enum_to_int(member: enum.Enum, int_map: Mapping[int, enum.Enum]) -> int:
    """Convert an enum member back to its integer representation for API requests."""
    for integer, mapped_member in int_map.items():
        if mapped_member is member:
            return integer
    raise ValueError(f"No integer mapping found for {member!r}")


def _parse_dt(value: Any) -> datetime | None:
    """Parse an ISO-8601 datetime string returned by the Bunny API."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    s: str = value
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s)
