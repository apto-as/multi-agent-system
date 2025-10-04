"""
Datetime Utilities for TMWS
Centralized datetime handling to avoid duplication
"""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """
    Get current UTC datetime.

    Returns:
        Current datetime in UTC timezone
    """
    return datetime.now(timezone.utc)


def to_iso_string(dt: datetime | None) -> str | None:
    """
    Convert datetime to ISO format string.

    Args:
        dt: Datetime to convert

    Returns:
        ISO format string or None if input is None
    """
    if dt is None:
        return None
    return dt.isoformat()


def from_iso_string(iso_string: str | None) -> datetime | None:
    """
    Parse ISO format string to datetime.

    Args:
        iso_string: ISO format datetime string

    Returns:
        Parsed datetime or None if input is None
    """
    if not iso_string:
        return None
    try:
        return datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
    except ValueError:
        return None


def ensure_utc(dt: datetime) -> datetime:
    """
    Ensure datetime has UTC timezone.

    Args:
        dt: Datetime to normalize

    Returns:
        Datetime with UTC timezone
    """
    if dt.tzinfo is None:
        # Assume naive datetime is UTC
        return dt.replace(tzinfo=timezone.utc)
    elif dt.tzinfo != timezone.utc:
        # Convert to UTC
        return dt.astimezone(timezone.utc)
    return dt


def timestamp_to_datetime(timestamp: int | float) -> datetime:
    """
    Convert Unix timestamp to UTC datetime.

    Args:
        timestamp: Unix timestamp

    Returns:
        UTC datetime
    """
    return datetime.fromtimestamp(timestamp, timezone.utc)


def datetime_to_timestamp(dt: datetime) -> float:
    """
    Convert datetime to Unix timestamp.

    Args:
        dt: Datetime to convert

    Returns:
        Unix timestamp as float
    """
    return dt.timestamp()


def format_datetime(dt: datetime | None, format_str: str = "%Y-%m-%d %H:%M:%S UTC") -> str | None:
    """
    Format datetime to string.

    Args:
        dt: Datetime to format
        format_str: Format string

    Returns:
        Formatted string or None if input is None
    """
    if dt is None:
        return None

    # Ensure UTC for consistent formatting
    utc_dt = ensure_utc(dt)
    return utc_dt.strftime(format_str)


def is_recent(dt: datetime, minutes: int = 5) -> bool:
    """
    Check if datetime is within recent minutes from now.

    Args:
        dt: Datetime to check
        minutes: Minutes threshold

    Returns:
        True if datetime is recent
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    diff = utc_now() - dt
    return diff.total_seconds() <= (minutes * 60)


def days_ago(days: int) -> datetime:
    """
    Get datetime N days ago from now.

    Args:
        days: Number of days

    Returns:
        UTC datetime N days ago
    """
    from datetime import timedelta

    return utc_now() - timedelta(days=days)


def hours_ago(hours: int) -> datetime:
    """
    Get datetime N hours ago from now.

    Args:
        hours: Number of hours

    Returns:
        UTC datetime N hours ago
    """
    from datetime import timedelta

    return utc_now() - timedelta(hours=hours)


# Aliases for backward compatibility
now = utc_now
isoformat = to_iso_string
