"""Deterministic timestamp parsing and canonicalisation.

The status-history engine orders events by *effective time* (the ``ts`` field on
a source row) and compares it with *knowledge time* (when the pipeline first
learned about the event).  Both need a single, unambiguous representation:
integer microseconds since the Unix epoch in UTC.

Only well-defined inputs are accepted.  Anything else returns ``None`` so the
caller can record the event as rejected while retaining its original payload.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# A small, explicit set of fallback layouts.  ISO-8601 is handled by
# ``datetime.fromisoformat`` first; these cover the common human formats.
_FALLBACK_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y%m%d",
)


def parse_time(value):
    """Return a timezone-aware UTC ``datetime`` or ``None``.

    ``value`` may be a ``datetime``, ``date``, epoch number, or a string.
    Naive datetimes/timestamps are interpreted as UTC, which is what the
    bundled source produces.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    elif isinstance(value, (int, float)):
        try:
            return _EPOCH + timedelta(seconds=float(value))
        except (OverflowError, ValueError):
            return None
    else:
        text = str(value).strip()
        if not text:
            return None
        candidate = text
        if candidate[-1:] in ("Z", "z"):
            candidate = candidate[:-1] + "+00:00"
        dt = None
        try:
            dt = datetime.fromisoformat(candidate)
        except ValueError:
            for fmt in _FALLBACK_FORMATS:
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    dt = None
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def epoch_us(value):
    """Return integer microseconds since the epoch, or ``None``."""
    dt = parse_time(value)
    if dt is None:
        return None
    delta = dt - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def canonical(value):
    """Return a stable UTC ISO-8601 string (``...Z``) or ``None``."""
    dt = parse_time(value)
    if dt is None:
        return None
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        base += "." + ("%06d" % dt.microsecond).rstrip("0")
    return base + "Z"


def canonical_us(us):
    """Canonical string for an integer microsecond timestamp (exact)."""
    if us is None:
        return None
    total = int(us)
    seconds, micros = divmod(total, 1_000_000)
    dt = _EPOCH + timedelta(seconds=seconds, microseconds=micros)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if micros:
        base += "." + ("%06d" % micros).rstrip("0")
    return base + "Z"
