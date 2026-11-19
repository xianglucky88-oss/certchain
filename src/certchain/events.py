"""Immutable observation events with full provenance.

Every source row the pipeline sees becomes an *event*: a content-addressed,
append-only record of "this source said this about this certificate, with this
effective time".  Events never mutate once accepted; re-sends only bump
``observations``/``last_seen_us``.  This is what lets an auditor see the
original evidence behind any conclusion, including evidence that was later
rejected or overtaken.
"""
from __future__ import annotations

import hashlib
import json

from . import timeutil
from .config import SPEC
from .kernel import RULES_VERSION, classify


def source_row(record):
    """Project a parsed row onto the declared source columns.

    Keeps provenance faithful: values are not interpreted here, only bounded to
    the columns the source is documented to provide.
    """
    return {c: record.get(c, "") for c in SPEC.columns}


def observation_key(row):
    """Content identity of an observation.

    The effective timestamp is canonicalised first so the same instant written
    with a different UTC offset or precision hashes identically.  Two genuinely
    different statuses at the same instant therefore remain distinct events
    (both are retained; projection breaks the tie deterministically), while a
    byte-identical re-send collapses onto the existing event.
    """
    material = dict(row)
    canon = timeutil.canonical(row.get(SPEC.ts_field))
    if canon is not None:
        material[SPEC.ts_field] = canon
    blob = json.dumps(material, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()[:24]


def build_event(record, run_id="", source="", now_us=0):
    """Build an event dict from a parsed source row.

    ``reject_reason`` only captures *intrinsic* defects (bad identity, bad time,
    unknown status word).  Ordering-dependent admissibility such as a
    beyond-window correction is decided by the projector from the persisted
    event set, so it stays stable across runs.
    """
    row = source_row(record)
    cert_id = str(row.get("id", "") or "").strip()
    eff_us = timeutil.epoch_us(row.get(SPEC.ts_field))
    eff_ts = timeutil.canonical_us(eff_us)
    status_word = str(row.get("status", "") or "").strip()
    classification = classify(status_word)

    reason = None
    if not cert_id:
        reason = "missing_identity"
    elif eff_us is None:
        reason = "unparseable_time"
    elif not status_word:
        reason = "missing_status"
    elif classification["invalid_status"]:
        reason = "unknown_status"

    return {
        "event_id": observation_key(row),
        "cert_id": cert_id,
        "effective_us": eff_us,
        "effective_ts": eff_ts,
        "raw_status": status_word,
        "issuer": str(row.get("issuer", "") or ""),
        "payload": json.dumps(row, ensure_ascii=False, sort_keys=True),
        "source": str(source or ""),
        "first_run": str(run_id or ""),
        "first_seen_us": int(now_us or 0),
        "last_seen_us": int(now_us or 0),
        "observations": 1,
        "reject_reason": reason,
        "rules_version": RULES_VERSION,
    }


def decode_payload(event):
    """Return the original source row stored on an event."""
    try:
        return json.loads(event["payload"])
    except (KeyError, TypeError, ValueError):
        return {}


def intrinsic_rejected(event):
    """True when the event can never inform a projection."""
    return bool(event.get("reject_reason"))


def describe(event):
    """Compact, JSON-safe provenance view used in explanations."""
    return {
        "event_id": event.get("event_id"),
        "cert_id": event.get("cert_id"),
        "raw_status": event.get("raw_status"),
        "effective_ts": event.get("effective_ts"),
        "issuer": event.get("issuer"),
        "source": event.get("source"),
        "first_run": event.get("first_run"),
        "first_seen_us": event.get("first_seen_us"),
        "last_seen_us": event.get("last_seen_us"),
        "observations": event.get("observations"),
        "reject_reason": event.get("reject_reason"),
    }
