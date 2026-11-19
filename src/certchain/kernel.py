
"""Certificate status rules (pure, deterministic, versioned).

The kernel only answers two questions:

* how a raw source status maps to a normalised lifecycle state, and
* whether an observation represents a terminal/rotation/revocation event.

It deliberately knows nothing about storage or time ordering; those live in
``status`` and ``timeutil``.  ``RULES_VERSION`` is part of every projection so a
rule change is visible to an auditor and can be re-applied to the retained raw
events.
"""

RULES_VERSION = 2

# Raw status -> normalised lifecycle state.  The original wording is retained
# on the event itself; this table is only the interpretation.
TRANS = {
    # not yet usable
    "new": "pending", "draft": "pending", "pending": "pending",
    "issued": "pending", "requested": "pending",
    # usable
    "active": "active", "valid": "active", "enabled": "active",
    "rotating": "active", "renewing": "active",
    # no longer usable (revocation / expiry / rotation away / withdrawal)
    "sold": "closed", "withdrawn": "closed", "closed": "closed",
    "revoked": "closed", "untrusted": "closed", "suspended": "closed",
    "expired": "closed", "superseded": "closed", "rotated": "closed",
    "retired": "closed",
    # out of the active set but kept for audit
    "deleted": "archived", "archived": "archived",
}

# Monotonic lifecycle rank.  Used to detect an observation that moves a
# certificate *backwards* (a likely stale/late duplicate).
ORDER = {"unknown": 0, "pending": 1, "active": 2, "closed": 3, "archived": 4}

# Why a certificate became terminal.  Kept separate from the coarse state so
# revocation, expiry and rotation remain distinguishable in the history.
_REASON_TERMS = (
    ("revocation", ("revoke", "revoked", "untrust", "suspend")),
    ("expiry", ("expire", "expired", "not_after", "notafter")),
    ("rotation", ("rotat", "renew", "superseded", "supersede")),
)


def raw_status(record):
    """Lower-cased, stripped source status reported by ``record``."""
    return str(record.get("status", "")).strip().lower()


def classify(raw):
    """Classify a raw status string.

    Returns a dict with ``state_norm`` (coarse lifecycle state), ``event_kind``
    (machine-friendly kind such as ``revocation``/``expiry``/``rotation``) and
    ``invalid_status`` (1 when the source word is not understood).  A reason
    kind is only assigned to *terminal* states; an in-progress renewal keeps
    its lifecycle kind so it can never be mistaken for a rotation event.
    """
    s = str(raw or "").strip().lower()
    state = TRANS.get(s, "unknown")
    terminal = 1 if state in ("closed", "archived") else 0
    kind = state
    if terminal:
        for name, terms in _REASON_TERMS:
            if any(t in s for t in terms):
                kind = name
                break
    return {
        "state_norm": state,
        "event_kind": kind,
        "terminal": terminal,
        "invalid_status": int(s not in TRANS),
    }


def process(record):
    """Derive normalised state for a single record (public, back-compatible).

    Always returns a non-empty dict; ``state_norm`` and ``invalid_status`` keep
    their original meaning and new fields are additive.
    """
    return classify(raw_status(record))


def _record_time_key(record):
    eff = record.get("effective_us")
    if eff is not None:
        try:
            return (0, int(eff), "")
        except (TypeError, ValueError):
            pass
    return (1, 0, str(record.get("ts", "")))


def sort_key(record):
    """Deterministic per-certificate ordering key.

    Effective time first, then the source id, then the event identity.  Input
    order never influences the result.
    """
    return (str(record.get("id", "")), _record_time_key(record),
            str(record.get("event_id", "")))


def reduce(records):
    """Annotate records with a deterministic ``regression`` flag.

    Order-independent: input order does not affect the result, and the same
    input always produces the same output.  A record is a regression when its
    normalized state ranks below the highest state already seen for that
    certificate at an earlier-or-equal effective time.
    """
    last = {}
    out = sorted(records, key=sort_key)
    for r in out:
        rid = r.get("id")
        st = r.get("state_norm", "unknown")
        prev = last.get(rid, "unknown")
        r["regression"] = int(rid in last and ORDER.get(st, 0) < ORDER.get(prev, 0))
        if ORDER.get(st, 0) >= ORDER.get(prev, 0):
            last[rid] = st
    return records
