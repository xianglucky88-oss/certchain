"""Certificate status history: point-in-time projection over retained events.

The engine is deliberately *pure*: given the same set of events and the same
query it returns the same answer, independent of the order in which events were
stored and independent of how many times they were re-sent.  That is what makes
re-running after out-of-order delivery, duplicates, page interruptions, rule
changes and restored old data stable.

Two independent time axes are supported:

* **effective time** (``effective_us``) - when the certificate actually changed
  state, i.e. the source ``ts``.  A query at a historical effective instant
  answers "what was true about that moment?".
* **knowledge time** (``first_seen_us``) - when the pipeline first learned about
  the event.  Supplying ``as_known`` answers "what did we know at that moment?",
  which is how an auditor separates a genuinely late correction from a fact that
  was always present.

Projection rules
----------------
1. **Intrinsic rejection** - events without an identity, without a parseable
   effective time, without a status, or with a status the current rules do not
   recognise never inform a conclusion.  They are retained verbatim and
   reported together with their original payload and the reason.
2. **Bounded late correction** - an event is *late* when, at the knowledge
   instant it was first seen, a materially newer effective state for the same
   certificate was already known.  If its effective time is further behind that
   already-known state than the correction window, the event is retained but
   does not rewrite history (``beyond_correction_window``).  The check is a pure
   function of the stored ``(effective, first_seen)`` pairs, never of storage
   order.
3. **Terminal latch** - once a certificate is closed/archived at an effective
   instant, a later non-terminal observation (a stale re-send, for example)
   cannot resurrect it; it is retained and reported as ``after_terminal``.
   Apply this to effective ordering, so a within-window late revocation still
   supersedes a previously believed "active".
4. **Deterministic ordering** - events are ordered by effective time, then
   knowledge time, then lifecycle rank, then event id, so ties never depend on
   insertion order.
5. **Rules at read time** - the raw status word is retained and re-classified on
   every projection, so a rule change is re-applied consistently to the whole
   history without rewriting evidence.
"""
from __future__ import annotations

from . import kernel, timeutil
from .config import SPEC
from .events import describe, decode_payload

DAY_US = 86_400_000_000


def _window_us(window_days=None):
    if window_days is None:
        window_days = getattr(SPEC, "correction_window_days", 90)
    return int(float(window_days) * DAY_US)


def _cert_id(event):
    return str(event.get("cert_id") or "").strip()


def _first_seen(event):
    try:
        return int(event.get("first_seen_us") or 0)
    except (TypeError, ValueError):
        return 0


def _effective(event):
    value = event.get("effective_us")
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return timeutil.epoch_us(event.get("effective_ts"))


def _evaluate(event):
    """Return ``(classification, problems)`` for a single event."""
    raw = str(event.get("raw_status") or "").strip()
    classification = kernel.classify(raw)
    problems = []
    if not _cert_id(event):
        problems.append("missing_identity")
    if _effective(event) is None:
        problems.append("unparseable_time")
    if not raw:
        problems.append("missing_status")
    elif classification["invalid_status"]:
        problems.append("unknown_status")
    return classification, problems


def _order_key(event):
    classification = kernel.classify(event.get("raw_status"))
    return (
        _effective(event) if _effective(event) is not None else 0,
        _first_seen(event),
        kernel.ORDER.get(classification["state_norm"], 0),
        str(event.get("event_id") or ""),
    )


def late_cutoff(events, window_us=None):
    """Pure per-event late-correction map.

    Returns ``{event_id: newest_effective_us_known_before_it}`` for events that
    are late beyond ``window_us``.  "Known before it" means a strictly earlier
    ``first_seen_us``; events first seen in the same batch never mark each other
    late.  The result depends only on the set of ``(event_id, effective_us,
    first_seen_us)`` triples, so it is insertion-order independent.
    """
    if window_us is None:
        window_us = _window_us()
    ordered = sorted(events, key=lambda e: (_first_seen(e), _effective(e),
                                            str(e.get("event_id"))))
    cutoff = {}
    prefix_max = None
    index = 0
    while index < len(ordered):
        seen = _first_seen(ordered[index])
        batch = []
        while index < len(ordered) and _first_seen(ordered[index]) == seen:
            batch.append(ordered[index])
            index += 1
        if prefix_max is not None:
            for event in batch:
                effective = _effective(event)
                if effective is not None and effective < prefix_max - window_us:
                    cutoff[str(event.get("event_id"))] = prefix_max
        batch_max = max([_effective(e) for e in batch if _effective(e) is not None]
                        or [None], key=lambda x: -1 if x is None else x)
        if batch_max is not None:
            prefix_max = batch_max if prefix_max is None else max(prefix_max, batch_max)
    return cutoff, window_us


def _selection(cert_events, as_known_us=None, as_of_us=None, window_us=None):
    """Split events into (rejected, excluded, admitted) for one certificate.

    The late-correction decision is made only among events that could matter to
    this query, so a historical answer never depends on evidence that post-dates
    the queried instant.
    """
    known = [e for e in cert_events
             if as_known_us is None or _first_seen(e) <= as_known_us]

    rejected, usable = [], []
    for event in known:
        _classification, problems = _evaluate(event)
        if problems:
            rejected.append((event, problems))
        else:
            usable.append(event)

    relevant = [e for e in usable
                if as_of_us is None or (_effective(e) or 0) <= as_of_us]
    cutoff, window_us = late_cutoff(relevant, window_us)
    excluded, admitted = [], []
    for event in relevant:
        newest = cutoff.get(str(event.get("event_id")))
        if newest is not None:
            excluded.append((event, {
                "reason": "beyond_correction_window",
                "newest_known_effective": timeutil.canonical_us(newest),
                "window_days": round(window_us / DAY_US, 6),
            }))
        else:
            admitted.append(event)
    return rejected, excluded, admitted, window_us, len(known)


def project(events, cert_id=None, as_of=None, as_known=None, window_days=None):
    """Project the status of one certificate (or a mapping for all of them).

    ``as_of`` is an inclusive effective-time cut-off (``None`` = now);
    ``as_known`` is an inclusive knowledge-time cut-off (``None`` = all
    knowledge).  Both accept anything :func:`timeutil.epoch_us` accepts; an
    explicit but unparseable value is an error rather than a silent "now".
    """
    as_of_us = _cutoff(as_of, "as_of")
    as_known_us = _cutoff(as_known, "as_known")
    return project_us(events, cert_id, as_of_us, as_known_us, window_days)


def _cutoff(value, name):
    if value is None:
        return None
    us = timeutil.epoch_us(value)
    if us is None:
        raise ValueError("unparseable %s: %r" % (name, value))
    return us


def project_us(events, cert_id=None, as_of_us=None, as_known_us=None,
               window_days=None):
    """Like :func:`project` but with explicit microsecond cut-offs (internal)."""
    events = list(events)
    if cert_id is None:
        ids = sorted({_cert_id(e) for e in events if _cert_id(e)})
        return {cid: project_us(events, cid, as_of_us, as_known_us, window_days)
                for cid in ids}
    return _project_one(events, cert_id, as_of_us, as_known_us, window_days)


def _project_one(events, cert_id, as_of_us, as_known_us, window_days):
    cid = str(cert_id).strip()

    relevant = [e for e in events if _cert_id(e) == cid]
    rejected, excluded, admitted, window_us, known_count = _selection(
        relevant, as_known_us, as_of_us, _window_us(window_days))

    ordered = sorted(admitted, key=_order_key)
    terminal_event = None
    state = "unknown"
    decided_by = None
    timeline = []
    after_terminal = 0

    for event in ordered:
        effective = _effective(event)
        classification = kernel.classify(event.get("raw_status"))
        state_norm = classification["state_norm"]
        if terminal_event is not None and not classification["terminal"]:
            excluded.append((event, {
                "reason": "after_terminal",
                "terminal_event": str(terminal_event.get("event_id")),
                "terminal_at": timeutil.canonical_us(_effective(terminal_event)),
            }))
            after_terminal += 1
            continue
        state = state_norm
        decided_by = event
        if classification["terminal"]:
            terminal_event = event
        timeline.append({
            "event_id": event.get("event_id"),
            "effective_ts": event.get("effective_ts")
            or timeutil.canonical_us(effective),
            "raw_status": event.get("raw_status"),
            "state": state_norm,
            "kind": classification["event_kind"],
        })

    rejected_view = []
    for event, problems in rejected:
        item = describe(event)
        item.update({"reject_reason": problems[0], "reject_reasons": problems,
                     "raw_payload": decode_payload(event)})
        rejected_view.append(item)

    excluded_view = []
    for event, meta in excluded:
        item = describe(event)
        item.update(meta)
        item["raw_payload"] = decode_payload(event)
        excluded_view.append(item)

    return {
        "cert_id": cid,
        "state": state,
        "kind": (kernel.classify(decided_by.get("raw_status"))["event_kind"]
                 if decided_by is not None else "unknown"),
        "as_of": (timeutil.canonical_us(as_of_us) if as_of_us is not None else None),
        "as_known": (timeutil.canonical_us(as_known_us) if as_known_us is not None else None),
        "effective_ts": (decided_by.get("effective_ts") if decided_by is not None
                         else None),
        "decided_by": describe(decided_by) if decided_by is not None else None,
        "timeline": timeline,
        "rejected": _sort_view(rejected_view),
        "excluded": _sort_view(excluded_view),
        "rules_version": kernel.RULES_VERSION,
        "window_days": round(window_us / DAY_US, 6),
        "observed": len(relevant),
        "known": known_count,
        "admissible": len(timeline),
        "after_terminal": after_terminal,
    }


def _sort_view(items):
    return sorted(items, key=lambda x: (str(x.get("effective_ts")),
                                        str(x.get("event_id"))))


def terminal_events(events, cert_id):
    """Admissible terminal events for a certificate, oldest first."""
    cid = str(cert_id).strip()
    relevant = [e for e in events if _cert_id(e) == cid]
    _rejected, _excluded, admitted, _w, _k = _selection(relevant)
    out = []
    for event in admitted:
        if kernel.classify(event.get("raw_status"))["terminal"]:
            out.append(event)
    return sorted(out, key=_order_key)


def before(events, cert_id, of=None, as_known=None, window_days=None):
    """Status strictly before an effective instant.

    When ``of`` is omitted the newest terminal event (a rotation when one
    exists, otherwise the newest closure) is used - exactly the "state
    immediately before rotation" question.
    """
    if of is None:
        terminals = terminal_events(events, cert_id)
        rotations = [e for e in terminals
                     if kernel.classify(e.get("raw_status"))["event_kind"] == "rotation"]
        pool = rotations or terminals
        if not pool:
            return project(events, cert_id, None, as_known, window_days)
        target_us = _effective(pool[-1])
    else:
        target_us = timeutil.epoch_us(of)
        if target_us is None:
            raise ValueError("unparseable time: %r" % (of,))
    result = project_us(events, cert_id, target_us - 1, _cutoff(as_known, "as_known"),
                        window_days)
    result["before_effective_ts"] = timeutil.canonical_us(target_us)
    return result


def history(events, cert_id, as_known=None, window_days=None):
    """Full, explainable change history for one certificate."""
    result = project(events, cert_id, None, as_known, window_days)
    return {
        "cert_id": result["cert_id"],
        "current": result["state"],
        "timeline": result["timeline"],
        "rejected": result["rejected"],
        "excluded": result["excluded"],
        "rules_version": result["rules_version"],
        "window_days": result["window_days"],
    }


def explain(result):
    """Render a projection (or history) as a short human-readable paragraph."""
    if "current" in result and "state" not in result:
        return _explain_history(result)
    lines = ["certificate %s: %s" % (result.get("cert_id"), result.get("state"))]
    if result.get("as_of"):
        lines.append("  as of %s (effective time)" % result["as_of"])
    if result.get("as_known"):
        lines.append("  as known at %s" % result["as_known"])
    decided = result.get("decided_by") or {}
    if decided:
        lines.append("  decided by %s at %s (raw status %r)"
                     % (decided.get("event_id"), decided.get("effective_ts"),
                        decided.get("raw_status")))
    elif result.get("state") == "unknown":
        lines.append("  no admissible evidence on or before the queried instant")
    for item in result.get("excluded") or []:
        lines.append("  excluded %s at %s: %s"
                     % (item.get("event_id"), item.get("effective_ts"),
                        item.get("reason")))
    for item in result.get("rejected") or []:
        lines.append("  rejected %s at %s: %s (raw status %r)"
                     % (item.get("event_id"), item.get("effective_ts"),
                        item.get("reject_reason"), item.get("raw_status")))
    return "\n".join(lines)


def _explain_history(result):
    lines = ["certificate %s history (rules v%s, window %s days)"
             % (result.get("cert_id"), result.get("rules_version"),
                result.get("window_days")),
             "  current: %s" % result.get("current")]
    for step in result.get("timeline") or []:
        lines.append("  %s  %-10s -> %s (%s)"
                     % (step.get("effective_ts"), step.get("raw_status"),
                        step.get("state"), step.get("kind")))
    for item in result.get("excluded") or []:
        lines.append("  excluded %s at %s: %s (raw %r)"
                     % (item.get("event_id"), item.get("effective_ts"),
                        item.get("reason"), item.get("raw_status")))
    for item in result.get("rejected") or []:
        lines.append("  rejected %s at %s: %s (raw %r)"
                     % (item.get("event_id"), item.get("effective_ts"),
                        item.get("reject_reason"), item.get("raw_status")))
    return "\n".join(lines)

