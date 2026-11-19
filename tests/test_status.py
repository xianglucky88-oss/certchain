"""Point-in-time status semantics over retained events."""
import os
import tempfile

import pytest

from certchain import events as ev
from certchain import status, timeutil
from certchain.config import SPEC
from certchain.kernel import RULES_VERSION
from certchain.store import Store

DAY = 86_400_000_000


def T(days, us=0):
    return days * DAY + us


def row(cid, raw, days, issuer="issuer-A", **extra):
    data = {"id": cid, "name": "n", "value": 1, "status": raw,
            "ts": timeutil.canonical_us(T(days)), "issuer": issuer}
    data.update(extra)
    return data


def event(cid, raw, effective_days, first_seen_days, **extra):
    return ev.build_event(row(cid, raw, effective_days, **extra),
                          run_id="test", source="items",
                          now_us=T(first_seen_days))


def project(evs, cid="C1", **kw):
    return status.project(evs, cid, **kw)


# --------------------------------------------------------------------------- #
# Current vs historical trust.
# --------------------------------------------------------------------------- #
def test_current_status_follows_latest_effective_event():
    evs = [event("C1", "new", 1, 1), event("C1", "active", 2, 2),
           event("C1", "revoked", 5, 5)]
    assert project(evs)["state"] == "closed"
    assert project(evs)["kind"] == "revocation"


def test_as_of_answers_a_historical_moment():
    evs = [event("C1", "new", 1, 1), event("C1", "active", 2, 2),
           event("C1", "revoked", 5, 5)]
    at3 = status.project(evs, "C1", as_of=timeutil.canonical_us(T(3)))
    at1 = status.project(evs, "C1", as_of=timeutil.canonical_us(T(1)))
    assert at3["state"] == "active"
    assert at1["state"] == "pending"
    # Historical and current answers are each self-consistent, not aliased.
    assert at3["state"] != project(evs)["state"]


def test_status_before_rotation_is_the_pre_rotation_state():
    evs = [event("C1", "active", 1, 1), event("C1", "rotated", 5, 5)]
    prior = status.before(evs, "C1")
    assert prior["state"] == "active"
    assert prior["before_effective_ts"] == timeutil.canonical_us(T(5))


def test_literal_audit_question_is_answerable_after_disorder_and_duplicates():
    """The auditor's question: status immediately before a rotation."""
    evs = [event("C1", "new", 1, 1), event("C1", "active", 2, 2),
           event("C1", "rotated", 10, 10)]
    disordered = [evs[2], evs[0], evs[2], evs[1]]  # rotation first, duplicate
    prior = status.before(disordered, "C1")
    assert prior["state"] == "active"
    assert prior["before_effective_ts"] == timeutil.canonical_us(T(10))
    # The rotated event itself is still visible at the rotation instant.
    assert status.project(disordered, "C1")["state"] == "closed"


# --------------------------------------------------------------------------- #
# Provenance for unacceptable events.
# --------------------------------------------------------------------------- #
def test_unknown_status_is_rejected_but_retained_with_payload():
    evs = [event("C1", "active", 1, 1), event("C1", "banana", 2, 2)]
    result = project(evs)
    assert result["state"] == "active"
    assert len(result["rejected"]) == 1
    rej = result["rejected"][0]
    assert rej["reject_reason"] == "unknown_status"
    assert rej["raw_status"] == "banana"
    assert rej["raw_payload"]["status"] == "banana"
    assert rej["effective_ts"] == timeutil.canonical_us(T(2))


def test_unparseable_time_and_missing_identity_are_retained(tmp_path):
    bad_time = ev.build_event(
        {"id": "C1", "status": "active", "ts": "not-a-date", "issuer": "i"},
        run_id="t", source="items", now_us=T(1))
    no_id = ev.build_event(
        {"id": "", "status": "active", "ts": timeutil.canonical_us(T(2))},
        run_id="t", source="items", now_us=T(1))
    # The bad-time event is attributable to C1, so it appears (rejected) there.
    result = project([bad_time], "C1")
    assert result["state"] == "unknown"
    assert [r["reject_reason"] for r in result["rejected"]] == ["unparseable_time"]
    # An identity-less event is retained in the store but cannot be attributed
    # to any certificate.
    con = Store().connect(tmp_path / "unattributed.db")
    store = Store(con)
    store.reset()
    store.append_event(no_id)
    assert store.event_count() == 1
    assert store.all_events()[0]["reject_reason"] == "missing_identity"
    assert store.cert_ids() == [""]
    con.close()


def test_late_correction_inside_window_changes_the_conclusion():
    # Revocation is effective day 5 but only learned on day 10.
    evs = [event("C1", "active", 2, 2), event("C1", "revoked", 5, 10)]
    result = project(evs)
    assert result["state"] == "closed"
    assert result["excluded"] == []


def test_late_correction_beyond_window_is_retained_but_does_not_rewrite():
    # Revocation is effective day 1 but learnt 200 days later.
    evs = [event("C1", "active", 150, 150), event("C1", "revoked", 1, 200)]
    result = project(evs)
    assert result["state"] == "active"
    assert len(result["excluded"]) == 1
    ex = result["excluded"][0]
    assert ex["reason"] == "beyond_correction_window"
    assert ex["raw_status"] == "revoked"
    assert ex["raw_payload"]["status"] == "revoked"


def test_correction_window_is_configurable():
    # Revocation effective day 1, learnt on day 45, when a day-40 state is
    # already known.  Distance is 39 days.
    evs = [event("C1", "active", 40, 40), event("C1", "revoked", 1, 45)]
    assert project(evs, window_days=90)["state"] == "closed"
    assert project(evs, window_days=10)["state"] == "active"
    assert project(evs, window_days=10)["excluded"][0]["reason"] == \
        "beyond_correction_window"


# --------------------------------------------------------------------------- #
# Knowledge-time (bitemporal) queries.
# --------------------------------------------------------------------------- #
def test_as_known_separates_late_correction_from_always_known():
    evs = [event("C1", "active", 2, 2), event("C1", "revoked", 5, 20)]
    before = status.project(evs, "C1", as_known=timeutil.canonical_us(T(10)))
    after = status.project(evs, "C1", as_known=timeutil.canonical_us(T(25)))
    assert before["state"] == "active"
    assert after["state"] == "closed"


# --------------------------------------------------------------------------- #
# Stability under disorder, duplication, and re-runs.
# --------------------------------------------------------------------------- #
def test_projection_is_independent_of_arrival_order():
    evs = [event("C1", "new", 1, 1), event("C1", "active", 2, 2),
           event("C1", "rotated", 4, 4)]
    forward = status.project(evs, "C1")
    reverse = status.project(list(reversed(evs)), "C1")
    shuffled = status.project([evs[1], evs[2], evs[0]], "C1")
    assert forward["state"] == reverse["state"] == shuffled["state"]
    assert forward["timeline"] == reverse["timeline"] == shuffled["timeline"]


def test_repeated_identical_observations_do_not_change_history(tmp_path):
    con = Store().connect(tmp_path / "events.db")
    store = Store(con)
    store.reset()
    e = event("C1", "active", 2, 2)
    store.append_event(e)
    store.append_event(e)
    store.append_event(event("C1", "revoked", 5, 5))
    stored = store.all_events()
    assert store.event_count() == 2
    assert [x["observations"] for x in stored if x["event_id"] == e["event_id"]] == [2]
    assert status.project(stored, "C1")["state"] == "closed"
    con.close()


def test_old_data_restored_later_is_adjudicated_by_window():
    evs = [event("C1", "revoked", 5, 5)]
    # A stale "active" from day 3 turns up 300 days later: within window, it
    # is a legitimate correction that predates the revocation.
    evs.append(event("C1", "active", 3, 305))
    within = status.project(evs, "C1")
    assert within["state"] == "closed"
    assert within["excluded"] == []
    # Same row surfacing 400 days after a much newer effective event: retained,
    # but out of window and unable to rewrite.
    evs2 = [event("C1", "active", 400, 400), event("C1", "active", 1, 900)]
    out = status.project(evs2, "C1", window_days=90)
    assert out["state"] == "active"
    assert out["excluded"][0]["reason"] == "beyond_correction_window"


def test_terminal_state_cannot_be_resurrected_by_a_late_stale_row():
    evs = [event("C1", "active", 1, 1), event("C1", "revoked", 2, 2),
           event("C1", "active", 3, 3)]
    result = project(evs)
    assert result["state"] == "closed"
    assert any(e["reason"] == "after_terminal" for e in result["excluded"])


# --------------------------------------------------------------------------- #
# Rule changes are re-applied, not baked in.
# --------------------------------------------------------------------------- #
def test_rules_version_is_reported_and_rules_apply_at_read_time():
    evs = [event("C1", "expired", 2, 2)]
    result = project(evs)
    assert result["rules_version"] == RULES_VERSION
    assert result["state"] == "closed"
    assert result["kind"] == "expiry"


def test_in_progress_renewal_is_not_a_rotation_event():
    evs = [event("C1", "active", 1, 1), event("C1", "renewing", 3, 3),
           event("C1", "rotated", 5, 5)]
    prior = status.before(evs, "C1")
    # 'before rotation' must target the terminal rotation at day 5, not the
    # in-progress renewal at day 3.
    assert prior["before_effective_ts"] == timeutil.canonical_us(T(5))
    assert prior["state"] == "active"
    kinds = [t["kind"] for t in status.project(evs, "C1")["timeline"]]
    assert "rotation" in kinds
    assert "expiry" not in kinds


def test_history_exposes_evidence_and_counts():
    evs = [event("C1", "active", 1, 1), event("C1", "revoked", 2, 2),
           event("C1", "weird", 3, 3)]
    hist = status.history(evs, "C1")
    assert hist["current"] == "closed"
    assert len(hist["timeline"]) == 2
    assert len(hist["rejected"]) == 1
    assert hist["rules_version"] == RULES_VERSION


def test_corrupt_event_never_mutates_raw_status():
    e = event("C1", "banana", 1, 1)
    before = dict(e)
    project([e])
    assert e == before


def test_explicit_but_unparseable_cutoff_is_an_error():
    evs = [event("C1", "active", 1, 1)]
    for kwargs in ({"as_of": "not-a-date"}, {"as_known": "nope"}):
        try:
            status.project(evs, "C1", **kwargs)
        except ValueError as exc:
            assert "unparseable" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ValueError for %r" % kwargs)
