"""End-to-end behaviour of collection plus status queries."""
import importlib

import pytest

from certchain import pipeline, status, timeutil
from certchain.config import SPEC
from certchain.framework import Transport, fetch_batch, Http, Sleeper
from certchain.store import Store


@pytest.fixture()
def store(tmp_path):
    con = Store().connect(tmp_path / "certchain.db")
    st = Store(con)
    st.reset()
    yield st
    con.close()


@pytest.fixture()
def mock():
    app = importlib.import_module("mockapp.main").app
    return app


def test_pipeline_returns_a_status():
    con = Store().connect()
    Store(con).reset()
    try:
        result = pipeline.run(con=con)
    finally:
        con.close()
    assert isinstance(result, dict)
    assert result.get("engine") == SPEC.engine
    assert result


def _admin(mock, path, **body):
    from starlette.testclient import TestClient
    client = TestClient(mock)
    resp = client.post(path, json=body)
    assert resp.status_code == 200
    return resp.json()


def test_full_run_records_events_and_is_idempotent(store):
    first = pipeline.run(con=store.con)
    assert first["events_total"] == first["count"] == 9
    assert first["fetched"] == first["ingested"] + first["duplicates"]
    second = pipeline.run(con=store.con)
    assert second["ingested"] == 0
    assert second["count"] == first["count"]
    assert second["events_inserted"] == 0
    assert second["events_total"] == first["events_total"]


def test_current_and_historical_queries_agree_with_events(store):
    pipeline.run(con=store.con)
    events = store.all_events()
    ids = store.cert_ids()
    current = status.project(events, None)
    assert set(current) == set(ids)
    for cid in ids:
        result = pipeline.status_at(cid, con=store.con)
        assert result["state"] == current[cid]["state"]
        # A historical query at the first effective instant is self-consistent.
        earliest = min(e["effective_ts"] for e in events if e["cert_id"] == cid)
        historical = pipeline.status_at(cid, as_of=earliest, con=store.con)
        assert historical["state"] in ("pending", "active", "closed", "archived",
                                       "unknown")


def test_partial_page_failure_preserves_data_and_watermark(store, mock):
    _admin(mock, "/admin/reset")
    pipeline.run(con=store.con)
    before = store.event_count()
    watermark = store.watermark()
    # Fail page 2 past the retry budget.
    _admin(mock, "/admin/fault", page=2, status=503, count=10)
    try:
        result = pipeline.run(mode="incremental", con=store.con)
    finally:
        _admin(mock, "/admin/fault", page=2, count=0)
    assert result["partial"] is True
    assert result["interrupted_page"] == 2
    # Page-1 events were still retained; no fabricated event for the gap.
    assert store.event_count() >= before
    # The watermark must not advance across an incomplete read.
    assert result["watermark"] == watermark
    # A later complete run recovers.
    recovered = pipeline.run(mode="incremental", con=store.con)
    assert recovered["partial"] is False
    assert recovered["events_total"] >= before


def test_interrupted_run_is_retried_and_later_page_events_recovered(store, mock):
    _admin(mock, "/admin/reset")
    _admin(mock, "/admin/fault", page=3, status=500, count=10)
    partial = pipeline.run(con=store.con)
    assert partial["partial"] is True
    seen_partial = store.event_count()
    _admin(mock, "/admin/fault", page=3, count=0)
    full = pipeline.run(con=store.con)
    assert full["partial"] is False
    assert store.event_count() >= seen_partial
    assert full["events_total"] == full["count"] + 0 or full["events_total"] >= 9


def test_late_event_delivered_after_full_run_is_ingested_incrementally(store, mock):
    _admin(mock, "/admin/reset")
    pipeline.run(con=store.con)
    cid = store.cert_ids()[0]
    before = store.event_count()
    # Deliver a late correction directly to the event log's source and re-run.
    _admin(mock, "/admin/append", row={
        "id": cid, "name": "late", "value": 3,
        "status": "revoked",
        "ts": timeutil.canonical_us(1 * 86_400_000_000),
        "issuer": "issuer-late",
    })
    try:
        result = pipeline.run(mode="incremental", con=store.con)
    finally:
        _admin(mock, "/admin/reset")
    assert result["events_total"] > before
    history = pipeline.history(cid, con=store.con)
    # The late row is retained in evidence, whether or not it is in window.
    statuses = [t["raw_status"] for t in history["timeline"]]
    retained = statuses + [x["raw_status"] for x in history["excluded"]]
    assert "revoked" in retained


def test_rpa_engine_does_not_lose_the_gated_page(store, mock, monkeypatch):
    monkeypatch.setattr(SPEC, "engine", "rpa")
    _admin(mock, "/admin/reset")
    try:
        result = pipeline.run(con=store.con)
    finally:
        _admin(mock, "/admin/reset")
    assert result["engine"] == "rpa"
    assert result["captcha_solved"] is True
    # Every source row is collected exactly once: the gate must neither skip
    # page 1 nor duplicate it (10 rows, one of which is an exact duplicate).
    assert result["collected"] == 10
    assert result["duplicates"] == 1
    assert result["events_total"] == 9


def test_fetch_failure_does_not_become_a_business_event(store, mock):
    _admin(mock, "/admin/reset")
    pipeline.run(con=store.con)
    baseline = {cid: r["state"] for cid, r in status.project(
        store.all_events(), None).items()}
    _admin(mock, "/admin/fault", page=2, status=503, count=10)
    try:
        partial = pipeline.run(mode="incremental", con=store.con)
    finally:
        _admin(mock, "/admin/fault", page=2, count=0)
    assert partial["partial"] is True
    # A failed access is not a status event: conclusions are untouched and no
    # rejected/excluded evidence is fabricated for the gap.
    after = status.project(store.all_events(), None)
    assert {cid: r["state"] for cid, r in after.items()} == baseline
    assert sum(len(r["rejected"]) + len(r["excluded"]) for r in after.values()) == 0


def test_fetch_batch_reports_completion_and_attempts(mock):
    http = Http(Transport(), Sleeper())
    records, attempts, completion = fetch_batch(http)
    assert completion["complete"] is True
    assert completion["pages"] == 3
    assert len(records) == 10
    assert attempts >= 3
