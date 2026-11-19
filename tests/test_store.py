"""Store-level guarantees: append-only evidence, legacy compatibility."""
from certchain import events as ev
from certchain import status, timeutil
from certchain.store import Store

DAY = 86_400_000_000


def row(cid, raw, days):
    return {"id": cid, "name": "n", "value": 1, "status": raw,
            "ts": timeutil.canonical_us(days * DAY), "issuer": "i"}


def event(cid, raw, days, first_seen_days):
    return ev.build_event(row(cid, raw, days), run_id="t", source="items",
                          now_us=first_seen_days * DAY)


def test_store_identity_and_checkpoint():
    con = Store().connect()
    st = Store(con)
    st.reset()
    try:
        record = {"id": "sample", "ts": "t1", "v": 1}
        assert st.upsert(record) is True
        assert st.upsert(record) is False
        st.set_watermark("checkpoint")
        assert st.watermark() == "checkpoint"
    finally:
        st.reset()
        con.close()


def test_event_evidence_is_immutable_across_reappends(tmp_path):
    con = Store().connect(tmp_path / "s.db")
    st = Store(con)
    original = event("C1", "active", 2, 2)
    st.append_event(original)
    # A re-send with a different observed payload but the same identity must
    # not rewrite the stored evidence.
    resent = dict(original)
    resent["payload"] = '{"id": "C1", "status": "tampered"}'
    resent["last_seen_us"] = 999 * DAY
    st.append_event(resent)
    stored = st.all_events()[0]
    assert stored["payload"] == original["payload"]
    assert stored["raw_status"] == "active"
    assert stored["first_seen_us"] == original["first_seen_us"]
    assert stored["observations"] == 2
    con.close()


def test_legacy_and_event_views_coexist(tmp_path):
    con = Store().connect(tmp_path / "s.db")
    st = Store(con)
    st.upsert(row("C1", "active", 1))
    st.append_event(event("C1", "active", 1, 1))
    assert st.count() == 1
    assert st.event_count() == 1
    assert st.all_records()[0]["id"] == "C1"
    assert st.cert_ids() == ["C1"]
    con.close()


def test_reset_clears_both_views():
    con = Store().connect()
    st = Store(con)
    st.upsert(row("C1", "active", 1))
    st.append_event(event("C1", "active", 1, 1))
    st.reset()
    assert st.count() == 0
    assert st.event_count() == 0
    con.close()
