
"""SQLite store: append-only observation events plus a legacy record view.

Two tables are maintained:

* ``records`` - the original content-addressed view (unchanged semantics, so
  existing callers, watermarks and the offline verification entry point keep
  working);
* ``events`` - the append-only evidence log.  Rows are only ever inserted or
  have their *observation counters* bumped; identity/payload/effective time are
  immutable.  Any conclusion is re-derived from this log, so re-runs, re-ordering
  and restored old data cannot silently change history.
"""
import hashlib
import json
import sqlite3

from .config import DB_PATH

_EVENT_COLUMNS = (
    "event_id", "cert_id", "effective_us", "effective_ts", "raw_status",
    "issuer", "payload", "source", "first_run", "first_seen_us",
    "last_seen_us", "observations", "reject_reason", "rules_version",
)


class Store:
    def __init__(self, con=None):
        self.con = con
        if con is not None:
            self._init()

    def connect(self, path=None):
        con = sqlite3.connect(str(path or DB_PATH))
        self.__init__(con)
        return con

    def _init(self):
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS records("
            "content_hash TEXT PRIMARY KEY, id TEXT, ts TEXT, payload TEXT NOT NULL)")
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS events("
            "event_id TEXT PRIMARY KEY, cert_id TEXT NOT NULL, "
            "effective_us INTEGER, effective_ts TEXT, raw_status TEXT, "
            "issuer TEXT, payload TEXT NOT NULL, source TEXT, first_run TEXT, "
            "first_seen_us INTEGER, last_seen_us INTEGER, observations INTEGER, "
            "reject_reason TEXT, rules_version INTEGER)")
        self.con.execute(
            "CREATE INDEX IF NOT EXISTS events_cert_effective "
            "ON events(cert_id, effective_us)")
        self.con.execute(
            "CREATE INDEX IF NOT EXISTS events_cert_known "
            "ON events(cert_id, first_seen_us)")
        self.con.commit()

    # ------------------------------------------------------------------ #
    # Legacy record view.
    # ------------------------------------------------------------------ #
    @staticmethod
    def hash(record):
        blob = json.dumps(record, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode()).hexdigest()[:24]

    def upsert(self, record):
        cur = self.con.execute(
            "INSERT OR IGNORE INTO records(content_hash,id,ts,payload) VALUES(?,?,?,?)",
            (self.hash(record), str(record.get("id", "")),
             str(record.get("ts", "")), json.dumps(record, ensure_ascii=False)))
        self.con.commit()
        return cur.rowcount > 0

    def count(self):
        return self.con.execute("SELECT COUNT(*) FROM records").fetchone()[0]

    def all_records(self):
        return [json.loads(p) for (_h, p) in
                self.con.execute("SELECT content_hash,payload FROM records")]

    def get(self, content_hash):
        row = self.con.execute(
            "SELECT payload FROM records WHERE content_hash=?", (content_hash,)).fetchone()
        return json.loads(row[0]) if row else None

    def watermark(self):
        row = self.con.execute("SELECT v FROM meta WHERE k='watermark'").fetchone()
        return row[0] if row else None

    def set_watermark(self, value):
        self.con.execute(
            "INSERT INTO meta(k,v) VALUES('watermark',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(value),))
        self.con.commit()

    def reset(self):
        self.con.execute("DELETE FROM records")
        self.con.execute("DELETE FROM meta")
        self.con.execute("DELETE FROM events")
        self.con.commit()

    # ------------------------------------------------------------------ #
    # Append-only event log.
    # ------------------------------------------------------------------ #
    def append_event(self, event):
        """Insert an event, or bump its observation counters on re-send.

        Returns ``"inserted"`` or ``"updated"``.  Immutable evidence fields are
        never overwritten, so a replayed or duplicated fetch can only raise the
        observed count, never alter history.
        """
        existing = self.con.execute(
            "SELECT first_seen_us, last_seen_us, observations FROM events "
            "WHERE event_id=?", (event["event_id"],)).fetchone()
        if existing is None:
            self.con.execute(
                "INSERT INTO events(%s) VALUES(%s)"
                % (",".join(_EVENT_COLUMNS), ",".join("?" * len(_EVENT_COLUMNS))),
                tuple(event.get(c) for c in _EVENT_COLUMNS))
            self.con.commit()
            return "inserted"
        first_seen, last_seen, observations = existing
        new_first = min(int(first_seen or 0), int(event.get("first_seen_us") or 0))
        new_last = max(int(last_seen or 0), int(event.get("last_seen_us") or 0))
        self.con.execute(
            "UPDATE events SET first_seen_us=?, last_seen_us=?, observations=? "
            "WHERE event_id=?",
            (new_first, new_last, int(observations or 0) + 1, event["event_id"]))
        self.con.commit()
        return "updated"

    def _row_to_event(self, row):
        return {c: row[i] for i, c in enumerate(_EVENT_COLUMNS)}

    def all_events(self, cert_id=None):
        if cert_id is None:
            rows = self.con.execute(
                "SELECT %s FROM events ORDER BY cert_id, effective_us, event_id"
                % ",".join(_EVENT_COLUMNS)).fetchall()
        else:
            rows = self.con.execute(
                "SELECT %s FROM events WHERE cert_id=? "
                "ORDER BY effective_us, event_id" % ",".join(_EVENT_COLUMNS),
                (str(cert_id),)).fetchall()
        return [self._row_to_event(r) for r in rows]

    def event_count(self):
        return self.con.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def cert_ids(self):
        return [r[0] for r in self.con.execute(
            "SELECT DISTINCT cert_id FROM events ORDER BY cert_id")]
