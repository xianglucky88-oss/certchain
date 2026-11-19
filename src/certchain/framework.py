"""Local transport, parsing, storage, and session helpers."""
from __future__ import annotations
import hashlib
import importlib
import json
from datetime import datetime, timezone

from lxml import html as _lh

from . import events, timeutil
from .config import SPEC
from .store import Store


# --------------------------------------------------------------------------- #
# Transport helpers.
# --------------------------------------------------------------------------- #
class Transport:
    """Client for the bundled local service."""

    def __init__(self):
        import os
        import sys
        for p in (str(SPEC_ROOT()), str(SPEC_ROOT() / "src")):
            if p not in sys.path:
                sys.path.insert(0, p)
        from starlette.testclient import TestClient
        app = importlib.import_module("mockapp.main").app
        self.client = TestClient(app)
        self.cookies: dict[str, str] = {}

    def request(self, method, path, params=None, json_body=None, headers=None):
        q = {k: v for k, v in (params or {}).items() if v not in (None, "")}
        resp = self.client.request(method, path, params=q, json=json_body,
                                   headers=headers or {}, cookies=self.cookies)
        for k, v in resp.cookies.items():
            self.cookies[k] = v
        return resp.status_code, dict(resp.headers), resp.text


def SPEC_ROOT():
    from .config import ROOT
    return ROOT


class Sleeper:
    """Records requested delays without blocking the caller."""

    def __init__(self):
        self.slept = 0.0
        self.calls = 0

    def sleep(self, seconds):
        self.slept += seconds
        self.calls += 1


class Http:
    """HTTP client with bounded retry support."""

    def __init__(self, transport: Transport, sleeper: Sleeper,
                 max_retries=4, base_backoff=0.5, politeness=0.25):
        self.t = transport
        self.sleeper = sleeper
        self.max_retries = max_retries
        self.base_backoff = base_backoff
        self.politeness = politeness

    def get(self, path, params=None, headers=None):
        attempt = 0
        while True:
            self.sleeper.sleep(self.politeness)
            status, hdr, body = self.t.request("GET", path, params, headers=headers)
            if status in (429, 500, 502, 503) and attempt < self.max_retries:
                self.sleeper.sleep(self.base_backoff * (2 ** attempt))
                attempt += 1
                continue
            return status, hdr, body, attempt


# --------------------------------------------------------------------------- #
# Response parsing.
# --------------------------------------------------------------------------- #
def _coerce(name, val):
    if name in SPEC.int_fields:
        try:
            return int(val)
        except (TypeError, ValueError):
            return val
    return val


def parse(resp_body, fmt):
    cols = SPEC.columns
    if fmt == "json":
        items = json.loads(resp_body).get("items", [])
        return [{c: _coerce(c, it.get(c)) for c in cols} for it in items]
    if fmt == "html":
        doc = _lh.fromstring(resp_body)
        rows = []
        for tr in doc.xpath("//table//tr[./td]"):
            cells = [td.text_content().strip() for td in tr.xpath("./td")]
            if len(cells) != len(cols):
                continue
            rows.append({c: _coerce(c, v) for c, v in zip(cols, cells)})
        return rows
    if fmt == "text":
        out = []
        for line in resp_body.splitlines():
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split("\t")]
            d = {c: _coerce(c, parts[i]) if i < len(parts) else _coerce(c, "")
                 for i, c in enumerate(cols)}
            out.append(d)
        return out
    raise ValueError("unknown fmt: %s" % fmt)


def fetch_batch(http: Http):
    """Collect records page by page, tolerating an interruption.

    A page that cannot be retrieved after the configured retries does **not**
    raise and is **not** turned into a domain event: the pages already obtained
    are returned, together with ``complete=False`` and a description of the
    interruption.  Callers must not advance their incremental watermark past a
    gap, so a later successful run re-reads the same window.  Source
    availability itself is still governed by :class:`Http`'s retry policy.
    """
    max_pages = int(getattr(SPEC, "max_pages", 200))
    records, attempts, page = [], 0, 1
    completion = {"complete": True, "pages": 0, "error": None,
                  "interrupted_page": None}
    while True:
        try:
            status, _hdr, body, att = http.get(
                "/" + SPEC.endpoint, params={"page": page})
            attempts += att + 1
            if status != 200:
                raise RuntimeError("status=%s" % status)
            page_recs = parse(body, SPEC.fmt)
        except Exception as exc:  # transport exhausted or malformed response
            completion.update({"complete": False,
                               "interrupted_page": page,
                               "error": "%s: %s" % (type(exc).__name__, exc)})
            break
        records.extend(page_recs)
        completion["pages"] = page
        if len(page_recs) < SPEC.page_size:
            break
        page += 1
        if page > max_pages:
            completion.update({"complete": False,
                               "interrupted_page": page,
                               "error": "page limit %d reached" % max_pages})
            break
    return records, attempts, completion


def fetch_all(http: Http):
    """Collect records from the local source, raising on an incomplete read.

    Retained for backward compatibility: callers that treat any interrupted
    page as a hard failure get the original ``RuntimeError``.  The pipeline
    itself uses :func:`fetch_batch`, which preserves the pages already read.
    """
    records, attempts, completion = fetch_batch(http)
    if not completion["complete"]:
        raise RuntimeError("fetch failed status=%s page=%s"
                           % (completion.get("error"), completion.get("interrupted_page")))
    return records, attempts



# --------------------------------------------------------------------------- #
# Record identity helpers.
# --------------------------------------------------------------------------- #
def canonical(d):
    return json.dumps(d, sort_keys=True, ensure_ascii=False)


def content_hash(d):
    return hashlib.sha256(canonical(d).encode()).hexdigest()[:24]


def dedup(records):
    seen, out, dup = set(), [], 0
    for r in records:
        h = content_hash(r)
        if h in seen:
            dup += 1
            continue
        seen.add(h)
        out.append(r)
    return out, dup


def normalize(r):
    d = {k: (v.strip() if isinstance(v, str) else v) for k, v in r.items()}
    if isinstance(d.get("status"), str):
        d["status"] = d["status"].lower()
    return d


def _apply_kernel(records):
    k = importlib.import_module(".kernel", __package__)
    for r in records:
        if hasattr(k, "process"):
            r.update(k.process(r))
    if hasattr(k, "reduce"):
        records = k.reduce(records)
    return records


# --------------------------------------------------------------------------- #
# Collection pipeline.
# --------------------------------------------------------------------------- #
def _ingest_events(store, records, run_id, source, now_us):
    """Append observations to the event log.

    Returns ``(inserted, updated)`` counts.  In incremental mode the record view
    is filtered by the watermark, but *every* fetched row is still offered to
    the event log: an event that arrives late is exactly what the log must
    keep, and the event id makes the operation idempotent.
    """
    inserted = updated = 0
    seen = set()
    for record in records:
        event = events.build_event(record, run_id=run_id, source=source,
                                   now_us=now_us)
        if event["event_id"] in seen:
            continue  # an intra-batch repeat is one observation, not two
        seen.add(event["event_id"])
        if store.append_event(event) == "inserted":
            inserted += 1
        else:
            updated += 1
    return inserted, updated


def run(mode="full", con=None, now=None, run_id=""):
    own = con is None
    con = con or Store().connect()
    store = Store(con)
    sleeper = Sleeper()
    http = Http(Transport(), sleeper)
    now_us = timeutil.epoch_us(now)
    if now_us is None:
        now_us = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
    run_id = run_id or "run-%d" % now_us
    try:
        records, attempts, completion = fetch_batch(http)
        norm = [normalize(dict(r)) for r in records]
        norm, dup_in_batch = dedup(norm)
        norm = _apply_kernel(norm)

        wm = store.watermark()
        touched = norm
        if mode == "incremental" and wm:
            touched = [r for r in norm if str(r.get("ts", "")) > wm]

        ingested = sum(1 for r in touched if store.upsert(r))
        ev_inserted, ev_updated = _ingest_events(
            store, records, run_id, SPEC.endpoint, now_us)
        total = store.count()

        # Only advance the watermark over a complete read: a gap means later
        # pages might hold events we have not seen yet.
        if completion["complete"]:
            new_wm = max([str(r.get("ts", "")) for r in norm] + [wm or ""])
            if new_wm:
                store.set_watermark(new_wm)

        return {"engine": "crawl", "mode": mode, "fetched": len(records),
                "duplicates": dup_in_batch, "ingested": ingested, "count": total,
                "http_attempts": attempts, "slept": round(sleeper.slept, 4),
                "watermark": store.watermark(),
                "events_inserted": ev_inserted, "events_updated": ev_updated,
                "events_total": store.event_count(),
                "partial": not completion["complete"],
                "interrupted_page": completion.get("interrupted_page"),
                "fetch_error": completion.get("error")}
    finally:
        if own:
            con.close()


# --------------------------------------------------------------------------- #
# Session pipeline.
# --------------------------------------------------------------------------- #
class Rpa:
    def __init__(self):
        self.t = Transport()
        self.sleeper = Sleeper()
        self.log = []
        self.captcha_solved = False

    def login(self):
        status, _h, _b = self.t.request("POST", "/login",
                                        json_body={"u": "operator", "p": "local"})
        if status != 200:
            raise RuntimeError("login failed status=%s" % status)
        self.log.append("login")
        return True

    def _csrf(self):
        return {"x-csrf": self.t.cookies.get("csrf", "")}

    def _query_page(self, page):
        status, _h, body = self.t.request("GET", "/query", params={"page": page},
                                          headers=self._csrf())
        if status != 200:
            raise RuntimeError("query failed status=%s" % status)
        return json.loads(body)

    def collect(self):
        """Collect query pages, resuming past a captcha interruption.

        The gate is a session challenge, not a business event, so it never
        produces a status observation.  Pages are tracked by number: a page is
        consumed exactly once even if the portal asks us to repeat the request
        after solving the challenge, and no page is skipped.
        """
        pages, page = {}, 1
        max_pages = int(getattr(SPEC, "max_pages", 200))
        while True:
            self.sleeper.sleep(0.1)
            data = self._query_page(page)
            if page not in pages:
                pages[page] = data.get("items", [])
            if data.get("captcha_required") and not self.captcha_solved:
                ok = self._solve_captcha()
                if not ok:
                    raise RuntimeError("captcha solve rejected")
                self.captcha_solved = True
                # Repeat the same page; it was not consumed, so nothing is lost
                # and nothing is counted twice.
                continue
            if not data.get("has_more"):
                break
            page += 1
            if page > max_pages:
                break
        out = []
        for number in sorted(pages):
            out.extend(pages[number])
        self.log.append("collect:%d" % len(out))
        return out

    def _solve_captcha(self):
        status, _h, body = self.t.request("POST", "/captcha",
                                          json_body={"code": self.t.cookies.get("challenge", "")},
                                          headers=self._csrf())
        ok = status == 200 and json.loads(body).get("ok") is True
        self.log.append("captcha:%s" % ("solved" if ok else "failed"))
        return ok

    def submit(self, record):
        token = content_hash(record)
        status, _h, body = self.t.request("POST", "/submit",
                                          json_body={"token": token, "record": record},
                                          headers=self._csrf())
        data = json.loads(body)
        self.log.append("submit:%s" % ("created" if data.get("created") else "dedup"))
        return bool(data.get("created"))


def run_rpa(con=None, now=None, run_id=""):
    own = con is None
    con = con or Store().connect()
    store = Store(con)
    r = Rpa()
    now_us = timeutil.epoch_us(now)
    if now_us is None:
        now_us = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
    run_id = run_id or "rpa-%d" % now_us
    try:
        logged = r.login()
        items = r.collect()
        norm = [normalize(dict(it)) for it in items]
        norm, dup = dedup(norm)
        norm = _apply_kernel(norm)
        ingested = sum(1 for x in norm if store.upsert(x))
        ev_inserted, ev_updated = _ingest_events(
            store, items, run_id, "query", now_us)
        total = store.count()
        created = dedup_submit = 0
        for x in norm[:2]:
            if r.submit(x):
                created += 1
            else:
                dedup_submit += 1
        for x in norm[:1]:
            if not r.submit(x):
                dedup_submit += 1
        wm = max([str(x.get("ts", "")) for x in norm] + [""])
        if wm:
            store.set_watermark(wm)
        return {"engine": "rpa", "logged_in": logged, "captcha_solved": r.captcha_solved,
                "collected": len(items), "fetched": len(items), "duplicates": dup,
                "ingested": ingested, "count": total,
                "events_inserted": ev_inserted, "events_updated": ev_updated,
                "events_total": store.event_count(),
                "submit_created": created, "submit_dedup": dedup_submit, "log": r.log}
    finally:
        if own:
            con.close()

