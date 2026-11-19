
"""Public orchestration entry point.

Collection (:func:`run`) and read-only status queries (:func:`status_at`,
:func:`history`, :func:`status_before`) share the same retained event log.
Queries never mutate state and are safe to run against a copy of the database.
"""
from . import framework, status as status_engine
from .store import Store


def run(mode="full", con=None, now=None, run_id=""):
    from .config import SPEC
    if SPEC.engine == "rpa":
        return framework.run_rpa(con=con, now=now, run_id=run_id)
    return framework.run(mode=mode, con=con, now=now, run_id=run_id)


def _events(con, cert_id=None):
    """Load events without creating or migrating a database when unneeded."""
    if con is None:
        con = Store().connect()
        try:
            return Store(con).all_events(cert_id)
        finally:
            con.close()
    return Store(con).all_events(cert_id)


def status_at(cert_id, as_of=None, as_known=None, con=None, window_days=None):
    """Status of ``cert_id`` at effective instant ``as_of`` (default: now).

    ``as_known`` additionally restricts the answer to what had been observed
    by that knowledge instant, which is how a late correction is told apart
    from a fact that was always there.
    """
    return status_engine.project(_events(con, cert_id), cert_id, as_of, as_known,
                                 window_days)


def status_before(cert_id, of=None, as_known=None, con=None, window_days=None):
    """Status strictly before ``of`` (default: the latest terminal event).

    This is the literal "state immediately before rotation" query.
    """
    return status_engine.before(_events(con, cert_id), cert_id, of, as_known,
                                window_days)


def history(cert_id, as_known=None, con=None, window_days=None):
    """Full explainable history for one certificate."""
    return status_engine.history(_events(con, cert_id), cert_id, as_known,
                                 window_days)


def current_statuses(con=None, as_known=None, window_days=None):
    """Current status for every known certificate, keyed by certificate id."""
    events = _events(con)
    return status_engine.project(events, None, None, as_known, window_days)
