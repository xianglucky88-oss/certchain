"""Read-only CLI query surface."""
import json

from certchain import cli, pipeline
from certchain.store import Store


def _prepared(store):
    pipeline.run(con=store.con)
    return store.cert_ids()


def test_cli_list_defaults_to_collection(capsys):
    cli.main([])
    out = json.loads(capsys.readouterr().out)
    assert out["engine"] == "crawl"


def test_cli_status_and_history_are_json(capsys):
    con = Store().connect()
    Store(con).reset()
    try:
        ids = _prepared(Store(con))
        capsys.readouterr()
        cli.main(["--status", ids[0]])
        status_out = json.loads(capsys.readouterr().out)
        assert status_out["cert_id"] == ids[0]
        assert "excluded" in status_out and "rejected" in status_out
        cli.main(["--history", ids[0]])
        hist = json.loads(capsys.readouterr().out)
        assert hist["cert_id"] == ids[0]
        assert "timeline" in hist
    finally:
        con.close()


def test_cli_text_is_human_readable(capsys):
    con = Store().connect()
    Store(con).reset()
    try:
        ids = _prepared(Store(con))
        capsys.readouterr()
        cli.main(["--status", ids[0], "--text"])
        text = capsys.readouterr().out
        assert "certificate" in text and ids[0] in text
    finally:
        con.close()


def test_cli_rejects_unknown_arguments():
    try:
        cli.main(["--nope"])
    except SystemExit as exc:
        assert "unknown argument" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected SystemExit")
