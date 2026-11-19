
from types import SimpleNamespace

ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "certchain.db"

SPEC = SimpleNamespace(
    slug="certchain",
    scene="TLS certificate expiry/renewal status chain",
    fmt="text",
    engine="crawl",
    kernel="state_machine",
    endpoint="items",
    columns=["id", "name", "value", "status", "ts", "issuer"],
    page_size=4,
    int_fields=["value"],
    ts_field="ts",
    # A correction whose effective time is older than this many days behind the
    # latest known effective time for the same certificate is retained as
    # evidence but is not allowed to rewrite an already-established conclusion.
    correction_window_days=90,
    max_pages=200,
)
