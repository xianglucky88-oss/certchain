
from types import SimpleNamespace

ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "certchain.db"

SPEC = SimpleNamespace(
    slug="certchain",
    fmt="text",
    engine="crawl",
    endpoint="items",
    columns=["id", "name", "value", "status", "ts", "issuer"],
    page_size=4,
    int_fields=["value"],
    ts_field="ts",
)
