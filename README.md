# certchain

A small offline data-processing service with a local HTTP fixture and SQLite
storage. It is self-contained and does not require network access.

It collects certificate status observations, keeps every observation as
immutable evidence, and answers two different questions credibly:

- what is the certificate's status **now**, and
- what was its status at a **specified historical instant** (for example
  immediately before a rotation).

## Usage

```text
make run       # process the bundled source
make run_inc   # process using the incremental command-line mode
make status    # print current status of every certificate
make test      # run the test suite
make mock      # start the local fixture service
```

The package exposes a Python entry point under `src/certchain`. The fixture
service supports the source formats used by the package, and the command-line
entry point writes results to the local SQLite database. Re-running commands is
safe for an existing database.

## Status history

Collection appends every source row to an append-only `events` table in
addition to the original content-addressed `records` view. A conclusion is
recomputed from that evidence on every query, so re-running after out-of-order
delivery, duplicated rows, an interrupted page, a rule change or restored old
data produces the same, explainable answer.

Queries are read-only and never touch collection state:

```text
python -m certchain.cli --list                       # current status of all certs
python -m certchain.cli --status CER-0004            # current status (JSON)
python -m certchain.cli --status CER-0004 --as-of 2030-01-03T00:00:00Z
python -m certchain.cli --status CER-0004 --as-known 2030-02-01T00:00:00Z
python -m certchain.cli --before CER-0004            # status before its rotation
python -m certchain.cli --history CER-0004 --text
```

The same functions are available from Python:

```python
from certchain import pipeline

pipeline.status_at("CER-0004", as_of="2030-01-03T00:00:00Z")
pipeline.status_before("CER-0004")          # state immediately before rotation
pipeline.history("CER-0004")                # timeline + retained rejections
pipeline.current_statuses()                 # {cert_id: projection}
```

### Semantics

- **Effective time vs knowledge time.** Every event carries the instant the
  change was effective (the source `ts`) and the instant the pipeline first
  learned it. `as_of` filters on the first; `as-known` filters on the second,
  which is how a genuinely late correction is told apart from a fact that was
  always available.
- **Unacceptable events are kept.** An event with no identity, an unparseable
  time, a missing status or a status the current rules do not recognise is
  rejected from conclusions but retained verbatim and reported, with its
  original payload and the reason.
- **Corrections are bounded.** A correction that arrives materially later than
  a newer already-known state may only rewrite the recent past. Its effective
  time must fall within `correction_window_days` (default 90, configurable with
  `--window-days`); otherwise it is retained but excluded as
  `beyond_correction_window`.
- **Terminal state latches.** A stale `active` row arriving after a revocation
  or rotation cannot resurrect a closed certificate; it is kept and reported as
  `after_terminal`.
- **Rules are applied at read time** from the retained raw status word, and the
  applied `rules_version` is part of every answer, so a rule change is visible
  and re-applied consistently to the whole history.
- **Interruptions are not business events.** A page that cannot be retrieved
  does not fabricate a status and does not advance the incremental watermark;
  the pages already read are kept, and the next complete run recovers the gap.
  A portal challenge is resumed by re-reading the gated page, not skipping it.

Source availability still follows the existing collection rules (`Http` bounded
retries with backoff), and unchanged source data continues to produce the same
records as before.
