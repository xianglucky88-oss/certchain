
"""Command-line entry point.

``python -m certchain.cli`` runs a collection pass (unchanged behaviour).
Read-only status queries never mutate the database:

    --status CERT [--as-of TS] [--as-known TS]   status at an effective instant
    --before CERT [--at TS] [--as-known TS]      status immediately before TS
                                                 (default: before the rotation)
    --history CERT [--as-known TS]               full history with provenance
    --list [--as-known TS]                       current status of every cert
    --window-days N                              override the correction window
    --text                                       human-readable output
"""
import json
import sys

from . import pipeline


def _parse(argv):
    opts = {"mode": "full", "query": None, "cert": None,
            "as_of": None, "as_known": None, "at": None,
            "window_days": None, "text": False}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--incremental":
            opts["mode"] = "incremental"
        elif arg == "--full":
            opts["mode"] = "full"
        elif arg == "--text":
            opts["text"] = True
        elif arg == "--list":
            opts["query"] = "list"
        elif arg in ("--status", "--history", "--before"):
            opts["query"] = arg[2:]
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                i += 1
                opts["cert"] = argv[i]
        elif arg in ("--as-of", "--as-known", "--at", "--window-days") \
                and i + 1 < len(argv):
            i += 1
            opts[arg[2:].replace("-", "_")] = argv[i]
        else:
            raise SystemExit("unknown argument: %s" % arg)
        i += 1
    return opts


def _emit(payload, text):
    if text and isinstance(payload, dict) and (
            "cert_id" in payload or "current" in payload):
        from .status import explain
        print(explain(payload))
        return
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    opts = _parse(argv)
    window = int(opts["window_days"]) if opts["window_days"] is not None else None

    if opts["query"] == "list":
        results = pipeline.current_statuses(as_known=opts["as_known"],
                                            window_days=window)
        if opts["text"]:
            for cid in sorted(results):
                item = results[cid]
                print("%s\t%s\t%s" % (cid, item["state"],
                                      item.get("effective_ts") or ""))
            return
        _emit({cid: {"state": item["state"], "kind": item["kind"],
                     "effective_ts": item.get("effective_ts"),
                     "decided_by": (item.get("decided_by") or {}).get("event_id"),
                     "excluded": len(item.get("excluded") or []),
                     "rejected": len(item.get("rejected") or [])}
               for cid, item in results.items()}, False)
        return

    if opts["query"] and not opts["cert"]:
        raise SystemExit("--%s requires a certificate id" % opts["query"])

    if opts["query"] == "status":
        _emit(pipeline.status_at(opts["cert"], opts["as_of"], opts["as_known"],
                                 window_days=window), opts["text"])
        return
    if opts["query"] == "before":
        _emit(pipeline.status_before(opts["cert"], opts["at"], opts["as_known"],
                                     window_days=window), opts["text"])
        return
    if opts["query"] == "history":
        _emit(pipeline.history(opts["cert"], opts["as_known"], window_days=window),
              opts["text"])
        return

    print(json.dumps(pipeline.run(mode=opts["mode"]), ensure_ascii=False))


if __name__ == "__main__":
    main()
