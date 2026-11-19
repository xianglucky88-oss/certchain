
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import hashlib
import json
from fastapi import FastAPI, Request, Response
from certchain.config import SPEC
from certchain.mockdata import build_rows, extra_row

app = FastAPI(title="Local source")
_ALL = build_rows()
_extra = []
_verified_sessions = set()
_accepted_tokens = set()
# Test hooks: pages that should fail, and rows to deliver late.
_fault_pages = {}          # page -> remaining failure count
_fault_status = 500

def _data():
    return _ALL + _extra

def _page_items(page):
    lo, hi = (page - 1) * SPEC.page_size, page * SPEC.page_size
    return _data()[lo:hi]

@app.get("/items")
def items(page: int = 1):
    remaining = _fault_pages.get(page, 0)
    if remaining > 0:
        _fault_pages[page] = remaining - 1
        return Response(status_code=_fault_status)
    data = _page_items(page)
    if SPEC.fmt == "json":
        return {"items": data, "page": page}
    if SPEC.fmt == "text":
        lines = ["\t".join(str(it.get(c, "")) for c in SPEC.columns) for it in data]
        return Response(content="\n".join(lines), media_type="text/plain")
    th = "".join("<th>%s</th>" % c for c in SPEC.columns)
    trs = "".join("<tr>" + "".join("<td>%s</td>" % it.get(c, "") for c in SPEC.columns)
                  + "</tr>" for it in data)
    return Response(content="<html><table><tr>%s</tr>%s</table></html>" % (th, trs),
                    media_type="text/html")

@app.post("/admin/fault")
async def fault(request: Request):
    """Enable a transient failure for a page (offline test hook)."""
    body = await request.json()
    page = int(body.get("page", 1))
    global _fault_status
    _fault_status = int(body.get("status", 500))
    count = int(body.get("count", 1))
    if count > 0:
        _fault_pages[page] = count
    else:
        _fault_pages.pop(page, None)
    return {"page": page, "count": max(count, 0), "status": _fault_status}

@app.post("/admin/append")
async def append(request: Request):
    """Insert a source row (offline test hook for late events)."""
    body = await request.json()
    row = dict(body.get("row") or body)
    position = body.get("position")
    if position is None:
        _extra.append(row)
    else:
        _extra.insert(int(position), row)
    return {"total": len(_data())}

@app.post("/admin/reset")
def reset():
    _extra.clear()
    _fault_pages.clear()
    _verified_sessions.clear()
    _accepted_tokens.clear()
    return {"total": len(_data())}

@app.get("/refresh")
def refresh():
    _extra.append(extra_row(len(_extra) + 1))
    return {"total": len(_data())}

@app.get("/probe")
def probe():
    app.__dict__["_flaky_n"] = app.__dict__.get("_flaky_n", 0) + 1
    if app.__dict__["_flaky_n"] <= 2:
        return Response(status_code=429)
    return {"ok": True, "attempts": app.__dict__["_flaky_n"]}

@app.get("/health")
def health():
    return {"ok": True, "rows": len(_data())}

@app.post("/login")
def login(response: Response):
    sid = "SID-local"
    csrf = "CSRF-local"
    challenge = hashlib.sha256((sid + csrf).encode()).hexdigest()[:4]
    response.set_cookie("sid", sid)
    response.set_cookie("csrf", csrf)
    response.set_cookie("challenge", challenge)
    return {"role": "operator"}

@app.get("/query")
def query(request: Request, page: int = 1):
    if not request.cookies.get("sid"):
        return Response(status_code=401)
    if request.headers.get("x-csrf") != request.cookies.get("csrf"):
        return Response(status_code=403)
    items_page = _page_items(page)
    nxt = _page_items(page + 1)
    sid = request.cookies.get("sid")
    gate = (SPEC.engine == "rpa" and page == 1 and sid not in _verified_sessions
            and len(_data()) > SPEC.page_size)
    return {"items": items_page, "page": page, "has_more": bool(nxt),
            "captcha_required": bool(gate)}

@app.post("/captcha")
async def captcha(request: Request):
    body = await request.json()
    ok = body.get("code") == request.cookies.get("challenge")
    if ok:
        _verified_sessions.add(request.cookies.get("sid"))
    return {"ok": bool(ok)}

@app.post("/submit")
async def submit(request: Request):
    body = await request.json()
    token = body.get("token")
    created = token not in _accepted_tokens
    if created:
        _accepted_tokens.add(token)
    return {"created": bool(created), "token": token}
