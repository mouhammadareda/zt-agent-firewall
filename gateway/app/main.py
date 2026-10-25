"""Policy gateway: the only path from the caged agent to tools, the network and the LLM.

Two listeners:
  :8080  agent-facing API   (/tool, /llm, /health)            -> reachable from the agent network
  :8081  admin page / API   (/admin ...) + HTTP Basic auth    -> published on 127.0.0.1 of the host only
"""
import asyncio, html, json, secrets, time, urllib.request

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn

from . import audit, config
from .executor import ToolError, execute
from .grants import GrantManager
from .honeytoken import HoneytokenDetector
from .policy import ALLOW, APPROVE, DENY, Policy
from .validator import ToolCall, ValidationError, validate

policy = Policy()
grants = GrantManager()
honey = HoneytokenDetector()

agent_app = FastAPI(title="ZT gateway - agent API")
admin_app = FastAPI(title="ZT gateway - admin")


# --------------------------------------------------------------------------- agent API
@agent_app.get("/health")
def health():
    return {"ok": True, "mode": config.MODE, "model": config.OLLAMA_MODEL}


@agent_app.post("/tool")
def tool(call: ToolCall):
    t0 = time.perf_counter()
    base = {"task_id": call.task_id, "tool": call.tool, "args": call.args}

    def done(decision, status, observation, **extra):
        ms = round((time.perf_counter() - t0) * 1000, 1)
        audit.log("tool_call", **base, decision=decision, status=status, latency_ms=ms, **extra)
        return {"decision": decision, "status": status, "observation": observation}

    # 1. validator
    try:
        args = validate(call)
    except ValidationError as e:
        return done("deny", "invalid", f"DENIED: invalid request ({e})", reason=str(e))
    base["args"] = args

    # honeytokens leaving through ANY tool argument
    hits = honey.scan(args)
    if hits:
        audit.log("honeytoken_alert", task_id=call.task_id, tool=call.tool, tokens=hits)
        if config.MODE == "full":
            return done("deny", "blocked", "DENIED: action blocked by security policy", reason="honeytoken")

    # 2. policy engine
    if config.MODE == "full":
        decision, rule = policy.decide(call.tool, args)
    else:  # container_only: log everything, enforce nothing
        decision, rule = ALLOW, "container_only"

    if decision == DENY:
        return done("deny", "blocked", f"DENIED by policy ({rule})", rule=rule)

    # 3. JIT grant (human approval -> single-use grant valid for tau seconds)
    grant_id = None
    if decision == APPROVE:
        req = grants.create_pending(call.task_id, call.tool, args, rule)
        audit.log("approval_requested", task_id=call.task_id, request_id=req["id"], tool=call.tool, args=args)
        res = grants.wait(req["id"], config.APPROVAL_WAIT_SECONDS)
        audit.log("approval_" + res["status"], task_id=call.task_id, request_id=req["id"])
        if res["status"] != "approved":
            return done("approve", res["status"], f"DENIED: administrator approval {res['status']}",
                        rule=rule, request_id=req["id"])
        grant_id = res["grant_id"]
        ok, why = grants.consume(grant_id, call.tool, args)
        if not ok:
            return done("approve", "grant_invalid", f"DENIED: {why}", rule=rule, grant_id=grant_id)

    # 4. executor (+ egress allowlist already enforced by the policy rules)
    try:
        obs = execute(call.tool, args)
        status = "executed"
    except ToolError as e:
        obs, status = f"ERROR: {e}", "error"
    return done(decision, status, obs, rule=rule, grant_id=grant_id)


@agent_app.post("/llm")
async def llm(request: Request):
    body = await request.json()
    msgs = body.get("messages", [])
    payload = {"model": config.OLLAMA_MODEL, "messages": msgs, "stream": False,
               "format": "json", "options": {"temperature": 0, "num_predict": 400, "num_ctx": 8192}}
    t0 = time.perf_counter()

    def call():
        req = urllib.request.Request(config.OLLAMA_URL + "/api/chat", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=180) as r:
            return json.loads(r.read())

    try:
        out = await asyncio.to_thread(call)
    except Exception as e:
        raise HTTPException(502, f"LLM unreachable: {e}")
    content = out.get("message", {}).get("content", "")
    audit.log("llm_call", task_id=body.get("task_id", "?"), n_messages=len(msgs),
              latency_ms=round((time.perf_counter() - t0) * 1000, 1))
    return {"content": content}


# --------------------------------------------------------------------------- admin page
basic = HTTPBasic()


def admin(creds: HTTPBasicCredentials = Depends(basic)):
    ok = config.ADMIN_PASSWORD and secrets.compare_digest(creds.username, config.ADMIN_USER) \
        and secrets.compare_digest(creds.password, config.ADMIN_PASSWORD)
    if not ok:
        raise HTTPException(401, "unauthorized", headers={"WWW-Authenticate": "Basic"})
    return creds.username


@admin_app.get("/", response_class=HTMLResponse)
def admin_page(user: str = Depends(admin)):
    esc = html.escape
    rows = "".join(
        f"<tr><td>{esc(r['id'])}</td><td>{esc(r['task_id'])}</td><td><b>{esc(r['tool'])}</b></td>"
        f"<td><code>{esc(json.dumps(r['args'], ensure_ascii=False))[:400]}</code></td><td>{esc(r['reason'])}</td>"
        f"<td>{int(time.time() - r['created'])}s</td><td>"
        f"<form method=post action='/approve/{r['id']}' style=display:inline><button class=ok>Approve</button></form> "
        f"<form method=post action='/deny/{r['id']}' style=display:inline><button class=no>Deny</button></form></td></tr>"
        for r in grants.list_pending()) or "<tr><td colspan=7>No pending requests</td></tr>"
    log = "".join(
        f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(e['ts']))}</td><td>{esc(e['event'])}</td>"
        f"<td>{esc(str(e.get('tool', '')))}</td><td>{esc(str(e.get('decision', '')))}</td>"
        f"<td>{esc(str(e.get('status', e.get('tokens', ''))))}</td></tr>"
        for e in reversed(audit.tail(30)))
    return f"""<!doctype html><html><head><meta charset=utf-8><meta http-equiv=refresh content=3>
<title>ZT Gateway - Admin</title><style>
body{{font-family:system-ui,sans-serif;margin:24px;background:#f6f8fa;color:#1e2430}}
table{{border-collapse:collapse;width:100%;background:#fff;margin-bottom:24px}}
td,th{{border:1px solid #d0d7de;padding:6px 8px;text-align:left;font-size:14px}}th{{background:#1f3a5f;color:#fff}}
button{{border:0;padding:6px 12px;border-radius:4px;color:#fff;cursor:pointer}}.ok{{background:#2e7d32}}.no{{background:#b03a2e}}
</style></head><body><h2>Zero-Trust Gateway &mdash; mode: {esc(config.MODE)} &mdash; grant TTL {config.GRANT_TTL_SECONDS}s</h2>
<h3>Pending approval requests</h3><table><tr><th>ID</th><th>Task</th><th>Tool</th><th>Arguments</th><th>Rule</th><th>Age</th><th>Decision</th></tr>{rows}</table>
<h3>Audit log (latest 30)</h3><table><tr><th>Time</th><th>Event</th><th>Tool</th><th>Decision</th><th>Status</th></tr>{log}</table>
</body></html>"""


@admin_app.post("/approve/{rid}")
def approve(rid: str, user: str = Depends(admin)):
    if grants.resolve(rid, True):
        audit.log("admin_decision", request_id=rid, approved=True, by=user)
    return RedirectResponse("/", status_code=303)


@admin_app.post("/deny/{rid}")
def deny(rid: str, user: str = Depends(admin)):
    if grants.resolve(rid, False):
        audit.log("admin_decision", request_id=rid, approved=False, by=user)
    return RedirectResponse("/", status_code=303)


@admin_app.get("/api/pending")
def api_pending(user: str = Depends(admin)):
    return grants.list_pending()


# --------------------------------------------------------------------------- entry point
async def _serve():
    servers = [uvicorn.Server(uvicorn.Config(agent_app, host="0.0.0.0", port=config.AGENT_PORT, log_level="warning")),
               uvicorn.Server(uvicorn.Config(admin_app, host="0.0.0.0", port=config.ADMIN_PORT, log_level="warning"))]
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    if not config.ADMIN_PASSWORD:
        raise SystemExit("ZT_ADMIN_PASSWORD is not set (see .env)")
    audit.log("gateway_start", policy_rules=len(policy.rules), allowlist=policy.allowlist)
    asyncio.run(_serve())
