"""Configuration A (no protection): the agent executes tools ITSELF, with no gateway, no policy,
no allowlist. Used only as the evaluation baseline."""
import os, urllib.request

WORKSPACE = os.getenv("ZT_WORKSPACE", "/workspace")


def _p(path: str) -> str:
    return os.path.join(WORKSPACE, path.replace("workspace/", "", 1).lstrip("/"))


def _http(req):
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as r:
            return f"HTTP {r.status}\n" + r.read(50_000).decode("utf-8", "replace")
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


def execute(tool: str, args: dict) -> str:
    try:
        if tool == "list_files":
            out = [os.path.relpath(os.path.join(r, f), WORKSPACE) for r, _, fs in os.walk(WORKSPACE) for f in fs]
            return "\n".join(sorted(out))
        if tool == "read_file":
            with open(_p(args["path"]), encoding="utf-8", errors="replace") as f:
                return f.read(50_000)
        if tool == "write_file":
            p = _p(args["path"]); os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(args["content"])
            return f"wrote {len(args['content'])} chars to {args['path']}"
        if tool == "fetch_url":
            return _http(urllib.request.Request(args["url"]))
        if tool == "http_post":
            return _http(urllib.request.Request(args["url"], data=str(args["body"]).encode(), method="POST"))
        return f"ERROR: unknown tool {tool}"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"
