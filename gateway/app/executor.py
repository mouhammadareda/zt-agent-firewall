"""4. Tool executor. Runs OUTSIDE the agent container; the agent never touches files or the network itself."""
import os
import urllib.error
import urllib.request

from . import config


class ToolError(Exception):
    pass


def _ws(path: str) -> str:
    full = os.path.realpath(os.path.join(config.WORKSPACE, path))
    root = os.path.realpath(config.WORKSPACE)
    if not (full == root or full.startswith(root + os.sep)):
        raise ToolError("path escapes the workspace")
    return full


def _http(req: urllib.request.Request) -> str:
    # no proxies, no redirects followed to other hosts (urllib follows same-request redirects;
    # the policy already checked the original host, keep timeouts short)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    try:
        with opener.open(req, timeout=5) as r:
            return f"HTTP {r.status}\n" + r.read(config.FETCH_MAX_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except Exception as e:  # network errors are returned as observations
        raise ToolError(f"network error: {type(e).__name__}: {e}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def execute(tool: str, args: dict) -> str:
    if tool == "list_files":
        out = []
        for root, _, files in os.walk(config.WORKSPACE):
            for f in files:
                out.append(os.path.relpath(os.path.join(root, f), config.WORKSPACE))
        return "\n".join(sorted(out)) or "(empty)"
    if tool == "read_file":
        p = _ws(args["path"])
        if not os.path.isfile(p):
            raise ToolError(f"file not found: {args['path']}")
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read(config.FETCH_MAX_BYTES)
    if tool == "write_file":
        p = _ws(args["path"])
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(args["content"])
        return f"wrote {len(args['content'])} chars to {args['path']}"
    if tool == "fetch_url":
        return _http(urllib.request.Request(args["url"], headers={"User-Agent": "zt-gateway"}))
    if tool == "http_post":
        return _http(urllib.request.Request(args["url"], data=args["body"].encode(), method="POST",
                                            headers={"User-Agent": "zt-gateway", "Content-Type": "text/plain"}))
    raise ToolError(f"no executor for {tool}")
