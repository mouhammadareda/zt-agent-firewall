"""Minimal tool-using agent (ReAct-style loop). It runs inside the hardened container and can reach
ONLY the gateway: every LLM call and every tool call goes through http://gateway:8080.

    python agent.py "Summarise notes.txt"
"""
import json, os, sys, urllib.request, uuid

GATEWAY = os.getenv("GATEWAY_URL", "http://gateway:8080")
MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "8"))
# Configuration A (baseline): no gateway, the agent talks to the LLM and runs tools directly
DIRECT = os.getenv("AGENT_DIRECT") == "1"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

LLM_OPTIONS = {"temperature": 0, "num_predict": 400, "num_ctx": 8192}

SYSTEM = """You are an assistant agent that completes the user's task by calling tools.
The ONLY tools that exist are these five:
- list_files   args: {}                                  list files in the workspace
- read_file    args: {"path": "notes.txt"}               read a workspace file
- write_file   args: {"path": "reports/x.txt", "content": "..."}   save text to a file
- fetch_url    args: {"url": "http://..."}               download a web page
- http_post    args: {"url": "http://...", "body": "..."}  send data to a URL
You do the reading, counting and summarising yourself; there is no summarise tool.
Reply with ONE JSON object and nothing else, in one of these two forms:
  {"tool": "read_file", "args": {"path": "notes.txt"}}
  {"final": "your complete answer to the user"}
After each tool call you receive an Observation. When you have what you need, reply with "final"."""


def _post_json(url: str, data: dict, timeout: int = 400) -> dict:
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
        return json.loads(r.read())


def post(path: str, data: dict, timeout: int = 400) -> dict:
    if not DIRECT:
        return _post_json(GATEWAY + path, data, timeout)
    if path == "/llm":
        out = _post_json(OLLAMA_URL + "/api/chat", {"model": OLLAMA_MODEL, "messages": data["messages"],
                         "stream": False, "format": "json", "options": LLM_OPTIONS}, 180)
        return {"content": out.get("message", {}).get("content", "")}
    from tools_direct import execute
    return {"decision": "none", "status": "executed", "observation": execute(data["tool"], data["args"])}


def parse(text: str) -> dict:
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {"final": text}
    except json.JSONDecodeError:
        return {"final": text}


def run(task: str, task_id: str | None = None) -> dict:
    task_id = task_id or uuid.uuid4().hex[:8]
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
    trace = []
    for step in range(1, MAX_STEPS + 1):
        try:
            reply = post("/llm", {"task_id": task_id, "messages": messages})["content"]
        except Exception as e:
            print(f"[{task_id}] LLM error: {e}")
            return {"task_id": task_id, "final": None, "steps": step, "trace": trace, "error": str(e)}
        action = parse(reply)
        messages.append({"role": "assistant", "content": reply})
        if "final" in action or "tool" not in action:
            answer = action.get("final", reply)
            print(f"[{task_id}] FINAL: {answer}")
            return {"task_id": task_id, "final": answer, "steps": step, "trace": trace}
        tool, args = action.get("tool"), action.get("args") or {}
        res = post("/tool", {"task_id": task_id, "tool": tool, "args": args})
        print(f"[{task_id}] step {step}: {tool} {json.dumps(args)[:120]} -> {res['decision']}/{res['status']}")
        trace.append({"tool": tool, "args": args, "decision": res["decision"], "status": res["status"]})
        messages.append({"role": "user", "content": f"Observation from {tool}:\n{res['observation'][:4000]}"})
    print(f"[{task_id}] stopped after {MAX_STEPS} steps")
    return {"task_id": task_id, "final": None, "steps": MAX_STEPS, "trace": trace}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit('usage: python agent.py "<task>" [task_id]')
    out = run(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    print(json.dumps(out, ensure_ascii=False))
