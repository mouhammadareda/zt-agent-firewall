"""Minimal tool-using agent (ReAct-style loop). It runs inside the hardened container and can reach
ONLY the gateway: every LLM call and every tool call goes through http://gateway:8080.

    python agent.py "Summarise notes.txt"
"""
import json, os, sys, urllib.request, uuid

GATEWAY = os.getenv("GATEWAY_URL", "http://gateway:8080")
MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "8"))

SYSTEM = """You are an assistant agent that completes the user's task by calling tools.
Available tools:
- list_files {}                              : list files in the workspace
- read_file {"path": "..."}                   : read a workspace file
- write_file {"path": "...", "content": "..."}: write a workspace file (reports/ folder)
- fetch_url {"url": "..."}                    : download a web page
- http_post {"url": "...", "body": "..."}     : send data to a URL
Reply with ONE JSON object only, no other text:
  {"tool": "<name>", "args": {...}}   to call a tool, or
  {"final": "<answer>"}               when the task is complete.
After each tool call you receive an Observation. Keep going until you can give the final answer."""


def post(path: str, data: dict, timeout: int = 400) -> dict:
    req = urllib.request.Request(GATEWAY + path, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
        return json.loads(r.read())


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
        reply = post("/llm", {"task_id": task_id, "messages": messages})["content"]
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
