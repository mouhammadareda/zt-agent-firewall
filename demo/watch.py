#!/usr/bin/env python3
"""Live viewer for the demo panes.
    python3 demo/watch.py audit      -> gateway decisions as they happen
    python3 demo/watch.py attacker   -> everything the attacker's server receives
"""
import json, os, re, sys, time, urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODE = sys.argv[1] if len(sys.argv) > 1 else "audit"
FILE = os.path.join(ROOT, "data/audit/audit.jsonl" if MODE == "audit" else "data/attacker/hits.jsonl")
HONEY = re.findall(r"^\s*-\s*(\S+)", open(os.path.join(ROOT, "gateway/policies/honeytokens.yaml")).read(), re.M)

R, G, Y, B, C, DIM, BOLD, RST = "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[36m", "\033[2m", "\033[1m", "\033[0m"
INV = "\033[7m"


def header():
    os.system("clear")
    if MODE == "audit":
        print(f"{BOLD}{B}  GATEWAY AUDIT LOG  (every decision, live){RST}\n")
    else:
        print(f"{BOLD}{R}  ATTACKER SERVER  attacker:9000  (what reached the attacker){RST}\n")
        print(f"{DIM}  empty = nothing leaked{RST}\n")


def short(v, n=70):
    s = json.dumps(v, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + "…"


def show_audit(e):
    t = time.strftime("%H:%M:%S", time.localtime(e.get("ts", time.time())))
    ev = e.get("event")
    if ev == "tool_call":
        st, dec = e.get("status"), e.get("decision")
        col = G if st == "executed" else (Y if st in ("expired", "denied") else R)
        tag = {"executed": "ALLOWED ", "blocked": "BLOCKED ", "invalid": "INVALID ", "denied": "DENIED  ",
               "expired": "EXPIRED ", "error": "ERROR   ", "grant_invalid": "NO GRANT"}.get(st, st)
        print(f"{DIM}{t}{RST} {col}{BOLD}{tag}{RST} {e.get('tool'):<10} {short(e.get('args'), 60)}")
        if e.get("rule"):
            print(f"{DIM}          rule: {e['rule']}   mode: {e.get('mode')}   {e.get('latency_ms', '')} ms{RST}")
    elif ev == "approval_requested":
        print(f"{DIM}{t}{RST} {Y}{BOLD}APPROVAL?{RST} {e.get('tool'):<10} {short(e.get('args'), 60)}  {Y}-> admin page{RST}")
    elif ev == "admin_decision":
        ok = e.get("approved")
        print(f"{DIM}{t}{RST} {(G if ok else R)}{BOLD}ADMIN {'APPROVED' if ok else 'DENIED'}{RST} request {e.get('request_id')}")
    elif ev == "honeytoken_alert":
        print(f"{DIM}{t}{RST} {R}{INV}{BOLD} HONEYTOKEN ALERT {RST} {R}secret leaving through {e.get('tool')}: {', '.join(e.get('tokens', []))}{RST}")
    elif ev == "gateway_start":
        print(f"{DIM}{t} gateway started (mode {e.get('mode')}){RST}")


def show_hit(h):
    t = time.strftime("%H:%M:%S", time.localtime(h.get("ts", time.time())))
    body = (h.get("path", "") + "\n" + h.get("body", "")).strip()
    body = urllib.parse.unquote_plus(body)
    leaked = [x for x in HONEY if x in body]
    print(f"{R}{INV}{BOLD} {t}  {h.get('method')} {h.get('path', '')[:50]} {RST}")
    for line in body.splitlines()[:8]:
        for x in HONEY:
            line = line.replace(x, f"{INV}{x}{RST}{R}")
        print(f"{R}   {line[:110]}{RST}")
    if leaked:
        print(f"{R}{BOLD}   >>> {len(leaked)} SECRET(S) STOLEN <<<{RST}")
    print()


def follow():
    header()
    pos, ino = 0, None
    while True:
        try:
            st = os.stat(FILE)
            if ino != st.st_ino or st.st_size < pos:   # new or truncated file
                if ino is not None:
                    header()
                ino, pos = st.st_ino, 0
            if st.st_size > pos:
                with open(FILE, encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    for line in f:
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        (show_audit if MODE == "audit" else show_hit)(obj)
                    pos = f.tell()
        except FileNotFoundError:
            pass
        time.sleep(0.3)


if __name__ == "__main__":
    try:
        follow()
    except KeyboardInterrupt:
        pass
