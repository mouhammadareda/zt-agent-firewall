"""Append-only audit log (JSON Lines). The evaluation reads results from here, not from model text."""
import json, os, threading, time

from . import config

_lock = threading.Lock()


def log(event: str, **fields) -> dict:
    rec = {"ts": round(time.time(), 3), "mode": config.MODE, "event": event, **fields}
    os.makedirs(os.path.dirname(config.AUDIT_FILE), exist_ok=True)
    with _lock, open(config.AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def tail(n: int = 50) -> list[dict]:
    if not os.path.exists(config.AUDIT_FILE):
        return []
    with _lock, open(config.AUDIT_FILE, encoding="utf-8") as f:
        lines = f.readlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out
