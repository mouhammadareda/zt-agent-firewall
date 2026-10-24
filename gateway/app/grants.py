"""3. JIT grant manager: pending approvals and single-use grants that expire after tau seconds."""
import hashlib, json, threading, time, uuid

from . import config


def args_hash(tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps([tool, args], sort_keys=True).encode()).hexdigest()


class GrantManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.pending: dict[str, dict] = {}   # request_id -> request
        self.grants: dict[str, dict] = {}    # grant_id   -> grant

    # ---- approval workflow ----
    def create_pending(self, task_id: str, tool: str, args: dict, reason: str) -> dict:
        req = {"id": uuid.uuid4().hex[:12], "task_id": task_id, "tool": tool, "args": args,
               "reason": reason, "created": time.time(), "status": "pending", "grant_id": None}
        with self._lock:
            self.pending[req["id"]] = req
        return req

    def resolve(self, request_id: str, approve: bool) -> dict | None:
        with self._lock:
            req = self.pending.get(request_id)
            if not req or req["status"] != "pending":
                return None
            if approve:
                g = {"id": uuid.uuid4().hex[:12], "hash": args_hash(req["tool"], req["args"]),
                     "expires": time.time() + config.GRANT_TTL_SECONDS, "used": False}
                self.grants[g["id"]] = g
                req.update(status="approved", grant_id=g["id"])
            else:
                req["status"] = "denied"
            return dict(req)

    def wait(self, request_id: str, timeout: float) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            with self._lock:
                req = self.pending[request_id]
                if req["status"] != "pending":
                    return dict(req)
            time.sleep(0.25)
        with self._lock:
            req = self.pending[request_id]
            if req["status"] == "pending":
                req["status"] = "expired"
            return dict(req)

    def list_pending(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.pending.values() if r["status"] == "pending"]

    # ---- grant consumption ----
    def consume(self, grant_id: str, tool: str, args: dict) -> tuple[bool, str]:
        with self._lock:
            g = self.grants.get(grant_id)
            if not g:
                return False, "no such grant"
            if g["used"]:
                return False, "grant already used"
            if time.time() > g["expires"]:
                return False, "grant expired"
            if g["hash"] != args_hash(tool, args):
                return False, "grant does not match this exact action"
            g["used"] = True
            return True, "ok"
