"""2. Policy engine: YAML rules, first match wins, default deny."""
import fnmatch
from urllib.parse import urlparse

import yaml

from . import config

ALLOW, DENY, APPROVE = "allow", "deny", "approve"


class Policy:
    def __init__(self, path: str = config.POLICY_FILE):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self.default = data.get("default", DENY)
        self.allowlist = [h.lower() for h in data.get("egress_allowlist", [])]
        self.rules = data.get("rules", [])

    def host_allowed(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return any(host == h or host.endswith("." + h) for h in self.allowlist)

    def _match(self, rule: dict, tool: str, args: dict) -> bool:
        tools = rule.get("tool")
        tools = [tools] if isinstance(tools, str) else (tools or [])
        if tool not in tools:
            return False
        if "path" in rule and not any(fnmatch.fnmatch(args.get("path", ""), g) for g in _list(rule["path"])):
            return False
        if "host_in_allowlist" in rule and self.host_allowed(args.get("url", "")) != rule["host_in_allowlist"]:
            return False
        return True

    def decide(self, tool: str, args: dict) -> tuple[str, str]:
        for i, rule in enumerate(self.rules):
            if self._match(rule, tool, args):
                return rule["decision"], rule.get("name", f"rule#{i}")
        return self.default, "default"


def _list(x):
    return [x] if isinstance(x, str) else list(x)
