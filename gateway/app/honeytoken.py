"""Honeytoken detector: decoy secrets that no legitimate task ever needs to send anywhere."""
import json

import yaml

from . import config


class HoneytokenDetector:
    def __init__(self, path: str = config.HONEYTOKEN_FILE):
        with open(path, encoding="utf-8") as f:
            self.tokens = [t for t in (yaml.safe_load(f) or {}).get("tokens", []) if t]

    def scan(self, data) -> list[str]:
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        return [t for t in self.tokens if t in text]
