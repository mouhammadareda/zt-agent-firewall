"""1. Request validator: schema, known tool, argument types and sizes, path safety."""
import json, posixpath
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from . import config

TOOLS = {
    "list_files": {},
    "read_file": {"path": str},
    "write_file": {"path": str, "content": str},
    "fetch_url": {"url": str},
    "http_post": {"url": str, "body": str},
}


class ToolCall(BaseModel):
    task_id: str = Field(min_length=1, max_length=64)
    tool: str
    args: dict = Field(default_factory=dict)


class ValidationError(Exception):
    pass


def safe_rel_path(p: str) -> str:
    p = p.strip().replace("\\", "/")
    if p.startswith("workspace/"):
        p = p[len("workspace/"):]
    if ".." in p.split("/") or p.startswith("/"):
        raise ValidationError(f"unsafe path: {p!r}")
    norm = posixpath.normpath(p)
    if not norm or norm == "." or "\x00" in norm:
        raise ValidationError(f"unsafe path: {p!r}")
    return norm


def validate(call: ToolCall) -> dict:
    """Returns normalised args or raises ValidationError."""
    if call.tool not in TOOLS:
        raise ValidationError(f"unknown tool: {call.tool}")
    spec = TOOLS[call.tool]
    extra = set(call.args) - set(spec)
    if extra:
        raise ValidationError(f"unexpected arguments: {sorted(extra)}")
    args = {}
    for name, typ in spec.items():
        if name not in call.args:
            raise ValidationError(f"missing argument: {name}")
        v = call.args[name]
        if not isinstance(v, typ):
            raise ValidationError(f"argument {name} must be {typ.__name__}")
        args[name] = v
    if len(json.dumps(args)) > config.MAX_ARG_CHARS:
        raise ValidationError("arguments too large")
    if "path" in args:
        args["path"] = safe_rel_path(args["path"])
    if "url" in args:
        u = urlparse(args["url"])
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValidationError("url must be http(s) with a host")
    return args
