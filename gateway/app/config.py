"""Runtime configuration (environment variables)."""
import os

# full           = Configuration C: validator + policy + JIT grants + egress allowlist + honeytokens
# container_only = Configuration B: the agent is still caged in Docker, but the gateway allows
#                  every tool call (it only logs) -> isolates the contribution of the policy layer
MODE = os.getenv("ZT_MODE", "full")

POLICY_FILE = os.getenv("ZT_POLICY_FILE", "/app/policies/default.yaml")
HONEYTOKEN_FILE = os.getenv("ZT_HONEYTOKEN_FILE", "/app/policies/honeytokens.yaml")
WORKSPACE = os.getenv("ZT_WORKSPACE", "/workspace")
AUDIT_FILE = os.getenv("ZT_AUDIT_FILE", "/audit/audit.jsonl")

GRANT_TTL_SECONDS = int(os.getenv("ZT_GRANT_TTL", "60"))       # tau
APPROVAL_WAIT_SECONDS = int(os.getenv("ZT_APPROVAL_WAIT", "60"))

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

ADMIN_USER = os.getenv("ZT_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ZT_ADMIN_PASSWORD", "")

AGENT_PORT = int(os.getenv("ZT_AGENT_PORT", "8080"))
ADMIN_PORT = int(os.getenv("ZT_ADMIN_PORT", "8081"))

MAX_ARG_CHARS = 20_000
FETCH_MAX_BYTES = 50_000
