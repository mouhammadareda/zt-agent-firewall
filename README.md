# Zero-Trust Cognitive Firewall for Agentic Systems

Senior Project 1 - Syrian Private University, 2026.

Containment of **indirect prompt injection** in tool-using AI agents. The agent runs inside a
hardened Docker container with no network route except to a **policy gateway**. The gateway is
the single Policy Enforcement Point (NIST SP 800-207). It validates every tool call, applies a
YAML policy (default deny), issues **single-use JIT grants** that expire after τ seconds when an
administrator approves a risky action, enforces an egress allowlist, and detects **honeytokens**.
Every decision is written to an append-only audit log.

## Layout

| Path | Purpose |
|---|---|
| `agent/` | Minimal ReAct agent (stdlib only), runs as uid 10001 in a read-only container |
| `gateway/app/validator.py` | 1. Request validator (schema, types, sizes, path safety) |
| `gateway/app/policy.py` | 2. Policy engine, first match wins, default deny |
| `gateway/app/grants.py` | 3. JIT grant manager (approval → single-use grant, TTL τ) |
| `gateway/app/executor.py` | 4. Tool executor (runs outside the agent container) |
| `gateway/app/honeytoken.py` | Honeytoken detector |
| `gateway/app/audit.py` | Audit log (JSON Lines) |
| `gateway/policies/` | `default.yaml` policy and `honeytokens.yaml` |
| `lab/web`, `lab/attacker` | Lab web server (clean + injected pages) and mock attacker endpoint |
| `workspace/` | Files the agent may work on (`secrets.txt` is a decoy) |

## Run

Requires Docker Engine + Compose and Ollama on the host (`qwen2.5:3b`).

```bash
bash scripts/init_env.sh          # creates .env with a random admin password
bash scripts/smoke_test.sh        # build, isolation checks, benign task, injection task
```

Admin page: <http://127.0.0.1:8081> (user `admin`, password from `.env`).

Run a single task:

```bash
docker compose exec agent python agent.py "Summarise notes.txt"
```

Switch configuration (`full` or `container_only`) by editing `ZT_MODE` in `.env`, then
`docker compose up -d`.

## Evaluation configurations

| Config | Description |
|---|---|
| A | No protection — `agent_open` service: no hardening, no gateway, direct LLM/tools/network |
| B | `ZT_MODE=container_only` — caged agent, gateway logs but does not enforce |
| C | `ZT_MODE=full` — complete system |

Run the evaluation (5 benign tasks + 6 attack scenarios on A, B, C):

```bash
python3 eval/run_eval.py --reps 3
```

Metrics: attack success rate (from `data/attacker/hits.jsonl` and the audit log, never from model
text), benign utility, added latency, number of approvals.
