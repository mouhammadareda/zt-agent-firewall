#!/usr/bin/env bash
# Creates .env (never committed) with a random admin password and your user/group ids.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then echo ".env already exists"; exit 0; fi
PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
cat > .env <<EOF
HOST_UID=$(id -u)
HOST_GID=$(id -g)
ZT_MODE=full
ZT_GRANT_TTL=60
ZT_APPROVAL_WAIT=60
OLLAMA_MODEL=qwen2.5:3b
ZT_ADMIN_PASSWORD=$PASS
EOF
chmod 600 .env
mkdir -p data/audit data/attacker
echo "Created .env - admin page: http://127.0.0.1:8081  user: admin"
echo "Show the admin password with:  grep PASSWORD .env"
