#!/usr/bin/env bash
# Generates throwaway local secrets for the compose stack.
# Never overwrites existing files, never prints values.
set -euo pipefail
cd "$(dirname "$0")/.."

for f in .env.docker.app .env.docker.db .env.docker.redis; do
  if [ -e "$f" ]; then
    echo "refusing to overwrite $f (delete it first to regenerate)" >&2
    exit 1
  fi
done

umask 077
hex()  { python3 -c 'import secrets; print(secrets.token_hex(24))'; }
urlsafe() { python3 -c 'import secrets; print(secrets.token_urlsafe(64))'; }

db_super_pw=$(hex)
db_app_pw=$(hex)
redis_pw=$(hex)
secret_key=$(urlsafe)

cat > .env.docker.db <<EOF
POSTGRES_PASSWORD=${db_super_pw}
APP_DB_NAME=securevault_db
APP_DB_USER=securevault_user
APP_DB_PASSWORD=${db_app_pw}
EOF

cat > .env.docker.redis <<EOF
REDIS_PASSWORD=${redis_pw}
EOF

cat > .env.docker.app <<EOF
SECRET_KEY=${secret_key}
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1
HTTPS_ONLY=False
EMAIL_HOST=localhost
DB_NAME=securevault_db
DB_USER=securevault_user
DB_PASSWORD=${db_app_pw}
DB_HOST=db
DB_PORT=5432
CELERY_BROKER_URL=redis://:${redis_pw}@redis:6379/0
EOF

echo "wrote .env.docker.app .env.docker.db .env.docker.redis (mode 600)"
