#!/bin/bash
# Runs once, on first start of an empty data volume.
# The application role must NOT be a superuser and must NOT bypass RLS.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --no-psqlrc --username postgres --dbname postgres \
  -v app_db="$APP_DB_NAME" -v app_user="$APP_DB_USER" -v app_pw="$APP_DB_PASSWORD" <<'SQL'
CREATE ROLE :"app_user" LOGIN PASSWORD :'app_pw' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE DATABASE :"app_db" OWNER :"app_user";
SQL
