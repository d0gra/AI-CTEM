#!/bin/sh
# Creates the two database roles the platform uses:
#   ctem_owner  owns the schema and runs migrations
#   ctem_app    used by the API and workers; not an owner, no BYPASSRLS, so row-level security applies
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE ctem_owner LOGIN PASSWORD '${CTEM_OWNER_DB_PASSWORD}';
CREATE ROLE ctem_app LOGIN PASSWORD '${CTEM_APP_DB_PASSWORD}' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE ctem OWNER ctem_owner;
SQL
