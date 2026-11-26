-- Creates this service's own role and database on any PostgreSQL 16+ server: local Docker, a
-- managed host or your own. Run once, as a role allowed to create roles and databases:
--
--   psql "$ADMIN_DATABASE_URL" -v password="$(openssl rand -base64 24)" -f db/bootstrap.sql
--
-- Then set DATABASE_URL=postgres://openrms_accounts:<password>@<host>/openrms_accounts (add ?sslmode=verify-full for
-- a remote server) and start the service: migrations run at startup. The role owns only its own
-- database and cannot connect to other services' databases. Rename freely; nothing else depends
-- on these names.
\set ON_ERROR_STOP on
CREATE ROLE openrms_accounts LOGIN PASSWORD :'password';
-- Managed hosts (Neon, RDS, ...) run this as a non-superuser admin. On PostgreSQL 16+ it must be
-- a member of the role to create a database owned by it.
GRANT openrms_accounts TO CURRENT_USER;
CREATE DATABASE openrms_accounts OWNER openrms_accounts;
REVOKE ALL ON DATABASE openrms_accounts FROM PUBLIC;
