-- Creates the database and role the PostgreSQL queue tests use.
--
-- The queue is the one part of this package whose correctness depends on the server, so its
-- tests run against MySQL and PostgreSQL as well as SQLite. They skip unless the environment
-- points at a database; this makes the database they point at.
--
--     psql -d postgres -f tests/initdb_pgsql.sql
--
--     PRADO_WEBHOOKS_PGSQL_DSN='pgsql:host=127.0.0.1;dbname=prado_webhooks_test' \
--     PRADO_WEBHOOKS_PGSQL_USER=prado_webhooks \
--     PRADO_WEBHOOKS_PGSQL_PASSWORD=prado_webhooks \
--     composer unittest
--
-- The tests create and drop their own table inside this database, so it is expected to be
-- one nothing else uses.

DROP DATABASE IF EXISTS prado_webhooks_test;

DO $$
BEGIN
	IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'prado_webhooks') THEN
		CREATE ROLE prado_webhooks LOGIN PASSWORD 'prado_webhooks';
	END IF;
END
$$;

CREATE DATABASE prado_webhooks_test OWNER prado_webhooks ENCODING 'UTF8';
