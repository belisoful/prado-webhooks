-- Creates the database and user the MySQL queue tests use.
--
-- The queue is the one part of this package whose correctness depends on the server, so its
-- tests run against a real one as well as against SQLite. They skip unless the environment
-- points at a database; this makes the database they point at.
--
--     mysql -uroot < tests/initdb_mysql.sql
--
--     PRADO_WEBHOOKS_MYSQL_DSN='mysql:host=127.0.0.1;dbname=prado_webhooks_test' \
--     PRADO_WEBHOOKS_MYSQL_USER=prado_webhooks \
--     PRADO_WEBHOOKS_MYSQL_PASSWORD=prado_webhooks \
--     composer unittest
--
-- The tests create and drop their own table inside this database, so it is expected to be
-- one nothing else uses.

DROP DATABASE IF EXISTS `prado_webhooks_test`;
CREATE DATABASE `prado_webhooks_test` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'prado_webhooks'@'%' IDENTIFIED BY 'prado_webhooks';
GRANT ALL ON `prado_webhooks_test`.* TO 'prado_webhooks'@'%';
FLUSH PRIVILEGES;
