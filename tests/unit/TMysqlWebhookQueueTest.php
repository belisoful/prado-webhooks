<?php

use Prado\Data\TDbConnection;

/**
 * The queue against MySQL, which is what catches the things SQLite is relaxed about: MySQL
 * has no `IF NOT EXISTS` on `CREATE INDEX`, its own auto-increment spelling, and its own
 * view of what a placeholder may be named.
 *
 * Point it at a server with the environment, and it skips when there is none:
 *
 * ```
 * PRADO_WEBHOOKS_MYSQL_DSN='mysql:host=127.0.0.1;dbname=prado_webhooks_test' \
 * PRADO_WEBHOOKS_MYSQL_USER=prado_webhooks \
 * PRADO_WEBHOOKS_MYSQL_PASSWORD=prado_webhooks \
 * composer unittest
 * ```
 *
 * `tests/initdb_mysql.sql` creates that database and user.
 */
class TMysqlWebhookQueueTest extends TWebhookQueueDriverTestCase
{
	protected function newConnection(): TDbConnection
	{
		$dsn = getenv('PRADO_WEBHOOKS_MYSQL_DSN');
		if ($dsn === false || $dsn === '') {
			$this->markTestSkipped('PRADO_WEBHOOKS_MYSQL_DSN is not set');
		}
		if (!in_array('mysql', PDO::getAvailableDrivers(), true)) {
			$this->markTestSkipped('pdo_mysql is not loaded');
		}

		return new TDbConnection(
			$dsn,
			(string) getenv('PRADO_WEBHOOKS_MYSQL_USER'),
			(string) getenv('PRADO_WEBHOOKS_MYSQL_PASSWORD')
		);
	}

	protected function driverName(): string
	{
		return 'mysql';
	}
}
