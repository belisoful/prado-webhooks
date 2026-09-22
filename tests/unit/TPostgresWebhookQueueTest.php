<?php

use Prado\Data\TDbConnection;

/**
 * The queue against PostgreSQL, which disagrees with both the others: its auto-increment is
 * a sequence rather than a column attribute, the id of an inserted row is reported by naming
 * that sequence, and index names are unique per schema rather than per table.
 *
 * Point it at a server with the environment, and it skips when there is none:
 *
 * ```
 * PRADO_WEBHOOKS_PGSQL_DSN='pgsql:host=127.0.0.1;dbname=prado_webhooks_test' \
 * PRADO_WEBHOOKS_PGSQL_USER=prado_webhooks \
 * PRADO_WEBHOOKS_PGSQL_PASSWORD=prado_webhooks \
 * composer unittest
 * ```
 *
 * `tests/initdb_pgsql.sql` creates that database and role.
 */
class TPostgresWebhookQueueTest extends TWebhookQueueDriverTestCase
{
	protected function newConnection(): TDbConnection
	{
		$dsn = getenv('PRADO_WEBHOOKS_PGSQL_DSN');
		if ($dsn === false || $dsn === '') {
			$this->markTestSkipped('PRADO_WEBHOOKS_PGSQL_DSN is not set');
		}
		if (!in_array('pgsql', PDO::getAvailableDrivers(), true)) {
			$this->markTestSkipped('pdo_pgsql is not loaded');
		}

		return new TDbConnection(
			$dsn,
			(string) getenv('PRADO_WEBHOOKS_PGSQL_USER'),
			(string) getenv('PRADO_WEBHOOKS_PGSQL_PASSWORD')
		);
	}

	protected function driverName(): string
	{
		return 'pgsql';
	}
}
