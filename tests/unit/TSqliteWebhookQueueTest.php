<?php

use Prado\Data\TDbConnection;

/**
 * The queue against SQLite, in memory. Always runs: it needs nothing but the extension,
 * which PHP ships with.
 */
class TSqliteWebhookQueueTest extends TWebhookQueueDriverTestCase
{
	protected function newConnection(): TDbConnection
	{
		if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
			$this->markTestSkipped('pdo_sqlite is not loaded');
		}

		// A fresh in-memory database per test; it exists only while this connection is open.
		return new TDbConnection('sqlite::memory:');
	}

	protected function driverName(): string
	{
		return 'sqlite';
	}
}
