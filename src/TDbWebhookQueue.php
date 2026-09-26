<?php

/**
 * TDbWebhookQueue class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Exception;
use Prado\Data\TDataSourceConfig;
use Prado\Data\TDbConnection;
use Prado\Data\TDbDriver;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\TModule;
use Prado\TPropertyValue;

/**
 * TDbWebhookQueue class.
 *
 * Keeps queued deliveries in a database table, so a delivery survives the request that
 * raised it, the worker that was sending it, and the machine both were on.
 *
 * ```xml
 * <modules>
 *		<module id="db" class="Prado\Data\TDataSourceConfig">
 *			<database ConnectionString="sqlite:protected/runtime/app.db" />
 *		</module>
 *		<module id="webhook-queue" class="Belisoful\Prado\Web\Webhooks\TDbWebhookQueue"
 *			ConnectionID="db" AutoCreateTable="true" />
 *		<module id="belisoful/prado-webhooks" QueueID="webhook-queue" />
 *		<module id="cron" class="Prado\Util\Cron\TCronModule">
 *			<job Name="webhooks" Schedule="* * * * *"
 *				Task="Belisoful\Prado\Web\Webhooks\TWebhookCronTask" />
 *			<job Name="webhooks-prune" Schedule="0 4 * * *"
 *				Task="Belisoful\Prado\Web\Webhooks\TWebhookPruneCronTask" />
 *		</module>
 * </modules>
 * ```
 *
 * ## Claiming
 *
 * A drain takes a lease rather than a lock: rows are stamped with a token and a time, and
 * only rows whose lease has run out can be stamped again. That is three statements -- find
 * the due ids, stamp them, read back what was actually stamped -- rather than one
 * `SELECT ... FOR UPDATE`, because the row-level locking syntaxes differ across SQLite,
 * MySQL and PostgreSQL while this works the same on all three. Two runners racing for the
 * same row both run the stamping `UPDATE`; its `WHERE` repeats every condition the `SELECT`
 * had -- the lease, and that the row is still due -- so exactly one wins, and a row that
 * another runner rescheduled between the two statements is left for when it is due.
 *
 * A lease guards the claim; {@see ownedBy} guards the write-back. A runner that finishes
 * after its lease has expired finds its update matches nothing, so it cannot clear the lease
 * of whoever took the delivery over, nor delete the row from under it.
 *
 * Make {@see TWebhookCronTask::setLeaseSeconds LeaseSeconds} longer than an attempt can
 * take all the same. A lease that expires while the first runner is still sending is a
 * second runner sending the same delivery alongside it -- allowed by at-least-once, and
 * still worth avoiding.
 *
 * Every time in the table -- when a delivery is due, when a lease runs out -- is written
 * from the runner's own clock, not the server's. Runners on several application servers
 * therefore need their clocks synchronized: one running a minute fast sees the others'
 * leases expire a minute early, and starts their deliveries alongside them.
 *
 * ## The table
 *
 * {@see setAutoCreateTable AutoCreateTable} creates it on first use, which suits
 * development. In production, create it once and leave the property off, so an application
 * that cannot see its table fails loudly instead of quietly making an empty one. The
 * statements are written to the common ground of SQLite, MySQL and PostgreSQL, which are
 * the three the test suite runs against; another server may well work, and has not been
 * shown to.
 *
 * Accepted deliveries are removed unless {@see setKeepDelivered KeepDelivered} is on.
 * Deliveries that run out of attempts are kept either way, for inspection and replay, until
 * {@see TWebhookPruneCronTask} removes them.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TDbWebhookQueue extends TModule implements IWebhookQueue
{
	/** @var string the table used when none is named. */
	public const DEFAULT_TABLE_NAME = 'webhook_queue';

	/** @var int how many rows one pass of a bounded {@see prune} removes at most. */
	public const PRUNE_CHUNK_SIZE = 500;

	/** @var null|\Prado\Data\TDbConnection the connection, once resolved */
	private ?TDbConnection $_connection = null;

	/** @var null|string the id of the TDataSourceConfig module to use */
	private ?string $_connectionId = null;

	/** @var string the table queued deliveries are kept in */
	private string $_tableName = self::DEFAULT_TABLE_NAME;

	/** @var bool whether a missing table is created on first use */
	private bool $_autoCreateTable = false;

	/** @var bool whether accepted deliveries are kept rather than removed */
	private bool $_keepDelivered = false;

	/** @var bool whether the table has been checked for this instance */
	private bool $_tableEnsured = false;

	/**
	 * Stores a delivery to be attempted later.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the delivery to store.
	 * @throws \Prado\Exceptions\TConfigurationException when there is no usable table.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the payload or the target
	 *   specification cannot be written as JSON. Stored as an empty string instead, the row
	 *   would come back as a delivery of nothing to nowhere and fail every attempt.
	 */
	public function enqueue(TWebhookQueueItem $item): void
	{
		$this->ensureTable();
		$spec = json_encode($item->getTargetSpec());
		if ($spec === false) {
			throw new TInvalidDataValueException('webhooks_queue_spec_invalid', json_last_error_msg());
		}
		$payload = json_encode($item->getPayload());
		if ($payload === false) {
			throw new TInvalidDataValueException('webhooks_queue_payload_invalid', json_last_error_msg());
		}
		$now = time();
		$item->setCreatedTime($now);
		$item->setUpdatedTime($now);

		$command = $this->getDbConnection()->createCommand(
			'INSERT INTO ' . $this->_tableName . ' (deliveryid, eventname, targetspec, payload, status,'
			. ' attempts, maxattempts, nextattempt, leaseduntil, leasetoken, laststatus, createdtime, updatedtime)'
			. ' VALUES (:deliveryid, :eventname, :targetspec, :payload, :status,'
			. ' :attempts, :maxattempts, :nextattempt, 0, NULL, NULL, :createdtime, :updatedtime)'
		);
		$command->bindValue(':deliveryid', $item->getDeliveryId());
		$command->bindValue(':eventname', $item->getEvent());
		$command->bindValue(':targetspec', $spec);
		$command->bindValue(':payload', $payload);
		$command->bindValue(':status', $item->getStatus()->value);
		$command->bindValue(':attempts', $item->getAttempts());
		$command->bindValue(':maxattempts', $item->getMaxAttempts());
		$command->bindValue(':nextattempt', $item->getNextAttempt());
		$command->bindValue(':createdtime', $now);
		$command->bindValue(':updatedtime', $now);
		$command->execute();

		$db = $this->getDbConnection();
		// PostgreSQL reports the last id by sequence rather than by connection.
		$sequence = $db->getDriverName() === TDbDriver::DRIVER_PGSQL ? $this->_tableName . '_tabuid_seq' : '';
		$item->setId((int) $db->getLastInsertID($sequence));
	}

	/**
	 * Takes a lease on up to $limit deliveries that are due.
	 * @param int $limit how many to take at most.
	 * @param int $leaseSeconds how long the lease lasts.
	 * @throws \Prado\Exceptions\TConfigurationException when there is no usable table.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem[] the claimed deliveries.
	 */
	public function claim(int $limit, int $leaseSeconds): array
	{
		$this->ensureTable();
		if ($limit < 1) {
			return [];
		}
		$now = time();
		$due = $this->findDue($limit, $now);
		if ($due === []) {
			return [];
		}

		$token = bin2hex(random_bytes(16));
		$this->stampLease($due, $token, $now, $now + max(1, $leaseSeconds));

		return $this->claimedBy($token);
	}

	/**
	 * The first statement of a claim: which deliveries are due and unleased.
	 * @param int $limit how many to find at most.
	 * @param int $now the runner's clock.
	 * @return int[] the ids, due first.
	 * @since 0.2.0
	 */
	protected function findDue(int $limit, int $now): array
	{
		// Each placeholder is named once. PDO only allows a name to repeat while prepare
		// emulation is on, which is a driver setting rather than something to rely on.
		$command = $this->getDbConnection()->createCommand(
			'SELECT tabuid FROM ' . $this->_tableName
			. ' WHERE status = :status AND nextattempt <= :duenow AND leaseduntil <= :leasenow'
			. ' ORDER BY nextattempt, tabuid LIMIT ' . $limit
		);
		$command->bindValue(':status', TWebhookQueueStatus::Pending->value);
		$command->bindValue(':duenow', $now);
		$command->bindValue(':leasenow', $now);

		return array_map('intval', $command->queryColumn());
	}

	/**
	 * The second statement of a claim: stamps the lease on the deliveries found, where they
	 * still qualify.
	 *
	 * The `WHERE` repeats every condition {@see findDue} had rather than trusting it. The
	 * lease, so that of two runners stamping the same row exactly one writes it and the
	 * other simply gets fewer rows back. And that the row is still due: between the two
	 * statements another runner may have attempted the delivery and rescheduled it with a
	 * backoff, and stamping it anyway would send it again before that backoff had run.
	 *
	 * @param int[] $due the ids to stamp.
	 * @param string $token the lease token.
	 * @param int $now the runner's clock.
	 * @param int $until when the lease runs out.
	 * @since 0.2.0
	 */
	protected function stampLease(array $due, string $token, int $now, int $until): void
	{
		$command = $this->getDbConnection()->createCommand(
			'UPDATE ' . $this->_tableName . ' SET leasetoken = :token, leaseduntil = :until, updatedtime = :now'
			. ' WHERE tabuid IN (' . implode(', ', array_map('intval', $due)) . ')'
			. ' AND status = :status AND nextattempt <= :duenow AND leaseduntil <= :leasenow'
		);
		$command->bindValue(':token', $token);
		$command->bindValue(':until', $until);
		$command->bindValue(':now', $now);
		$command->bindValue(':status', TWebhookQueueStatus::Pending->value);
		$command->bindValue(':duenow', $now);
		$command->bindValue(':leasenow', $now);
		$command->execute();
	}

	/**
	 * The last statement of a claim: reads back what the stamp actually took.
	 * @param string $token the lease token.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem[] the claimed deliveries, due first.
	 * @since 0.2.0
	 */
	protected function claimedBy(string $token): array
	{
		$command = $this->getDbConnection()->createCommand(
			'SELECT * FROM ' . $this->_tableName . ' WHERE leasetoken = :token ORDER BY nextattempt, tabuid'
		);
		$command->bindValue(':token', $token);

		return array_map([$this, 'itemFromRow'], $command->queryAll());
	}

	/**
	 * Records that the target accepted the delivery.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 */
	public function succeed(TWebhookQueueItem $item): void
	{
		$item->setStatus(TWebhookQueueStatus::Delivered);
		if (!$this->_keepDelivered) {
			$this->remove($item);

			return;
		}
		$this->finish($item, TWebhookQueueStatus::Delivered);
	}

	/**
	 * Returns a delivery to the queue and releases its lease.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 * @param int $delaySeconds how long before it is due again.
	 */
	public function reschedule(TWebhookQueueItem $item, int $delaySeconds): void
	{
		$this->ensureTable();
		$now = time();
		$item->setStatus(TWebhookQueueStatus::Pending);
		$item->setNextAttempt($now + max(0, $delaySeconds));
		$item->setUpdatedTime($now);

		$command = $this->getDbConnection()->createCommand(
			'UPDATE ' . $this->_tableName . ' SET status = :status, attempts = :attempts,'
			. ' nextattempt = :nextattempt, laststatus = :laststatus, updatedtime = :now,'
			. ' leasetoken = NULL, leaseduntil = 0 WHERE ' . $this->ownedBy($item)
		);
		$command->bindValue(':status', TWebhookQueueStatus::Pending->value);
		$command->bindValue(':attempts', $item->getAttempts());
		$command->bindValue(':nextattempt', $item->getNextAttempt());
		$command->bindValue(':laststatus', $item->getLastStatus());
		$command->bindValue(':now', $now);
		$this->bindOwnership($command, $item);
		$command->execute();
		$item->setLeaseToken(null);
	}

	/**
	 * Records that a delivery has run out of attempts, and keeps the row.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 */
	public function abandon(TWebhookQueueItem $item): void
	{
		$this->finish($item, TWebhookQueueStatus::Failed);
	}

	/**
	 * Writes a delivery's final state and releases its lease.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueStatus $status what it ended as.
	 */
	protected function finish(TWebhookQueueItem $item, TWebhookQueueStatus $status): void
	{
		$this->ensureTable();
		$now = time();
		$item->setStatus($status);
		$item->setUpdatedTime($now);

		$command = $this->getDbConnection()->createCommand(
			'UPDATE ' . $this->_tableName . ' SET status = :status, attempts = :attempts,'
			. ' laststatus = :laststatus, updatedtime = :now, leasetoken = NULL, leaseduntil = 0'
			. ' WHERE ' . $this->ownedBy($item)
		);
		$command->bindValue(':status', $status->value);
		$command->bindValue(':attempts', $item->getAttempts());
		$command->bindValue(':laststatus', $item->getLastStatus());
		$command->bindValue(':now', $now);
		$this->bindOwnership($command, $item);
		$command->execute();
		$item->setLeaseToken(null);
	}

	/**
	 * Removes one delivery.
	 *
	 * A claimed delivery is removed while the caller still holds its lease, as every
	 * write-back is. One that was never claimed has no lease to name, and is removed only
	 * while nobody else holds one either: an application tidying up by id must not be able
	 * to delete a row from under the runner that is sending it.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the delivery to remove.
	 */
	public function remove(TWebhookQueueItem $item): void
	{
		$this->ensureTable();
		$where = $item->getLeaseToken() === null
			? 'tabuid = :tabuid AND (leasetoken IS NULL OR leaseduntil <= :unleased)'
			: $this->ownedBy($item);
		$command = $this->getDbConnection()->createCommand(
			'DELETE FROM ' . $this->_tableName . ' WHERE ' . $where
		);
		$this->bindOwnership($command, $item);
		if ($item->getLeaseToken() === null) {
			$command->bindValue(':unleased', time());
		}
		$command->execute();
		$item->setLeaseToken(null);
	}

	/**
	 * Removes finished deliveries older than a given age.
	 *
	 * Unbounded, this is one `DELETE`, which on a table that has not been pruned in a long
	 * while is one long lock. Given a limit it works oldest first in chunks of
	 * {@see PRUNE_CHUNK_SIZE}: the ids of a chunk, then a `DELETE` naming them, until the
	 * limit is reached or a chunk comes back short -- written that way because neither
	 * `DELETE ... LIMIT` nor `DELETE ... ORDER BY` is something all three servers accept.
	 *
	 * @param int $age how old, in seconds, a finished delivery must be.
	 * @param int $limit how many to remove at most, or 0 for every one that qualifies.
	 * @return int how many were removed.
	 */
	public function prune(int $age, int $limit = 0): int
	{
		$this->ensureTable();
		$before = time() - max(0, $age);
		if ($limit < 1) {
			$command = $this->getDbConnection()->createCommand(
				'DELETE FROM ' . $this->_tableName . ' WHERE status <> :pending AND updatedtime < :before'
			);
			$command->bindValue(':pending', TWebhookQueueStatus::Pending->value);
			$command->bindValue(':before', $before);

			return $command->execute();
		}

		$removed = 0;
		while ($removed < $limit) {
			$chunk = min(self::PRUNE_CHUNK_SIZE, $limit - $removed);
			$command = $this->getDbConnection()->createCommand(
				'SELECT tabuid FROM ' . $this->_tableName . ' WHERE status <> :pending AND updatedtime < :before'
				. ' ORDER BY updatedtime, tabuid LIMIT ' . $chunk
			);
			$command->bindValue(':pending', TWebhookQueueStatus::Pending->value);
			$command->bindValue(':before', $before);
			$ids = array_map('intval', $command->queryColumn());
			if ($ids === []) {
				break;
			}
			$removed += $this->getDbConnection()->createCommand(
				'DELETE FROM ' . $this->_tableName . ' WHERE tabuid IN (' . implode(', ', $ids) . ')'
			)->execute();
			if (count($ids) < $chunk) {
				break;
			}
		}

		return $removed;
	}

	/**
	 * @param null|\Belisoful\Prado\Web\Webhooks\TWebhookQueueStatus $status the status to
	 *   count, or null for every delivery held.
	 * @return int how many deliveries the queue holds.
	 */
	public function getCount(?TWebhookQueueStatus $status = null): int
	{
		$this->ensureTable();
		$sql = 'SELECT COUNT(*) FROM ' . $this->_tableName;
		$command = $this->getDbConnection()->createCommand(
			$status === null ? $sql : $sql . ' WHERE status = :status'
		);
		if ($status !== null) {
			$command->bindValue(':status', $status->value);
		}

		return (int) $command->queryScalar();
	}

	/**
	 * The `WHERE` that writes a claimed delivery back, and only while this runner still holds
	 * it.
	 *
	 * A lease keeps two runners from *starting* the same delivery; it does nothing about a
	 * runner that finishes after its lease has expired and somebody else has taken over. Such
	 * a runner used to write over the new holder's lease -- letting a third runner in
	 * alongside -- or delete the row from under it. Naming the lease in the `WHERE` makes the
	 * write a no-op instead.
	 *
	 * A delivery that was never claimed has no lease to name, so it is addressed by id alone.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the delivery to write.
	 * @return string the condition.
	 */
	protected function ownedBy(TWebhookQueueItem $item): string
	{
		return $item->getLeaseToken() === null
			? 'tabuid = :tabuid'
			: 'tabuid = :tabuid AND leasetoken = :leasetoken';
	}

	/**
	 * Binds what {@see ownedBy} named.
	 * @param \Prado\Data\TDbCommand $command the command to bind on.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the delivery to write.
	 */
	protected function bindOwnership($command, TWebhookQueueItem $item): void
	{
		$command->bindValue(':tabuid', $item->getId());
		if ($item->getLeaseToken() !== null) {
			$command->bindValue(':leasetoken', $item->getLeaseToken());
		}
	}

	/**
	 * @param array<string, mixed> $row one row of the table.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem the delivery it holds.
	 */
	protected function itemFromRow(array $row): TWebhookQueueItem
	{
		$spec = json_decode((string) $row['targetspec'], true);
		$item = new TWebhookQueueItem(
			is_array($spec) || is_string($spec) ? $spec : [],
			json_decode((string) $row['payload'], true),
			$row['eventname'] === null ? null : (string) $row['eventname'],
			(string) $row['deliveryid']
		);
		$item->setId((int) $row['tabuid']);
		$item->setLeaseToken($row['leasetoken'] === null ? null : (string) $row['leasetoken']);
		$item->setStatus((string) $row['status']);
		$item->setAttempts($row['attempts']);
		$item->setMaxAttempts($row['maxattempts']);
		$item->setNextAttempt($row['nextattempt']);
		$item->setLastStatus($row['laststatus']);
		$item->setCreatedTime($row['createdtime']);
		$item->setUpdatedTime($row['updatedtime']);

		return $item;
	}

	/**
	 * Checks the table is there, creating it when told to.
	 * @throws \Prado\Exceptions\TConfigurationException when it is missing and this is not
	 *   allowed to create it.
	 */
	protected function ensureTable(): void
	{
		if ($this->_tableEnsured) {
			return;
		}
		$db = $this->getDbConnection();
		try {
			$db->createCommand('SELECT * FROM ' . $this->_tableName . ' WHERE 0=1')->query()->close();
		} catch (Exception $e) {
			if (!$this->_autoCreateTable) {
				throw new TConfigurationException('webhooks_queue_table_missing', $this->_tableName, static::class);
			}
			$this->createTable();
		}
		$this->_tableEnsured = true;
	}

	/**
	 * Creates the queue table. Identifiers are unquoted and chosen to be reserved on none of
	 * SQLite, MySQL or PostgreSQL, so one statement serves all three but for the spelling of
	 * the key -- and, on MySQL, the character set: a payload is JSON and may hold any
	 * character, which a server defaulting to latin1 would refuse.
	 */
	protected function createTable(): void
	{
		$db = $this->getDbConnection();
		$driver = $db->getDriverName();
		$key = 'INTEGER PRIMARY KEY';
		$options = '';
		if ($driver === TDbDriver::DRIVER_MYSQL) {
			$key = 'INTEGER PRIMARY KEY AUTO_INCREMENT';
			$options = ' DEFAULT CHARSET=utf8mb4';
		} elseif ($driver === TDbDriver::DRIVER_SQLITE) {
			$key = 'INTEGER PRIMARY KEY AUTOINCREMENT';
		} elseif ($driver === TDbDriver::DRIVER_PGSQL) {
			$key = 'SERIAL PRIMARY KEY';
		}

		$db->createCommand(
			'CREATE TABLE IF NOT EXISTS ' . $this->_tableName . ' (
			tabuid ' . $key . ',
			deliveryid VARCHAR(64) NOT NULL,
			eventname VARCHAR(190) NULL,
			targetspec TEXT NOT NULL,
			payload TEXT NULL,
			status VARCHAR(16) NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			maxattempts INTEGER NOT NULL DEFAULT 0,
			nextattempt INTEGER NOT NULL DEFAULT 0,
			leaseduntil INTEGER NOT NULL DEFAULT 0,
			leasetoken VARCHAR(64) NULL,
			laststatus VARCHAR(190) NULL,
			createdtime INTEGER NOT NULL,
			updatedtime INTEGER NOT NULL
			)' . $options
		)->execute();

		// The claim reads by the first three together, and the prune by status and age.
		// No `IF NOT EXISTS`: MySQL has no such clause on CREATE INDEX, and this only runs
		// when the table was missing, so the indices cannot be there either. The names carry
		// the table's, because PostgreSQL keeps index names per schema rather than per table.
		foreach ([
			'_due' => '(status, nextattempt, leaseduntil)',
			'_lease' => '(leasetoken)',
			'_delivery' => '(deliveryid)',
		] as $suffix => $columns) {
			$db->createCommand(
				'CREATE INDEX ' . $this->_tableName . $suffix . ' ON ' . $this->_tableName . ' ' . $columns
			)->execute();
		}
	}

	/**
	 * @throws \Prado\Exceptions\TConfigurationException when no connection is configured, or
	 *   the id names something that is not a data source.
	 * @return \Prado\Data\TDbConnection the connection the table is on.
	 */
	public function getDbConnection(): TDbConnection
	{
		if ($this->_connection === null) {
			if ($this->_connectionId === null) {
				throw new TConfigurationException('webhooks_queue_connection_required', static::class);
			}
			$source = $this->getApplication()?->getModule($this->_connectionId);
			if (!($source instanceof TDataSourceConfig)) {
				throw new TConfigurationException('webhooks_queue_connection_invalid', $this->_connectionId, static::class);
			}
			$this->_connection = $source->getDbConnection();
		}
		$this->_connection->setActive(true);

		return $this->_connection;
	}

	/**
	 * Sets the connection directly, instead of naming a data source module.
	 * @param null|\Prado\Data\TDbConnection $value the connection.
	 */
	public function setDbConnection(?TDbConnection $value): void
	{
		$this->_connection = $value;
		$this->_tableEnsured = false;
	}

	/**
	 * @return null|string the id of the {@see \Prado\Data\TDataSourceConfig} module in use.
	 */
	public function getConnectionID(): ?string
	{
		return $this->_connectionId;
	}

	/**
	 * @param mixed $value the id of a {@see \Prado\Data\TDataSourceConfig} module.
	 */
	public function setConnectionID($value): void
	{
		$id = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_connectionId = $id === '' ? null : $id;
		$this->_connection = null;
		$this->_tableEnsured = false;
	}

	/**
	 * @return string the table queued deliveries are kept in. Defaults to
	 *   {@see DEFAULT_TABLE_NAME}.
	 */
	public function getTableName(): string
	{
		return $this->_tableName;
	}

	/**
	 * @param mixed $value the table name.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is empty, or is not a
	 *   plain identifier -- it is interpolated into every statement, so it is checked here
	 *   rather than quoted in a dozen places.
	 */
	public function setTableName($value): void
	{
		$table = trim(TPropertyValue::ensureString($value));
		if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $table)) {
			throw new TConfigurationException('webhooks_queue_table_invalid', $table, static::class);
		}
		$this->_tableName = $table;
		$this->_tableEnsured = false;
	}

	/**
	 * @return bool whether a missing table is created on first use. Defaults to false.
	 */
	public function getAutoCreateTable(): bool
	{
		return $this->_autoCreateTable;
	}

	/**
	 * @param mixed $value whether to create the table when it is missing. Convenient in
	 *   development; in production a missing table is usually a wrong connection, and
	 *   failing is better than quietly queueing into a new empty one.
	 */
	public function setAutoCreateTable($value): void
	{
		$this->_autoCreateTable = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return bool whether accepted deliveries are kept. Defaults to false.
	 */
	public function getKeepDelivered(): bool
	{
		return $this->_keepDelivered;
	}

	/**
	 * @param mixed $value true to keep accepted deliveries as a record. They are pruned on
	 *   the same schedule as failed ones; left on, and never pruned, the table grows with
	 *   every webhook the application has ever sent.
	 */
	public function setKeepDelivered($value): void
	{
		$this->_keepDelivered = TPropertyValue::ensureBoolean($value);
	}
}
