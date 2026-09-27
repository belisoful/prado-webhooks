<?php

/**
 * TWebhookQueueDriverTestCase class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

use Belisoful\Prado\Web\Webhooks\TDbWebhookQueue;
use Belisoful\Prado\Web\Webhooks\TWebhookQueueItem;
use Belisoful\Prado\Web\Webhooks\TWebhookQueueStatus;
use Prado\Data\TDbConnection;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;

/**
 * The queue's behaviour, against whichever database a subclass supplies.
 *
 * The queue is the one part of this package whose correctness depends on the server it runs
 * on: the DDL, the claim, and the way a repeated placeholder is prepared all differ between
 * drivers, and a suite that only ever sees SQLite proves none of it. So the tests live here
 * once and each driver is a subclass -- one that skips when its server is not configured, so
 * a developer without it still gets the rest.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
abstract class TWebhookQueueDriverTestCase extends PHPUnit\Framework\TestCase
{

	private TDbConnection $_db;
	private TDbWebhookQueue $_queue;

	/**
	 * @return \Prado\Data\TDbConnection a connection to run this suite against. A subclass
	 *   whose server is not configured skips here instead.
	 */
	abstract protected function newConnection(): TDbConnection;

	protected function setUp(): void
	{
		$this->_db = $this->newConnection();
		$this->_db->setActive(true);
		// A server-backed driver keeps the table between tests, so each starts from nothing.
		$this->_db->createCommand('DROP TABLE IF EXISTS ' . TDbWebhookQueue::DEFAULT_TABLE_NAME)->execute();
		$this->_queue = $this->newQueue();
	}

	public function testTheSuiteRanAgainstTheDriverItSaysItDid()
	{
		// Without this a misconfigured job could pass while testing nothing new.
		$this->assertSame($this->driverName(), $this->_db->getDriverName());
	}

	/**
	 * @return string the driver this subclass exists to exercise.
	 */
	abstract protected function driverName(): string;

	private function newQueue(): TDbWebhookQueue
	{
		$queue = new TDbWebhookQueue();
		$queue->setDbConnection($this->_db);
		$queue->setAutoCreateTable(true);

		return $queue;
	}

	private function item(string $url = 'https://example.com/hook', mixed $payload = ['id' => 1], ?string $event = null): TWebhookQueueItem
	{
		return new TWebhookQueueItem($url, $payload, $event);
	}

	private function age(TWebhookQueueItem $item, int $seconds): void
	{
		$command = $this->_db->createCommand(
			'UPDATE ' . $this->_queue->getTableName() . ' SET updatedtime = :t WHERE tabuid = :id'
		);
		$command->bindValue(':t', time() - $seconds);
		$command->bindValue(':id', $item->getId());
		$command->execute();
	}

	// ── Storing ────────────────────────────────────────────────────────────────

	public function testEnqueuingStoresTheDeliveryAndGivesItAnId()
	{
		$item = $this->item();
		$this->_queue->enqueue($item);

		$this->assertIsInt($item->getId());
		$this->assertSame(1, $this->_queue->getCount());
		$this->assertSame(1, $this->_queue->getCount(TWebhookQueueStatus::Pending));
	}

	public function testTheTableIsCreatedOnFirstUse()
	{
		$this->assertSame(0, $this->_queue->getCount());
	}

	public function testEverythingStoredComesBack()
	{
		$item = new TWebhookQueueItem(
			['url' => 'https://example.com/hook', 'secret' => 's3cret', 'events' => ['invoice.paid']],
			['invoice' => ['id' => 7, 'total' => '9.99']],
			'invoice.paid'
		);
		$item->setMaxAttempts(4);
		$this->_queue->enqueue($item);

		$claimed = $this->_queue->claim(10, 60)[0];

		$this->assertSame($item->getDeliveryId(), $claimed->getDeliveryId());
		$this->assertSame('invoice.paid', $claimed->getEvent());
		$this->assertSame(['invoice' => ['id' => 7, 'total' => '9.99']], $claimed->getPayload());
		$this->assertSame(
			['url' => 'https://example.com/hook', 'secret' => 's3cret', 'events' => ['invoice.paid']],
			$claimed->getTargetSpec()
		);
		$this->assertSame(4, $claimed->getMaxAttempts());
		$this->assertSame(TWebhookQueueStatus::Pending, $claimed->getStatus());
	}

	public function testAUrlSpecificationComesBackAsAString()
	{
		$this->_queue->enqueue($this->item('https://example.com/hook'));

		$this->assertSame('https://example.com/hook', $this->_queue->claim(1, 60)[0]->getTargetSpec());
	}

	public function testAStringPayloadSurvivesTheRoundTrip()
	{
		$this->_queue->enqueue($this->item('https://example.com/hook', '<xml/>'));

		$this->assertSame('<xml/>', $this->_queue->claim(1, 60)[0]->getPayload());
	}

	// ── Claiming ───────────────────────────────────────────────────────────────

	public function testClaimingTakesTheDueOnesOldestFirstAndNoMoreThanAsked()
	{
		// One clock reading for the whole loop. Read per iteration, a second turning over
		// between two inserts shifts their due times relative to each other and the expected
		// order collapses into a tie -- rare, and rare is worse than never.
		$base = time();
		$ids = [];
		foreach ([3, 1, 2] as $order) {
			$item = $this->item('https://example.com/hook' . $order);
			$item->setNextAttempt($base - (10 - $order));
			$this->_queue->enqueue($item);
			$ids[$order] = $item->getDeliveryId();
		}

		$claimed = $this->_queue->claim(2, 60);

		$this->assertCount(2, $claimed);
		$this->assertSame($ids[1], $claimed[0]->getDeliveryId());
		$this->assertSame($ids[2], $claimed[1]->getDeliveryId());
	}

	public function testADeliveryThatIsNotDueYetIsNotClaimed()
	{
		$item = $this->item();
		$item->setNextAttempt(time() + 3600);
		$this->_queue->enqueue($item);

		$this->assertSame([], $this->_queue->claim(10, 60));
		$this->assertSame(1, $this->_queue->getCount(TWebhookQueueStatus::Pending));
	}

	public function testAClaimedDeliveryIsNotClaimedAgainWhileItsLeaseHolds()
	{
		$this->_queue->enqueue($this->item());

		$this->assertCount(1, $this->_queue->claim(10, 600));
		$this->assertSame([], $this->_queue->claim(10, 600));
	}

	public function testTwoRunnersNeverGetTheSameDelivery()
	{
		// The whole point of the lease: a second runner arriving mid-batch takes what is
		// left, not what the first one took.
		for ($i = 0; $i < 6; $i++) {
			$this->_queue->enqueue($this->item('https://example.com/hook' . $i));
		}

		$first = $this->newQueue()->claim(4, 600);
		$second = $this->newQueue()->claim(4, 600);

		$this->assertCount(4, $first);
		$this->assertCount(2, $second);
		$overlap = array_intersect(
			array_map(static fn ($i) => $i->getId(), $first),
			array_map(static fn ($i) => $i->getId(), $second)
		);
		$this->assertSame([], $overlap);
	}

	public function testADeliveryWhoseLeaseRanOutIsPickedUpAgain()
	{
		// What makes the guarantee survive a runner being killed mid-attempt.
		$item = $this->item();
		$this->_queue->enqueue($item);
		$this->_queue->claim(10, 600);

		$command = $this->_db->createCommand(
			'UPDATE ' . $this->_queue->getTableName() . ' SET leaseduntil = :t WHERE tabuid = :id'
		);
		$command->bindValue(':t', time() - 1);
		$command->bindValue(':id', $item->getId());
		$command->execute();

		$this->assertCount(1, $this->newQueue()->claim(10, 600));
	}

	public function testAskingForNothingClaimsNothing()
	{
		$this->_queue->enqueue($this->item());

		$this->assertSame([], $this->_queue->claim(0, 60));
		$this->assertSame([], $this->_queue->claim(-1, 60));
	}

	public function testAnEmptyQueueClaimsNothing()
	{
		$this->assertSame([], $this->_queue->claim(10, 60));
	}

	// ── Finishing ──────────────────────────────────────────────────────────────

	public function testAnAcceptedDeliveryIsRemoved()
	{
		$item = $this->item();
		$this->_queue->enqueue($item);
		$claimed = $this->_queue->claim(1, 60)[0];

		$this->_queue->succeed($claimed);

		$this->assertSame(0, $this->_queue->getCount());
		$this->assertSame(TWebhookQueueStatus::Delivered, $claimed->getStatus());
	}

	public function testAnAcceptedDeliveryIsKeptWhenTheQueueIsToldTo()
	{
		$this->_queue->setKeepDelivered(true);
		$this->_queue->enqueue($this->item());
		$this->_queue->succeed($this->_queue->claim(1, 60)[0]);

		$this->assertSame(1, $this->_queue->getCount(TWebhookQueueStatus::Delivered));
		$this->assertSame([], $this->_queue->claim(10, 60), 'a delivered row is never claimed again');
	}

	public function testReschedulingPutsItBackWithItsAttemptCountAndABackoff()
	{
		$this->_queue->enqueue($this->item());
		$claimed = $this->_queue->claim(1, 600)[0];
		$claimed->setAttempts(2);
		$claimed->setLastStatus('HTTP 503');

		$this->_queue->reschedule($claimed, 120);

		$this->assertSame([], $this->_queue->claim(10, 60), 'not due yet');

		$again = $this->newQueue();
		$this->assertSame(1, $again->getCount(TWebhookQueueStatus::Pending));
		$this->_db->createCommand(
			'UPDATE ' . $this->_queue->getTableName() . ' SET nextattempt = 0'
		)->execute();

		$reclaimed = $again->claim(1, 60)[0];
		$this->assertSame(2, $reclaimed->getAttempts());
		$this->assertSame('HTTP 503', $reclaimed->getLastStatus());
	}

	public function testAnAbandonedDeliveryIsKeptAsFailedAndNeverClaimedAgain()
	{
		$this->_queue->enqueue($this->item());
		$claimed = $this->_queue->claim(1, 60)[0];
		$claimed->setAttempts(10);
		$claimed->setLastStatus('Connection refused');

		$this->_queue->abandon($claimed);

		$this->assertSame(1, $this->_queue->getCount(TWebhookQueueStatus::Failed));
		$this->assertSame([], $this->newQueue()->claim(10, 60));
	}

	public function testADeliveryCanBeRemovedOutright()
	{
		$item = $this->item();
		$this->_queue->enqueue($item);

		$this->_queue->remove($item);

		$this->assertSame(0, $this->_queue->getCount());
	}

	// ── Leases that expire mid-attempt ─────────────────────────────────────────

	/**
	 * Hands the row to a second runner by expiring the first one's lease, and returns both
	 * runners' views of it.
	 * @return array{0: TDbWebhookQueue, 1: TWebhookQueueItem, 2: TDbWebhookQueue, 3: TWebhookQueueItem}
	 */
	private function overtaken(): array
	{
		$this->_queue->enqueue($this->item());

		$first = $this->newQueue();
		$stale = $first->claim(1, 600)[0];
		$this->_db->createCommand(
			'UPDATE ' . $this->_queue->getTableName() . ' SET leaseduntil = ' . (time() - 1)
		)->execute();

		$second = $this->newQueue();
		$held = $second->claim(1, 600)[0];

		$this->assertSame($stale->getId(), $held->getId());
		$this->assertNotNull($held->getLeaseToken());
		$this->assertNotSame($stale->getLeaseToken(), $held->getLeaseToken());

		return [$first, $stale, $second, $held];
	}

	private function leaseTokenInTheTable(): ?string
	{
		$token = $this->_db->createCommand(
			'SELECT leasetoken FROM ' . $this->_queue->getTableName()
		)->queryScalar();

		return $token === false || $token === null ? null : (string) $token;
	}

	public function testAStaleRunnerCannotRescheduleOverTheRunnerThatTookOver()
	{
		// A lease keeps two runners from starting the same delivery. It says nothing about a
		// runner that finishes late, and one used to clear the new holder's lease -- letting a
		// third runner in alongside it.
		[$first, $stale, , $held] = $this->overtaken();

		$stale->setAttempts(1);
		$stale->setLastStatus('HTTP 500');
		$first->reschedule($stale, 60);

		$this->assertSame($held->getLeaseToken(), $this->leaseTokenInTheTable());
		$this->_db->createCommand('UPDATE ' . $this->_queue->getTableName() . ' SET nextattempt = 0')->execute();
		$this->assertSame([], $this->newQueue()->claim(10, 600), 'nobody else can claim it either');
	}

	public function testAStaleRunnerCannotDeleteTheRowAnotherIsSending()
	{
		[$first, $stale, , $held] = $this->overtaken();

		$first->succeed($stale);

		$this->assertSame(1, $this->_queue->getCount(), 'the row is still there');
		$this->assertSame($held->getLeaseToken(), $this->leaseTokenInTheTable());
	}

	public function testAStaleRunnerCannotAbandonWhatAnotherIsSending()
	{
		[$first, $stale, , $held] = $this->overtaken();

		$stale->setAttempts(99);
		$first->abandon($stale);

		$this->assertSame(0, $this->_queue->getCount(TWebhookQueueStatus::Failed));
		$this->assertSame($held->getLeaseToken(), $this->leaseTokenInTheTable());
	}

	public function testTheRunnerThatHoldsTheLeaseStillWritesBack()
	{
		// The fence must not stop the legitimate case.
		[, , $second, $held] = $this->overtaken();

		$held->setAttempts(1);
		$held->setLastStatus('HTTP 503');
		$second->reschedule($held, 0);

		$this->assertNull($this->leaseTokenInTheTable(), 'the lease is released');
		$this->assertNull($held->getLeaseToken());

		$reclaimed = $this->newQueue()->claim(1, 600)[0];
		$this->assertSame(1, $reclaimed->getAttempts());
		$this->assertSame('HTTP 503', $reclaimed->getLastStatus());
	}

	public function testANeverClaimedDeliveryIsStillAddressableById()
	{
		// remove() has no lease to name when nothing ever claimed the row.
		$item = $this->item();
		$this->_queue->enqueue($item);

		$this->assertNull($item->getLeaseToken());
		$this->_queue->remove($item);
		$this->assertSame(0, $this->_queue->getCount());
	}

	public function testAnOverLongStatusIsTrimmedToWhatTheColumnHolds()
	{
		// A server in strict mode rejects an over-long value rather than truncating it, so the
		// write recording a failure would fail in turn. Exception messages are long.
		$this->_queue->enqueue($this->item());
		$claimed = $this->_queue->claim(1, 600)[0];
		$claimed->setAttempts(1);
		$claimed->setLastStatus(str_repeat('very long failure detail ', 40));

		$this->_queue->reschedule($claimed, 0);

		$stored = (string) $this->_db->createCommand(
			'SELECT laststatus FROM ' . $this->_queue->getTableName()
		)->queryScalar();
		$this->assertLessThanOrEqual(TWebhookQueueItem::MAX_LAST_STATUS_LENGTH, mb_strlen($stored));
		// ASCII dots, not an ellipsis character: a latin1 table cannot hold the latter.
		$this->assertStringEndsWith('...', $stored);
	}

	public function testFourByteCharactersSurviveTheTable()
	{
		// A payload is JSON and may hold any character. On MySQL this is what the table's
		// utf8mb4 charset is for: a server defaulting to latin1, or to the three-byte utf8,
		// refuses or mangles an emoji.
		$item = $this->item('https://example.com/hook', ['note' => 'paid 😀 ünïcödé']);
		$this->_queue->enqueue($item);
		$claimed = $this->_queue->claim(1, 600)[0];
		$claimed->setAttempts(1);
		$claimed->setLastStatus('failed 😀');
		$this->_queue->reschedule($claimed, 0);

		$again = $this->newQueue()->claim(1, 600)[0];
		$this->assertSame(['note' => 'paid 😀 ünïcödé'], $again->getPayload());
		$this->assertSame('failed 😀', $again->getLastStatus());
	}

	// ── Storing what cannot be written down ────────────────────────────────────

	public function testAPayloadThatCannotBeEncodedIsRefusedRatherThanStoredAsNothing()
	{
		// json_encode of a resource is false, and (string) false is '': the row came back as
		// a delivery of nothing and failed every attempt with no trace of why.
		$item = $this->item('https://example.com/hook', ['bad' => fopen('php://memory', 'r')]);

		try {
			$this->_queue->enqueue($item);
			$this->fail('an unencodable payload should be refused');
		} catch (TInvalidDataValueException $e) {
			$this->assertNull($item->getId(), 'never stored');
		}
		$this->assertSame(0, $this->_queue->getCount());
	}

	public function testAPayloadThatIsNotValidUtf8IsRefused()
	{
		$this->expectException(TInvalidDataValueException::class);
		$this->_queue->enqueue($this->item('https://example.com/hook', "\xB1\x31"));
	}

	public function testATargetSpecificationThatCannotBeEncodedIsRefused()
	{
		$item = new TWebhookQueueItem(['url' => 'https://example.com/hook', 'data' => "\xB1\x31"], ['id' => 1]);

		try {
			$this->_queue->enqueue($item);
			$this->fail('an unencodable specification should be refused');
		} catch (TInvalidDataValueException $e) {
			$this->assertStringContainsString('target', $e->getMessage());
		}
		$this->assertSame(0, $this->_queue->getCount());
	}

	// ── The claim's two statements ─────────────────────────────────────────────

	public function testARowRescheduledBetweenTheSelectAndTheUpdateIsNotClaimedBeforeItIsDue()
	{
		// claim() is three statements. The stamping UPDATE used to check the lease but not
		// the due time, so a row another runner attempted and rescheduled in between -- its
		// lease released, its next attempt an hour out -- was stamped and sent straight away.
		$this->_queue->enqueue($this->item());
		$other = $this->newQueue();

		$racer = new class () extends TDbWebhookQueue {
			public ?Closure $betweenStatements = null;

			protected function stampLease(array $due, string $token, int $now, int $until): void
			{
				if ($this->betweenStatements !== null) {
					$between = $this->betweenStatements;
					$this->betweenStatements = null;
					$between();
				}
				parent::stampLease($due, $token, $now, $until);
			}
		};
		$racer->setDbConnection($this->_db);
		$racer->betweenStatements = function () use ($other) {
			$claimed = $other->claim(1, 600)[0];
			$claimed->setAttempts(1);
			$claimed->setLastStatus('HTTP 503');
			$other->reschedule($claimed, 3600);
		};

		$this->assertSame([], $racer->claim(1, 600), 'the row is not due for an hour');
		$this->assertNull($this->leaseTokenInTheTable(), 'and carries no lease');
		$this->assertSame(1, $this->_queue->getCount(TWebhookQueueStatus::Pending));
	}

	public function testARowThatIsStillDueAfterTheSelectIsClaimedAsBefore()
	{
		// The extra condition must not refuse the ordinary case.
		$this->_queue->enqueue($this->item());

		$this->assertCount(1, $this->newQueue()->claim(1, 600));
	}

	// ── Removing by id ─────────────────────────────────────────────────────────

	public function testRemovingByIdCannotDeleteARowAnotherRunnerIsSending()
	{
		// An application tidying up with the item it enqueued has no lease to name, and the
		// delete by id alone went straight through the runner mid-attempt.
		$item = $this->item();
		$this->_queue->enqueue($item);
		$held = $this->newQueue()->claim(1, 600)[0];

		$this->_queue->remove($item);

		$this->assertSame(1, $this->_queue->getCount(), 'the row is still there');
		$this->assertSame($held->getLeaseToken(), $this->leaseTokenInTheTable());
	}

	public function testRemovingByIdWorksOnceTheLeaseHasRunOut()
	{
		$item = $this->item();
		$this->_queue->enqueue($item);
		$this->newQueue()->claim(1, 600);
		$this->_db->createCommand(
			'UPDATE ' . $this->_queue->getTableName() . ' SET leaseduntil = ' . (time() - 1)
		)->execute();

		$this->_queue->remove($item);

		$this->assertSame(0, $this->_queue->getCount());
	}

	public function testTheLeaseHolderCanStillRemoveWhatItHolds()
	{
		$this->_queue->enqueue($this->item());
		$held = $this->_queue->claim(1, 600)[0];

		$this->_queue->remove($held);

		$this->assertSame(0, $this->_queue->getCount());
		$this->assertNull($held->getLeaseToken());
	}

	// ── Pruning ────────────────────────────────────────────────────────────────

	public function testPruningRemovesOldFinishedDeliveriesAndLeavesPendingOnesAlone()
	{
		$pending = $this->item('https://example.com/pending');
		$this->_queue->enqueue($pending);
		$this->age($pending, 86400 * 365);

		$failed = $this->item('https://example.com/failed');
		$this->_queue->enqueue($failed);
		$this->_queue->abandon($failed);
		$this->age($failed, 86400 * 365);

		$removed = $this->_queue->prune(3600);

		$this->assertSame(1, $removed);
		$this->assertSame(0, $this->_queue->getCount(TWebhookQueueStatus::Failed));
		$this->assertSame(1, $this->_queue->getCount(TWebhookQueueStatus::Pending), 'age is not a reason to drop work');
	}

	public function testPruningCanBeBoundedAndTakesTheOldestFirst()
	{
		// One unbounded DELETE on a table that has never been pruned is one long lock.
		$ages = [];
		foreach ([5, 1, 4, 2, 3] as $order) {
			$item = $this->item('https://example.com/failed' . $order);
			$this->_queue->enqueue($item);
			$this->_queue->abandon($item);
			$this->age($item, 86400 * $order);
			$ages[$item->getId()] = $order;
		}
		$young = $this->item('https://example.com/young');
		$this->_queue->enqueue($young);
		$this->_queue->abandon($young);

		$this->assertSame(2, $this->_queue->prune(3600, 2));
		$this->assertSame(4, $this->_queue->getCount());
		$left = $this->_db->createCommand(
			'SELECT tabuid FROM ' . $this->_queue->getTableName() . ' WHERE tabuid <> ' . (int) $young->getId()
		)->queryColumn();
		$this->assertSame([1, 2, 3], array_values(array_map(static fn ($id) => $ages[(int) $id], $left)), 'the two oldest went');

		$this->assertSame(3, $this->_queue->prune(3600, 100), 'a bound above what qualifies removes what qualifies');
		$this->assertSame(1, $this->_queue->getCount(), 'the young one stays');
		$this->assertSame(0, $this->_queue->prune(3600, 100));
	}

	public function testABoundedPruneLeavesPendingDeliveriesAloneToo()
	{
		$pending = $this->item('https://example.com/pending');
		$this->_queue->enqueue($pending);
		$this->age($pending, 86400 * 365);

		$this->assertSame(0, $this->_queue->prune(3600, 10));
		$this->assertSame(1, $this->_queue->getCount(TWebhookQueueStatus::Pending));
	}

	public function testABoundOfZeroOrLessIsUnbounded()
	{
		for ($i = 0; $i < 3; $i++) {
			$item = $this->item('https://example.com/failed' . $i);
			$this->_queue->enqueue($item);
			$this->_queue->abandon($item);
			$this->age($item, 86400);
		}

		$this->assertSame(3, $this->_queue->prune(3600, 0));
		$this->assertSame(0, $this->_queue->getCount());
	}

	public function testPruningLeavesFinishedDeliveriesThatAreStillYoung()
	{
		$item = $this->item();
		$this->_queue->enqueue($item);
		$this->_queue->abandon($this->_queue->claim(1, 60)[0]);

		$this->assertSame(0, $this->_queue->prune(3600));
		$this->assertSame(1, $this->_queue->getCount(TWebhookQueueStatus::Failed));
	}

	// ── Configuration ──────────────────────────────────────────────────────────

	public function testAMissingTableIsAnErrorUnlessTheQueueMayCreateIt()
	{
		$queue = new TDbWebhookQueue();
		$queue->setDbConnection($this->_db);
		$queue->setTableName('nowhere');

		$this->expectException(TConfigurationException::class);
		$queue->getCount();
	}

	public function testTheTableNameHasToBeAPlainIdentifier()
	{
		foreach (['', 'has space', 'drop;table', '1abc', 'quoted"name'] as $name) {
			try {
				(new TDbWebhookQueue())->setTableName($name);
				$this->fail("'{$name}' should be refused");
			} catch (TConfigurationException $e) {
				$this->assertNotSame('', $e->getMessage());
			}
		}
		$queue = new TDbWebhookQueue();
		$queue->setTableName('webhook_queue_2');
		$this->assertSame('webhook_queue_2', $queue->getTableName());
	}

	public function testAQueueWithNoConnectionSaysSo()
	{
		$this->expectException(TConfigurationException::class);
		(new TDbWebhookQueue())->getDbConnection();
	}

	public function testAConnectionIdNamingNothingUsableSaysSo()
	{
		$queue = new TDbWebhookQueue();
		$queue->setConnectionID('nothing-by-that-name');

		$this->expectException(TConfigurationException::class);
		$queue->getDbConnection();
	}

	public function testDefaults()
	{
		$queue = new TDbWebhookQueue();

		$this->assertSame(TDbWebhookQueue::DEFAULT_TABLE_NAME, $queue->getTableName());
		$this->assertFalse($queue->getAutoCreateTable());
		$this->assertFalse($queue->getKeepDelivered());
		$this->assertNull($queue->getConnectionID());
	}

	public function testTheConnectionIdRoundTrips()
	{
		$queue = new TDbWebhookQueue();
		$queue->setConnectionID('db');
		$this->assertSame('db', $queue->getConnectionID());

		$queue->setConnectionID('');
		$this->assertNull($queue->getConnectionID());
	}

	public function testAPayloadLargerThanSixtyFourKilobytesSurvivesTheRoundTrip()
	{
		// MySQL's TEXT is 64 KiB; a larger body was refused there, or without strict mode
		// cut and decoded back as null, and then sent as the body `null`, signed.
		$payload = ['blob' => str_repeat('x', 70000)];
		$item = $this->item('https://example.com/hook', $payload);
		$this->_queue->enqueue($item);

		$this->assertSame($payload, $this->_queue->claim(1, 60)[0]->getPayload());
	}
}
