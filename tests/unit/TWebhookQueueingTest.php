<?php

use Belisoful\Prado\Web\Webhooks\IWebhookQueue;
use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookCronTask;
use Belisoful\Prado\Web\Webhooks\TWebhookDelivery;
use Belisoful\Prado\Web\Webhooks\TWebhookModule;
use Belisoful\Prado\Web\Webhooks\TWebhookPruneCronTask;
use Belisoful\Prado\Web\Webhooks\TWebhookQueueItem;
use Belisoful\Prado\Web\Webhooks\TWebhookQueueStatus;
use Belisoful\Prado\Web\Webhooks\TWebhookSender;
use Belisoful\Prado\Web\Webhooks\TWebhookTarget;
use Prado\Exceptions\TConfigurationException;
use Prado\IO\HttpClient\THttpClient;
use Prado\IO\HttpClient\THttpClientException;
use Prado\IO\HttpClient\THttpClientResponse;

/**
 * A queue in memory. It proves the contract is implementable by something that is not a
 * database, and lets the module's own behaviour be tested without one.
 *
 * It does not fence its write-backs on the lease, as the contract asks of a shared one: with
 * a single process and no expiry there is no second runner to fence against. A real
 * implementation has to -- see TWebhookQueueDriverTestCase for those tests.
 */
class TestArrayWebhookQueue implements IWebhookQueue
{
	/** @var TWebhookQueueItem[] */
	public array $items = [];
	public array $succeeded = [];
	public array $abandoned = [];
	public array $rescheduled = [];
	private int $_nextId = 1;

	public function enqueue(TWebhookQueueItem $item): void
	{
		$item->setId($this->_nextId++);
		$this->items[$item->getId()] = $item;
	}

	public function claim(int $limit, int $leaseSeconds): array
	{
		$due = array_filter(
			$this->items,
			static fn ($i) => $i->getStatus() === TWebhookQueueStatus::Pending && $i->getNextAttempt() <= time()
		);

		return array_slice(array_values($due), 0, max(0, $limit));
	}

	public function succeed(TWebhookQueueItem $item): void
	{
		$item->setStatus(TWebhookQueueStatus::Delivered);
		$this->succeeded[] = $item;
		unset($this->items[$item->getId()]);
	}

	public function reschedule(TWebhookQueueItem $item, int $delaySeconds): void
	{
		$item->setNextAttempt(time() + $delaySeconds);
		$this->rescheduled[] = [$item, $delaySeconds];
	}

	public function abandon(TWebhookQueueItem $item): void
	{
		$item->setStatus(TWebhookQueueStatus::Failed);
		$this->abandoned[] = $item;
	}

	public function prune(int $age): int
	{
		return 0;
	}

	public function getCount(?TWebhookQueueStatus $status = null): int
	{
		if ($status === null) {
			return count($this->items);
		}

		return count(array_filter($this->items, static fn ($i) => $i->getStatus() === $status));
	}
}

/** Answers from a script and records what it was asked. */
class TestQueueHttpClient extends THttpClient
{
	public array $requests = [];
	public array $answers = [];

	public function download(string $method, string $url, array $headers = [], ?string $body = null): THttpClientResponse
	{
		$this->requests[] = ['url' => $url, 'headers' => $headers, 'body' => $body];
		$answer = count($this->answers) > 1 ? array_shift($this->answers) : ($this->answers[0] ?? null);
		if ($answer instanceof Throwable) {
			throw $answer;
		}

		return $answer ?? new THttpClientResponse(200);
	}
}

class TWebhookQueueingTest extends PHPUnit\Framework\TestCase
{
	private const URL = 'https://example.com/hooks/prado';

	private TWebhookModule $_module;
	private TestArrayWebhookQueue $_queue;
	private TestQueueHttpClient $_client;

	protected function setUp(): void
	{
		$this->_queue = new TestArrayWebhookQueue();
		$this->_client = new TestQueueHttpClient();

		$sender = new TWebhookSender();
		$sender->setHttpClient($this->_client);

		$this->_module = new TWebhookModule();
		$this->_module->setSender($sender);
		$this->_module->setQueue($this->_queue);
	}

	private function answer(...$answers): void
	{
		$this->_client->answers = $answers;
	}

	// ── Queueing ───────────────────────────────────────────────────────────────

	public function testQueueingStoresInsteadOfSending()
	{
		$items = $this->_module->queue(self::URL, ['id' => 1], 'invoice.paid');

		$this->assertCount(1, $items);
		$this->assertSame([], $this->_client->requests, 'nothing is sent while queueing');
		$this->assertSame(1, $this->_queue->getCount());
		$this->assertSame('invoice.paid', $items[0]->getEvent());
		$this->assertSame(['id' => 1], $items[0]->getPayload());
	}

	public function testQueueingSkipsDisabledTargetsAndOnesThatWantOtherEvents()
	{
		$items = $this->_module->queue([
			['url' => self::URL, 'events' => ['invoice.paid']],
			['url' => 'https://other.example/hook', 'events' => ['invoice.failed']],
			['url' => 'https://off.example/hook', 'enabled' => false],
		], ['id' => 1], 'invoice.paid');

		$this->assertCount(1, $items);
		$this->assertSame(['url' => self::URL, 'events' => ['invoice.paid']], $items[0]->getTargetSpec());
	}

	public function testATargetsAttemptLimitIsCarriedIntoTheQueue()
	{
		$items = $this->_module->queue([['url' => self::URL, 'maxAttempts' => 3]], ['id' => 1]);

		$this->assertSame(3, $items[0]->getMaxAttempts());
	}

	public function testABuiltTargetWithoutASignatureCanBeQueued()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'method' => 'PUT', 'data' => 42]);

		$items = $this->_module->queue($target, ['id' => 1]);

		$spec = $items[0]->getTargetSpec();
		$this->assertSame(self::URL, $spec['url']);
		$this->assertSame('PUT', $spec['method']);
		$this->assertSame(42, $spec['data']);
	}

	public function testABuiltTargetCarryingASignatureIsRefused()
	{
		// Writing a key into the queue table by accident is worse than refusing.
		$target = TWebhookTarget::ensure(['url' => self::URL, 'secret' => 's3cret']);

		$this->expectException(TConfigurationException::class);
		$this->_module->queue($target, ['id' => 1]);
	}

	public function testASpecificationHoldingAnObjectIsRefused()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');

		$this->expectException(TConfigurationException::class);
		$this->_module->queue([['url' => self::URL, 'signature' => $signature]], ['id' => 1]);
	}

	public function testAnObjectAnywhereInTheSpecificationIsRefused()
	{
		// json_encode turns an object into whatever its public properties happen to be, so a
		// signer nested in a header would come back as something else -- silently, having
		// written part of itself into the table on the way.
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');

		foreach ([
			'headers.X-Sig' => ['url' => self::URL, 'headers' => ['X-Sig' => $signature]],
			'headers.a.b' => ['url' => self::URL, 'headers' => ['a' => ['b' => $signature]]],
		] as $path => $spec) {
			try {
				$this->_module->queue([$spec], ['id' => 1]);
				$this->fail("an object at {$path} should be refused");
			} catch (TConfigurationException $e) {
				$this->assertStringContainsString($path, $e->getMessage());
			}
		}
	}

	public function testAnObjectOnABuiltTargetsDataIsRefused()
	{
		$target = TWebhookTarget::ensure(self::URL);
		$target->setData(new THmacWebhookSignature());

		$this->expectException(TConfigurationException::class);
		$this->expectExceptionMessage('data');
		$this->_module->queue($target, ['id' => 1]);
	}

	public function testNestedValuesThatAreNotObjectsAreFine()
	{
		$items = $this->_module->queue([[
			'url' => self::URL,
			'headers' => ['X-Tenant' => '7'],
			'events' => ['invoice.paid'],
			'data' => ['id' => 7, 'nested' => ['deeper' => true, 'nothing' => null]],
		]], ['id' => 1], 'invoice.paid');

		$this->assertCount(1, $items);
		$this->assertSame(['id' => 7, 'nested' => ['deeper' => true, 'nothing' => null]], $items[0]->getTargetSpec()['data']);
	}

	public function testASecretInTheSpecificationIsQueuedWithIt()
	{
		// Documented, and deliberate: the alternative is the onDequeue handler below.
		$items = $this->_module->queue([['url' => self::URL, 'secret' => 's3cret']], ['id' => 1]);

		$this->assertSame('s3cret', $items[0]->getTargetSpec()['secret']);
	}

	public function testQueueingWithoutAQueueSaysSo()
	{
		$module = new TWebhookModule();

		$this->assertFalse($module->getHasQueue());
		$this->expectException(TConfigurationException::class);
		$module->queue(self::URL, ['id' => 1]);
	}

	// ── Draining ───────────────────────────────────────────────────────────────

	public function testDrainingSendsWhatWasQueued()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_module->queue(self::URL, ['id' => 1], 'invoice.paid');

		$deliveries = $this->_module->drain();

		$this->assertCount(1, $deliveries);
		$this->assertTrue($deliveries[0]->getSuccessful());
		$this->assertCount(1, $this->_client->requests);
		$this->assertSame('{"id":1}', $this->_client->requests[0]['body']);
		$this->assertCount(1, $this->_queue->succeeded);
		$this->assertSame(0, $this->_queue->getCount());
	}

	public function testTheDeliveryIdIsTheQueuedOneAndSurvivesEveryAttempt()
	{
		// A queue is at-least-once, so this id is how a receiver recognises a repeat.
		$this->answer(new THttpClientResponse(500));
		$item = $this->_module->queue(self::URL, ['id' => 1])[0];

		$first = $this->_module->drain()[0];
		$this->_queue->items[$item->getId()]->setNextAttempt(0);
		$second = $this->_module->drain()[0];

		$this->assertSame($item->getDeliveryId(), $first->getID());
		$this->assertSame($item->getDeliveryId(), $second->getID());
		$this->assertSame(
			$item->getDeliveryId(),
			$this->_client->requests[0]['headers'][TWebhookTarget::DEFAULT_DELIVERY_HEADER]
		);
	}

	public function testOneAttemptIsMadePerDrain()
	{
		// The queue owns the cadence; the sender must not spend three attempts in one run.
		$this->answer(new THttpClientResponse(500));
		$this->_module->getSender()->setMaxAttempts(5);
		$this->_module->queue(self::URL, ['id' => 1]);

		$this->_module->drain();

		$this->assertCount(1, $this->_client->requests);
	}

	public function testAFailedDeliveryGoesBackWithADoublingDelay()
	{
		$this->answer(new THttpClientResponse(503));
		$this->_module->setQueueRetryDelay(60);
		$item = $this->_module->queue(self::URL, ['id' => 1])[0];

		$delays = [];
		for ($run = 1; $run <= 4; $run++) {
			$item->setNextAttempt(0);
			$this->_module->drain();
			$delays[] = end($this->_queue->rescheduled)[1];
		}

		$this->assertSame([60, 120, 240, 480], $delays);
		$this->assertSame(4, $item->getAttempts());
		$this->assertSame('HTTP 503', $item->getLastStatus());
	}

	public function testTheDelayHasACeiling()
	{
		$this->answer(new THttpClientResponse(503));
		$this->_module->setQueueRetryDelay(60);
		$this->_module->setQueueMaxRetryDelay(100);
		$item = $this->_module->queue(self::URL, ['id' => 1])[0];

		$this->_module->drain();
		$item->setNextAttempt(0);
		$this->_module->drain();

		$this->assertSame(100, end($this->_queue->rescheduled)[1]);
	}

	public function testADeliveryIsAbandonedOnceItRunsOutOfAttempts()
	{
		$this->answer(new THttpClientResponse(500));
		$this->_module->setQueueMaxAttempts(3);
		$item = $this->_module->queue(self::URL, ['id' => 1])[0];

		for ($run = 1; $run <= 3; $run++) {
			$item->setNextAttempt(0);
			$this->_module->drain();
		}

		$this->assertCount(1, $this->_queue->abandoned);
		$this->assertSame(TWebhookQueueStatus::Failed, $item->getStatus());
		$this->assertCount(2, $this->_queue->rescheduled, 'rescheduled twice, then given up on');
	}

	public function testATargetsOwnAttemptLimitWinsOverTheModules()
	{
		$this->answer(new THttpClientResponse(500));
		$this->_module->setQueueMaxAttempts(10);
		$item = $this->_module->queue([['url' => self::URL, 'maxAttempts' => 2]], ['id' => 1])[0];

		$item->setNextAttempt(0);
		$this->_module->drain();
		$item->setNextAttempt(0);
		$this->_module->drain();

		$this->assertCount(1, $this->_queue->abandoned);
	}

	public function testATransportFailureIsRetriedLikeAnyOther()
	{
		$this->answer(new THttpClientException('Connection refused'));
		$item = $this->_module->queue(self::URL, ['id' => 1])[0];

		$this->_module->drain();

		$this->assertCount(1, $this->_queue->rescheduled);
		$this->assertSame('Connection refused', $item->getLastStatus());
	}

	public function testADeliveryCalledOffIsNotRetriedForever()
	{
		$this->_module->getSender()->onSending[] = function ($sender, TWebhookDelivery $delivery) {
			$delivery->setCancel(true);
		};
		$item = $this->_module->queue(self::URL, ['id' => 1])[0];

		$this->_module->drain();

		$this->assertSame([], $this->_client->requests);
		$this->assertCount(1, $this->_queue->abandoned);
		$this->assertSame('cancelled', $item->getLastStatus());
	}

	public function testAHandlerCanSupplyTheTargetSoNoSecretIsEverStored()
	{
		// The documented alternative to queueing the secret: store a reference, put the
		// built target back on the way out.
		$this->answer(new THttpClientResponse(200));
		$signature = new THmacWebhookSignature();
		$signature->setSecret('never-written-down');

		$this->_module->onDequeue[] = function ($sender, TWebhookQueueItem $item) use ($signature) {
			$target = TWebhookTarget::ensure($item->getTargetSpec());
			$this->assertSame(7, $target->getData(), 'the reference is what was stored');
			$target->setSignature($signature);
			$item->setTarget($target);
		};

		$this->_module->queue([['url' => self::URL, 'data' => 7]], ['id' => 1]);
		$this->_module->drain();

		$headers = $this->_client->requests[0]['headers'];
		$this->assertArrayHasKey(THmacWebhookSignature::DEFAULT_HEADER, $headers);
	}

	public function testOneUnbuildableRowDoesNotStopTheRest()
	{
		// Left to propagate, a row whose stored specification will not rebuild ends the run
		// before the rest of the batch -- and is claimed again next time, so the queue never
		// moves. A corrupt column, a row written by an older version, anything hand-edited.
		$this->answer(new THttpClientResponse(200));
		$this->_module->queue('https://example.com/first', ['n' => 1]);
		$this->_queue->enqueue($poison = new TWebhookQueueItem([], ['n' => 'corrupt']));
		$this->_module->queue('https://example.com/third', ['n' => 3]);

		$deliveries = $this->_module->drain(10, 600);

		$this->assertCount(2, $deliveries, 'the two good deliveries were made');
		$this->assertCount(2, $this->_client->requests);
		$this->assertSame(1, $poison->getAttempts(), 'the bad row used an attempt');
		$this->assertStringContainsString('Url', (string) $poison->getLastStatus());
	}

	public function testAnUnbuildableRowRunsOutOfAttemptsAndSettles()
	{
		$this->_module->setQueueMaxAttempts(2);
		$this->_queue->enqueue($poison = new TWebhookQueueItem([], ['n' => 'corrupt']));

		$this->_module->drain();
		$this->assertCount(1, $this->_queue->rescheduled);
		$poison->setNextAttempt(0);
		$this->_module->drain();

		$this->assertCount(1, $this->_queue->abandoned);
		$this->assertSame(TWebhookQueueStatus::Failed, $poison->getStatus());
	}

	public function testASignerThatCannotSignIsContainedToItsOwnDelivery()
	{
		// A configuration mistake reaches drain() as an exception from the signer, and must
		// not cost the rest of the batch either.
		$this->answer(new THttpClientResponse(200));
		$this->_module->onDequeue[] = function ($sender, TWebhookQueueItem $item) {
			if (($item->getPayload()['n'] ?? null) !== 'unsigned') {
				return;
			}
			$target = TWebhookTarget::ensure($item->getTargetSpec());
			$target->setSignature(new THmacWebhookSignature());   // no secret
			$item->setTarget($target);
		};
		$this->_module->queue('https://example.com/first', ['n' => 1]);
		$this->_module->queue('https://example.com/second', ['n' => 'unsigned']);
		$this->_module->queue('https://example.com/third', ['n' => 3]);

		$deliveries = $this->_module->drain();

		$this->assertCount(2, $deliveries);
		$this->assertCount(1, $this->_queue->rescheduled);
		$this->assertStringContainsString('Secret', (string) $this->_queue->rescheduled[0][0]->getLastStatus());
	}

	public function testDrainingTakesNoMoreThanItIsAskedFor()
	{
		$this->answer(new THttpClientResponse(200));
		for ($i = 0; $i < 5; $i++) {
			$this->_module->queue('https://example.com/hook' . $i, ['id' => $i]);
		}

		$this->assertCount(2, $this->_module->drain(2));
		$this->assertCount(3, $this->_module->drain(10));
	}

	public function testDrainingAnEmptyQueueDoesNothing()
	{
		$this->assertSame([], $this->_module->drain());
	}

	// ── The cron tasks ─────────────────────────────────────────────────────────

	public function testTheCronTaskDrainsTheQueue()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_module->queue(self::URL, ['id' => 1]);

		$task = new class ($this->_module) extends TWebhookCronTask {
			public function __construct(private TWebhookModule $_webhooks)
			{
				parent::__construct();
			}

			public function getWebhookModule(): TWebhookModule
			{
				return $this->_webhooks;
			}
		};
		$deliveries = $task->execute(null);

		$this->assertCount(1, $deliveries);
		$this->assertTrue($deliveries[0]->getSuccessful());
	}

	public function testTheCronTaskBatchAndLeaseRoundTrip()
	{
		$task = new TWebhookCronTask();

		$this->assertSame(TWebhookCronTask::DEFAULT_BATCH_SIZE, $task->getBatchSize());
		$this->assertSame(TWebhookCronTask::DEFAULT_LEASE_SECONDS, $task->getLeaseSeconds());

		$task->setBatchSize(0);
		$task->setLeaseSeconds(-1);
		$this->assertSame(1, $task->getBatchSize(), 'a batch of none would never drain');
		$this->assertSame(1, $task->getLeaseSeconds());

		$task->setBatchSize(50);
		$task->setLeaseSeconds(900);
		$this->assertSame(50, $task->getBatchSize());
		$this->assertSame(900, $task->getLeaseSeconds());
	}

	public function testThePruneTaskPrunes()
	{
		$task = new class ($this->_module) extends TWebhookPruneCronTask {
			public function __construct(private TWebhookModule $_webhooks)
			{
				parent::__construct();
			}

			public function getWebhookModule(): TWebhookModule
			{
				return $this->_webhooks;
			}
		};
		$task->setMaxAge(0);

		$this->assertSame(TWebhookPruneCronTask::DEFAULT_MAX_AGE, (new TWebhookPruneCronTask())->getMaxAge());
		$this->assertSame(0, $task->getMaxAge());
		$this->assertSame(0, $task->execute(null), 'the in-memory queue prunes nothing');
	}

	public function testATaskFindsTheModuleByItsDefaultId()
	{
		$module = $this->_module;
		$task = new class ($module) extends TWebhookCronTask {
			public mixed $resolved = null;

			public function __construct(private TWebhookModule $_webhooks)
			{
				parent::__construct();
			}

			public function getModule()
			{
				$this->resolved = $this->getModuleId();

				return $this->_webhooks;
			}
		};

		$this->assertSame($module, $task->getWebhookModule());
		$this->assertSame(TWebhookModule::DEFAULT_MODULE_ID, $task->resolved, 'it looks for the package id');
	}

	public function testATaskPointedAtSomethingElseSaysSo()
	{
		$task = new class () extends TWebhookCronTask {
			public function getModule()
			{
				return new TestArrayWebhookQueue();
			}
		};
		$task->setModuleId('not-the-webhooks');

		$this->expectException(TConfigurationException::class);
		$task->getWebhookModule();
	}

	public function testAQueueIdNamingNothingUsableSaysSo()
	{
		$module = new TWebhookModule();
		$module->setQueueID('nothing-by-that-name');

		$this->expectException(TConfigurationException::class);
		$module->getQueue();
	}

	public function testTheQueueSettingsRoundTrip()
	{
		$this->_module->setQueueMaxAttempts(0);
		$this->_module->setQueueMaxRetryDelay(0);
		$this->assertSame(1, $this->_module->getQueueMaxAttempts());
		$this->assertSame(1, $this->_module->getQueueMaxRetryDelay());

		$this->_module->setQueueMaxAttempts(12);
		$this->_module->setQueueRetryDelay(30);
		$this->_module->setQueueMaxRetryDelay(7200);

		$this->assertSame(12, $this->_module->getQueueMaxAttempts());
		$this->assertSame(30, $this->_module->getQueueRetryDelay());
		$this->assertSame(7200, $this->_module->getQueueMaxRetryDelay());
		$this->assertTrue($this->_module->getHasQueue());
	}

	public function testTheQueueIdRoundTrips()
	{
		$module = new TWebhookModule();
		$module->setQueueID('webhook-queue');

		$this->assertSame('webhook-queue', $module->getQueueID());
		$this->assertTrue($module->getHasQueue());

		$module->setQueueID('');
		$this->assertNull($module->getQueueID());
		$this->assertFalse($module->getHasQueue());
	}
}
