<?php

use Belisoful\Prado\Web\Webhooks\TWebhookQueueItem;
use Belisoful\Prado\Web\Webhooks\TWebhookQueueStatus;
use Belisoful\Prado\Web\Webhooks\TWebhookTarget;
use Prado\Exceptions\TInvalidDataValueException;

class TWebhookQueueItemTest extends PHPUnit\Framework\TestCase
{
	public function testItCarriesWhatWasQueued()
	{
		$item = new TWebhookQueueItem(['url' => 'https://example.com/hook'], ['id' => 1], 'invoice.paid');

		$this->assertSame(['url' => 'https://example.com/hook'], $item->getTargetSpec());
		$this->assertSame(['id' => 1], $item->getPayload());
		$this->assertSame(1, $item['id'], 'the payload is the event parameter');
		$this->assertSame('invoice.paid', $item->getEvent());
		$this->assertSame(TWebhookQueueStatus::Pending, $item->getStatus());
	}

	public function testADeliveryIdIsMintedWhenNoneIsGiven()
	{
		$first = new TWebhookQueueItem('https://example.com/hook');
		$second = new TWebhookQueueItem('https://example.com/hook');

		$this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $first->getDeliveryId());
		$this->assertNotSame($first->getDeliveryId(), $second->getDeliveryId());
	}

	public function testAGivenDeliveryIdIsKept()
	{
		$item = new TWebhookQueueItem('https://example.com/hook', null, null, 'abc123');

		$this->assertSame('abc123', $item->getDeliveryId());
	}

	public function testEveryPartRoundTrips()
	{
		$item = new TWebhookQueueItem('https://example.com/hook');
		$item->setId(7);
		$item->setDeliveryId('abc123');
		$item->setEvent('invoice.paid');
		$item->setTargetSpec(['url' => 'https://other.example/hook']);
		$item->setStatus('failed');
		$item->setAttempts(3);
		$item->setMaxAttempts(5);
		$item->setNextAttempt(1700000000);
		$item->setLastStatus('HTTP 500');
		$item->setCreatedTime(1699999999);
		$item->setUpdatedTime(1700000001);

		$this->assertSame(7, $item->getId());
		$this->assertSame('abc123', $item->getDeliveryId());
		$this->assertSame('invoice.paid', $item->getEvent());
		$this->assertSame(['url' => 'https://other.example/hook'], $item->getTargetSpec());
		$this->assertSame(TWebhookQueueStatus::Failed, $item->getStatus());
		$this->assertSame(3, $item->getAttempts());
		$this->assertSame(5, $item->getMaxAttempts());
		$this->assertSame(1700000000, $item->getNextAttempt());
		$this->assertSame('HTTP 500', $item->getLastStatus());
		$this->assertSame(1699999999, $item->getCreatedTime());
		$this->assertSame(1700000001, $item->getUpdatedTime());
	}

	public function testEmptyValuesClearBackToNull()
	{
		$item = new TWebhookQueueItem('https://example.com/hook', null, 'invoice.paid');
		$item->setEvent('');
		$item->setLastStatus('HTTP 500');
		$item->setLastStatus(null);

		$this->assertNull($item->getEvent());
		$this->assertNull($item->getLastStatus());
	}

	public function testNegativeCountsAreFloored()
	{
		$item = new TWebhookQueueItem('https://example.com/hook');
		$item->setAttempts(-1);
		$item->setMaxAttempts(-1);
		$item->setNextAttempt(-1);

		$this->assertSame(0, $item->getAttempts());
		$this->assertSame(0, $item->getMaxAttempts());
		$this->assertSame(0, $item->getNextAttempt());
	}

	public function testAHandlerSuppliedTargetRoundTrips()
	{
		$item = new TWebhookQueueItem('https://example.com/hook');
		$this->assertNull($item->getTarget());

		$target = TWebhookTarget::ensure('https://example.com/hook');
		$item->setTarget($target);
		$this->assertSame($target, $item->getTarget());

		$item->setTarget(null);
		$this->assertNull($item->getTarget());
	}

	public function testAnUnknownStatusIsRefused()
	{
		$this->expectException(TInvalidDataValueException::class);
		(new TWebhookQueueItem('https://example.com/hook'))->setStatus('halfway');
	}

	public function testStatusesAreReadInAnyCaseAndPassThrough()
	{
		$this->assertSame(TWebhookQueueStatus::Delivered, TWebhookQueueStatus::ensure(' DELIVERED '));
		$this->assertSame(TWebhookQueueStatus::Pending, TWebhookQueueStatus::ensure(TWebhookQueueStatus::Pending));
	}
}
