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

	public function testAnOverLongStatusIsTrimmedWithAsciiDots()
	{
		// A UTF-8 ellipsis cannot be stored by a latin1 MySQL table, and the write recording
		// a failure would fail for the mark that says it was shortened.
		$item = new TWebhookQueueItem('https://example.com/hook');
		$item->setLastStatus(str_repeat('x', 500));

		$status = (string) $item->getLastStatus();
		$this->assertSame(TWebhookQueueItem::MAX_LAST_STATUS_LENGTH, strlen($status));
		$this->assertStringEndsWith('...', $status);
		$this->assertMatchesRegularExpression('/^[\x20-\x7e]+$/', $status, 'ASCII only');

		$item->setLastStatus(str_repeat('y', TWebhookQueueItem::MAX_LAST_STATUS_LENGTH));
		$this->assertSame(str_repeat('y', TWebhookQueueItem::MAX_LAST_STATUS_LENGTH), $item->getLastStatus(), 'exactly the width is not trimmed');
	}

	public function testADeliveryIdWiderThanItsColumnIsRefused()
	{
		$item = new TWebhookQueueItem('https://example.com/hook');
		$item->setDeliveryId(str_repeat('a', TWebhookQueueItem::MAX_DELIVERY_ID_LENGTH));
		$this->assertSame(TWebhookQueueItem::MAX_DELIVERY_ID_LENGTH, strlen($item->getDeliveryId()));

		try {
			$item->setDeliveryId(str_repeat('a', TWebhookQueueItem::MAX_DELIVERY_ID_LENGTH + 1));
			$this->fail('an over-long delivery id should be refused, not truncated into an id nothing else has');
		} catch (TInvalidDataValueException $e) {
			$this->assertStringContainsString('DeliveryId', $e->getMessage());
			$this->assertStringContainsString((string) TWebhookQueueItem::MAX_DELIVERY_ID_LENGTH, $e->getMessage());
		}
		$this->assertSame(TWebhookQueueItem::MAX_DELIVERY_ID_LENGTH, strlen($item->getDeliveryId()), 'unchanged');
	}

	public function testAnEventWiderThanItsColumnIsRefused()
	{
		$item = new TWebhookQueueItem('https://example.com/hook');
		$item->setEvent(str_repeat('e', TWebhookQueueItem::MAX_EVENT_LENGTH));
		$this->assertSame(TWebhookQueueItem::MAX_EVENT_LENGTH, strlen((string) $item->getEvent()));

		$this->expectException(TInvalidDataValueException::class);
		$this->expectExceptionMessage('Event');
		$item->setEvent(str_repeat('e', TWebhookQueueItem::MAX_EVENT_LENGTH + 1));
	}

	public function testTheConstructorEnforcesTheSameLimits()
	{
		try {
			new TWebhookQueueItem('https://example.com/hook', null, str_repeat('e', TWebhookQueueItem::MAX_EVENT_LENGTH + 1));
			$this->fail('an over-long event should be refused at construction');
		} catch (TInvalidDataValueException $e) {
			$this->assertStringContainsString('Event', $e->getMessage());
		}

		$this->expectException(TInvalidDataValueException::class);
		new TWebhookQueueItem('https://example.com/hook', null, null, str_repeat('d', TWebhookQueueItem::MAX_DELIVERY_ID_LENGTH + 1));
	}
}
