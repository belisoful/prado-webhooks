<?php

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\TTokenWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookTarget;
use Prado\Exceptions\TConfigurationException;

class TWebhookTargetTest extends PHPUnit\Framework\TestCase
{
	private const URL = 'https://example.com/hooks/prado';

	public function testATargetPassesThroughEnsureUnchanged()
	{
		$target = new TWebhookTarget();
		$target->setUrl(self::URL);

		$this->assertSame($target, TWebhookTarget::ensure($target));
	}

	public function testAStringIsAUrl()
	{
		$this->assertSame(self::URL, TWebhookTarget::ensure(self::URL)->getUrl());
	}

	public function testAnArraySetsPropertiesByName()
	{
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'events' => ['invoice.paid'],
			'timeout' => 4,
			'data' => 42,
		]);

		$this->assertSame(self::URL, $target->getUrl());
		$this->assertSame(['invoice.paid'], $target->getEvents());
		$this->assertSame(4, $target->getTimeout());
		$this->assertSame(42, $target->getData());
	}

	public function testSecretIsShorthandForAnHmacSignature()
	{
		// The shape an application's own subscription row most often has.
		$target = TWebhookTarget::ensure(['url' => self::URL, 'secret' => 'per-subscriber']);

		$signature = $target->getSignature();
		$this->assertInstanceOf(THmacWebhookSignature::class, $signature);
		$this->assertSame('per-subscriber', $signature->getSecret());
	}

	public function testASignerCanBeGivenDirectly()
	{
		$signer = new TTokenWebhookSignature();
		$signer->setToken('t');
		$target = TWebhookTarget::ensure(['url' => self::URL, 'signature' => $signer]);

		$this->assertSame($signer, $target->getSignature());
	}

	public function testAnArrayWithoutAUrlIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		TWebhookTarget::ensure(['events' => ['a']]);
	}

	public function testSomethingElseEntirelyIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		TWebhookTarget::ensure(42);
	}

	public function testOnlyAbsoluteHttpUrlsAreAccepted()
	{
		foreach (['/hooks/prado', 'example.com/hook', 'ftp://example.com/hook', '', 'javascript:alert(1)'] as $url) {
			try {
				TWebhookTarget::ensure($url);
				$this->fail("'{$url}' should not be a usable webhook URL");
			} catch (TConfigurationException $e) {
				$this->assertStringContainsString('http', $e->getMessage());
			}
		}
		$this->assertSame('http://example.com/hook', TWebhookTarget::ensure('http://example.com/hook')->getUrl());
	}

	public function testATargetWithNoFilterWantsEveryEvent()
	{
		$target = TWebhookTarget::ensure(self::URL);

		$this->assertNull($target->getEvents());
		$this->assertTrue($target->acceptsEvent('invoice.paid'));
		$this->assertTrue($target->acceptsEvent(null));
	}

	public function testAFilteredTargetWantsOnlyWhatItListed()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'events' => 'invoice.paid, invoice.failed']);

		$this->assertSame(['invoice.paid', 'invoice.failed'], $target->getEvents());
		$this->assertTrue($target->acceptsEvent('invoice.paid'));
		$this->assertFalse($target->acceptsEvent('invoice.refunded'));
	}

	public function testAFilteredTargetWantsNothingFromAnUnnamedSend()
	{
		// A payload with no event cannot be shown to match a subscription, so it is not sent.
		$target = TWebhookTarget::ensure(['url' => self::URL, 'events' => ['invoice.paid']]);

		$this->assertFalse($target->acceptsEvent(null));
	}

	public function testAnEmptyEventListMeansNoFilter()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'events' => ' , ']);

		$this->assertNull($target->getEvents());
		$this->assertTrue($target->acceptsEvent('anything'));
	}

	public function testBuiltHeadersCarryTheContentTypeEventAndDeliveryId()
	{
		$headers = TWebhookTarget::ensure(self::URL)->buildHeaders('invoice.paid', 'abc123');

		$this->assertSame('application/json', $headers['Content-Type']);
		$this->assertSame('invoice.paid', $headers[TWebhookTarget::DEFAULT_EVENT_HEADER]);
		$this->assertSame('abc123', $headers[TWebhookTarget::DEFAULT_DELIVERY_HEADER]);
	}

	public function testAnUnnamedSendCarriesNoEventHeader()
	{
		$headers = TWebhookTarget::ensure(self::URL)->buildHeaders(null, 'abc123');

		$this->assertArrayNotHasKey(TWebhookTarget::DEFAULT_EVENT_HEADER, $headers);
	}

	public function testTheEventAndDeliveryHeadersCanBeRenamedOrSuppressed()
	{
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'eventHeader' => 'X-Stripe-Event',
			'deliveryHeader' => '',
		]);
		$headers = $target->buildHeaders('invoice.paid', 'abc123');

		$this->assertSame('invoice.paid', $headers['X-Stripe-Event']);
		$this->assertArrayNotHasKey(TWebhookTarget::DEFAULT_DELIVERY_HEADER, $headers);
	}

	public function testTheTargetsOwnHeadersWinOverTheDefaults()
	{
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'headers' => ['Content-Type' => 'application/vnd.example+json', 'X-Tenant' => '7'],
		]);
		$headers = $target->buildHeaders(null, 'abc');

		$this->assertSame('application/vnd.example+json', $headers['Content-Type']);
		$this->assertSame('7', $headers['X-Tenant']);
	}

	public function testHeadersCanBeConfiguredAsLines()
	{
		// What an XML attribute can carry.
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'headers' => "X-Tenant: 7\nX-Region: eu-west",
		]);

		$this->assertSame(['X-Tenant' => '7', 'X-Region' => 'eu-west'], $target->getHeaders());
	}

	public function testTheMethodAndContentTypeRoundTrip()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'method' => 'put', 'contentType' => 'text/plain']);

		$this->assertSame('PUT', $target->getMethod());
		$this->assertSame('text/plain', $target->getContentType());
	}

	public function testTheRetryDelayAndEnabledFlagRoundTrip()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'retryDelay' => 250, 'enabled' => '0']);

		$this->assertSame(250, $target->getRetryDelay());
		$this->assertFalse($target->getEnabled());
	}

	public function testAnEventFilterClearsBackToNull()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'events' => ['invoice.paid']]);
		$target->setEvents(null);

		$this->assertNull($target->getEvents());
		$this->assertTrue($target->acceptsEvent(null));
	}

	public function testTheEventAndDeliveryHeaderNamesAreReadable()
	{
		$target = TWebhookTarget::ensure(self::URL);

		$this->assertSame(TWebhookTarget::DEFAULT_EVENT_HEADER, $target->getEventHeader());
		$this->assertSame(TWebhookTarget::DEFAULT_DELIVERY_HEADER, $target->getDeliveryHeader());
	}

	public function testDefaults()
	{
		$target = TWebhookTarget::ensure(self::URL);

		$this->assertSame('POST', $target->getMethod());
		$this->assertSame('application/json', $target->getContentType());
		$this->assertSame([], $target->getHeaders());
		$this->assertNull($target->getSignature());
		$this->assertTrue($target->getEnabled());
		$this->assertNull($target->getData());
		// Zero everywhere the sender's own setting is the one that applies.
		$this->assertSame(0, $target->getTimeout());
		$this->assertSame(0, $target->getMaxAttempts());
		$this->assertSame(0, $target->getRetryDelay());
	}

	public function testNegativeOverridesFallBackToTheSenders()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'timeout' => -5, 'maxAttempts' => -1]);

		$this->assertSame(0, $target->getTimeout());
		$this->assertSame(0, $target->getMaxAttempts());
	}

	public function testAnEmptyMethodIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		TWebhookTarget::ensure(['url' => self::URL, 'method' => ' ']);
	}
}
