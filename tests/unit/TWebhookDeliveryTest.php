<?php

use Belisoful\Prado\Web\Webhooks\TWebhookDelivery;
use Belisoful\Prado\Web\Webhooks\TWebhookTarget;
use Prado\IO\HttpClient\THttpClientResponse;

class TWebhookDeliveryTest extends PHPUnit\Framework\TestCase
{
	private function delivery(): TWebhookDelivery
	{
		return new TWebhookDelivery(
			TWebhookTarget::ensure('https://example.com/hook'),
			'abc123',
			['invoice' => ['id' => 7]],
			'{"invoice":{"id":7}}',
			'invoice.paid'
		);
	}

	public function testItReportsWhatIsBeingSent()
	{
		$delivery = $this->delivery();

		$this->assertSame('abc123', $delivery->getID());
		$this->assertSame('invoice.paid', $delivery->getEvent());
		$this->assertSame('{"invoice":{"id":7}}', $delivery->getBody());
		$this->assertSame('https://example.com/hook', $delivery->getTarget()->getUrl());
	}

	public function testThePayloadIsTheEventParameterAndSubscriptable()
	{
		$delivery = $this->delivery();

		$this->assertSame(['invoice' => ['id' => 7]], $delivery->getPayload());
		$this->assertSame(7, $delivery['invoice']['id']);
	}

	public function testAnUnattemptedDeliveryIsNeitherSuccessfulNorExplained()
	{
		$delivery = $this->delivery();

		$this->assertFalse($delivery->getSuccessful());
		$this->assertSame(0, $delivery->getAttempts());
		$this->assertSame('not attempted', $delivery->getStatusText());
	}

	public function testATwoHundredIsSuccessful()
	{
		$delivery = $this->delivery();
		$delivery->setResponse(new THttpClientResponse(202));

		$this->assertTrue($delivery->getSuccessful());
		$this->assertSame('HTTP 202', $delivery->getStatusText());
	}

	public function testAFiveHundredIsNotSuccessful()
	{
		$delivery = $this->delivery();
		$delivery->setResponse(new THttpClientResponse(500));

		$this->assertFalse($delivery->getSuccessful());
		$this->assertSame('HTTP 500', $delivery->getStatusText());
	}

	public function testATransportErrorReplacesAnyEarlierResponse()
	{
		// The two are mutually exclusive accounts of the same attempt, so setting one clears
		// the other rather than leaving a delivery that claims both.
		$delivery = $this->delivery();
		$delivery->setResponse(new THttpClientResponse(500));
		$delivery->setError('Connection refused');

		$this->assertNull($delivery->getResponse());
		$this->assertSame('Connection refused', $delivery->getStatusText());
		$this->assertFalse($delivery->getSuccessful());
	}

	public function testAResponseClearsAnEarlierTransportError()
	{
		$delivery = $this->delivery();
		$delivery->setError('Connection refused');
		$delivery->setResponse(new THttpClientResponse(200));

		$this->assertNull($delivery->getError());
		$this->assertTrue($delivery->getSuccessful());
	}

	public function testCancelIsOffByDefaultAndSettable()
	{
		$delivery = $this->delivery();

		$this->assertFalse($delivery->getCancel());
		$delivery->setCancel(true);
		$this->assertTrue($delivery->getCancel());
	}

	public function testHeadersAndBodyAreEditable()
	{
		$delivery = $this->delivery();
		$delivery->setHeaders(['X-Tenant' => '7']);
		$delivery->setBody('{}');

		$this->assertSame(['X-Tenant' => '7'], $delivery->getHeaders());
		$this->assertSame('{}', $delivery->getBody());
	}

	public function testAnUnnamedSendHasNoEvent()
	{
		$delivery = new TWebhookDelivery(
			TWebhookTarget::ensure('https://example.com/hook'),
			'id',
			null,
			'null'
		);

		$this->assertNull($delivery->getEvent());
	}
}
