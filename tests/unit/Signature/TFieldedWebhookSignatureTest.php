<?php

use Belisoful\Prado\Web\Webhooks\Signature\TFieldedWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;

class TFieldedWebhookSignatureTest extends PHPUnit\Framework\TestCase
{
	private const SECRET = 'whsec_test_secret';
	private const BODY = '{"id":"evt_1","type":"invoice.paid"}';

	private function request(array $headers = [], string $body = self::BODY): TWebhookRequest
	{
		return new TWebhookRequest('POST', $body, $headers);
	}

	private function signature(): TFieldedWebhookSignature
	{
		$signature = new TFieldedWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');

		return $signature;
	}

	private function header(int $timestamp, string $body = self::BODY, string $secret = self::SECRET): string
	{
		return 't=' . $timestamp . ',v1=' . hash_hmac('sha256', $timestamp . '.' . $body, $secret);
	}

	public function testVerifiesAPackedSignature()
	{
		$this->assertTrue($this->signature()->verify($this->request(['X-Signature' => $this->header(time())])));
	}

	public function testTheSignedPayloadIsTheTimestampAndBodyJoinedByAPeriod()
	{
		// Pinning the default template: everything else in this class follows from it. The
		// timestamp is read back out of the header rather than assumed, because sign() reads
		// its own clock and a second can turn over between the two calls.
		$header = $this->signature()->sign($this->request())['X-Signature'];

		$this->assertSame('{timestamp}.{body}', $this->signature()->getPayloadFormat());
		$this->assertMatchesRegularExpression('/^t=\d+,v1=[0-9a-f]{64}$/', $header);

		preg_match('/^t=(\d+),v1=([0-9a-f]+)$/', $header, $field);
		$this->assertLessThanOrEqual(2, abs(time() - (int) $field[1]), 'the timestamp is now');
		$this->assertSame(
			hash_hmac('sha256', $field[1] . '.' . self::BODY, self::SECRET),
			$field[2],
			'the signature is over that timestamp and the body'
		);
	}

	public function testSignsWhatItVerifies()
	{
		$signature = $this->signature();
		$this->assertTrue($signature->verify($this->request($signature->sign($this->request()))));
	}

	public function testAnyOfSeveralPackedSignaturesMayMatch()
	{
		// Mid-rotation a provider packs one signature per active secret.
		$now = time();
		$header = 't=' . $now
			. ',v1=' . hash_hmac('sha256', $now . '.' . self::BODY, 'whsec_the_old_one')
			. ',v1=' . hash_hmac('sha256', $now . '.' . self::BODY, self::SECRET);

		$this->assertTrue($this->signature()->verify($this->request(['X-Signature' => $header])));
	}

	public function testNoMatchingSignatureIsRejected()
	{
		$now = time();
		$header = 't=' . $now . ',v1=' . hash_hmac('sha256', $now . '.' . self::BODY, 'whsec_wrong');

		$this->assertFalse($this->signature()->verify($this->request(['X-Signature' => $header])));
	}

	public function testAModifiedBodyIsRejected()
	{
		$header = $this->header(time());
		$this->assertFalse($this->signature()->verify($this->request(['X-Signature' => $header], '{"id":"evt_2"}')));
	}

	public function testAStaleOrFutureTimestampIsRejected()
	{
		$this->assertFalse($this->signature()->verify($this->request(['X-Signature' => $this->header(time() - 3600)])));
		$this->assertFalse($this->signature()->verify($this->request(['X-Signature' => $this->header(time() + 3600)])));
	}

	public function testAZeroToleranceAcceptsAnyTimestamp()
	{
		$signature = $this->signature();
		$signature->setTolerance(0);

		$this->assertTrue($signature->verify($this->request(['X-Signature' => $this->header(1000000000)])));
	}

	public function testAMissingHeaderIsRejected()
	{
		$this->assertFalse($this->signature()->verify($this->request()));
		$this->assertFalse($this->signature()->verify($this->request(['X-Signature' => ''])));
	}

	public function testAMalformedHeaderIsRejectedRatherThanThrowing()
	{
		foreach (['garbage', 't=', 't=abc,v1=def', ',,,', 't=' . time(), 'v1=abc'] as $header) {
			$this->assertFalse(
				$this->signature()->verify($this->request(['X-Signature' => $header])),
				"'{$header}' is not a signature"
			);
		}
	}

	public function testHeaderLookupIgnoresCase()
	{
		$this->assertTrue($this->signature()->verify($this->request(['x-signature' => $this->header(time())])));
	}

	public function testAnotherSignatureFieldIsNotAccepted()
	{
		// Raising the field is how an application stops accepting a retired scheme version.
		$signature = $this->signature();
		$signature->setSignatureField('v2');

		$this->assertFalse($signature->verify($this->request(['X-Signature' => $this->header(time())])));
	}

	public function testThePackingIsConfigurable()
	{
		$signature = $this->signature();
		$signature->setFieldSeparator(';');
		$signature->setValueSeparator(':');
		$signature->setTimestampField('ts');
		$signature->setSignatureField('sig');

		$now = time();
		$header = 'ts:' . $now . ';sig:' . hash_hmac('sha256', $now . '.' . self::BODY, self::SECRET);

		$this->assertTrue($signature->verify($this->request(['X-Signature' => $header])));
		// Read back rather than compared against a clock captured before signing.
		$this->assertMatchesRegularExpression(
			'/^ts:\d+;sig:[0-9a-f]{64}$/',
			$signature->sign($this->request())['X-Signature']
		);
	}

	public function testAnIdFieldIsPackedAndSigned()
	{
		$signature = $this->signature();
		$signature->setIdField('id');
		$signature->setPayloadFormat('{id}.{timestamp}.{body}');

		$headers = $signature->sign($this->request());

		$this->assertMatchesRegularExpression('/(^|,)id=[0-9a-f]{32}(,|$)/', $headers['X-Signature']);
		$this->assertTrue($signature->verify($this->request($headers)));
		// Rewriting the packed id breaks the signature it was part of.
		$tampered = preg_replace('/id=[0-9a-f]{32}/', 'id=' . str_repeat('0', 32), $headers['X-Signature']);
		$this->assertFalse($signature->verify($this->request(['X-Signature' => $tampered])));
	}

	public function testDefaults()
	{
		$signature = new TFieldedWebhookSignature();

		$this->assertSame(TFieldedWebhookSignature::DEFAULT_FIELD_SEPARATOR, $signature->getFieldSeparator());
		$this->assertSame(TFieldedWebhookSignature::DEFAULT_VALUE_SEPARATOR, $signature->getValueSeparator());
		$this->assertSame(TFieldedWebhookSignature::DEFAULT_TIMESTAMP_FIELD, $signature->getTimestampField());
		$this->assertSame(TFieldedWebhookSignature::DEFAULT_SIGNATURE_FIELD, $signature->getSignatureField());
		$this->assertNull($signature->getIdField());
		$this->assertSame(300, $signature->getTolerance());
	}

	public function testEmptySeparatorsAndFieldsAreRefused()
	{
		foreach (['setFieldSeparator', 'setValueSeparator', 'setTimestampField', 'setSignatureField'] as $setter) {
			try {
				(new TFieldedWebhookSignature())->{$setter}('');
				$this->fail("{$setter}('') should be refused");
			} catch (TConfigurationException $e) {
				$this->assertNotSame('', $e->getMessage());
			}
		}
	}

	public function testVerifyingWithoutASecretIsAConfigurationError()
	{
		$signature = new TFieldedWebhookSignature();
		$signature->setHeader('X-Signature');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request(['X-Signature' => $this->header(time())]));
	}
}
