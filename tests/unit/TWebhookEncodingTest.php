<?php

use Belisoful\Prado\Web\Webhooks\TWebhookEncoding;
use Prado\Exceptions\TInvalidDataValueException;

class TWebhookEncodingTest extends PHPUnit\Framework\TestCase
{
	private function raw(): string
	{
		return hash_hmac('sha256', 'body', 'secret', true);
	}

	public function testEachEncodingRendersTheBytesItsOwnWay()
	{
		$raw = $this->raw();

		$this->assertSame($raw, TWebhookEncoding::Raw->encode($raw));
		$this->assertSame(bin2hex($raw), TWebhookEncoding::Hex->encode($raw));
		$this->assertSame(base64_encode($raw), TWebhookEncoding::Base64->encode($raw));
		$this->assertSame(
			rtrim(strtr(base64_encode($raw), '+/', '-_'), '='),
			TWebhookEncoding::Base64Url->encode($raw)
		);
	}

	public function testBase64UrlIsUrlSafeAndUnpadded()
	{
		// The two properties JWT depends on: no +, no /, no =.
		$encoded = TWebhookEncoding::Base64Url->encode(random_bytes(50));

		$this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $encoded);
	}

	public function testEveryEncodingRoundTrips()
	{
		$raw = $this->raw();
		foreach (TWebhookEncoding::cases() as $encoding) {
			$this->assertSame($raw, $encoding->decode($encoding->encode($raw)), $encoding->value . ' round trips');
		}
	}

	public function testDecodingRefusesMalformedTextRatherThanGuessing()
	{
		// This input is attacker supplied, so a wrong answer matters more than a helpful one.
		$this->assertFalse(TWebhookEncoding::Hex->decode('zz'));
		$this->assertFalse(TWebhookEncoding::Hex->decode('abc'));
		$this->assertFalse(TWebhookEncoding::Base64->decode('!!!!'));
	}

	public function testEnsurePassesAnEncodingThrough()
	{
		$this->assertSame(TWebhookEncoding::Base64, TWebhookEncoding::ensure(TWebhookEncoding::Base64));
	}

	public function testEnsureReadsANameInAnyCase()
	{
		// A configuration file hands over strings, and nobody agrees on their case.
		$this->assertSame(TWebhookEncoding::Hex, TWebhookEncoding::ensure('HEX'));
		$this->assertSame(TWebhookEncoding::Base64Url, TWebhookEncoding::ensure('  Base64Url '));
	}

	public function testEnsureRejectsAnUnknownName()
	{
		$this->expectException(TInvalidDataValueException::class);
		$this->expectExceptionMessage('base32');
		TWebhookEncoding::ensure('base32');
	}
}
