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

	public function testBase64UrlIsDecodedStrictly()
	{
		// RFC 4648 section 5 and RFC 7515: the URL-safe alphabet only, no padding, no
		// whitespace. A JWS segment spelled any other way was not made by a conforming
		// signer, and two spellings of one signature are two things to get wrong.
		$raw = $this->raw();
		$standard = base64_encode($raw);
		$url = TWebhookEncoding::Base64Url->encode($raw);

		$this->assertSame($raw, TWebhookEncoding::Base64Url->decode($url));
		foreach ([
			'standard alphabet' => $standard,
			'padding' => $url . '=',
			'double padding' => rtrim($standard, '=') . '==',
			'a plus' => strtr($url, '-', '+'),
			'a slash' => strtr($url, '_', '/'),
			'a space' => substr($url, 0, 4) . ' ' . substr($url, 4),
			'a newline' => $url . "\n",
			'a leading space' => ' ' . $url,
			'a tab' => "\t" . $url,
			'an impossible length' => 'A',
			'an impossible length, longer' => 'AAAAA',
			'a period' => 'ab.cd',
		] as $why => $malformed) {
			$this->assertFalse(TWebhookEncoding::Base64Url->decode($malformed), $why);
		}
	}

	public function testBase64UrlDecodesEveryValidLength()
	{
		foreach ([0, 1, 2, 3, 4, 5, 31, 32, 33, 64] as $length) {
			$raw = $length === 0 ? '' : random_bytes($length);
			$this->assertSame($raw, TWebhookEncoding::Base64Url->decode(TWebhookEncoding::Base64Url->encode($raw)), "length {$length}");
		}
		$this->assertSame('', TWebhookEncoding::Base64Url->decode(''));
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
