<?php

use Belisoful\Prado\Web\Webhooks\Signature\TWebhookEcdsaTrait;
use Belisoful\Prado\Web\Webhooks\Signature\TWebhookRsaPssTrait;

/**
 * Exposes the two DER routines, which are parsers and are tested as parsers. Through the
 * public API their failure paths sit behind OpenSSL, which rejects malformed input first --
 * that is the point of having them, and it is also why they need reaching directly.
 */
class TestDerProbe
{
	use TWebhookEcdsaTrait;
	use TWebhookRsaPssTrait;

	public function encode(int $tag, string $contents): string
	{
		return $this->pssDer($tag, $contents);
	}

	public function encodeInteger(int $value): string
	{
		return $this->pssDerInteger($value);
	}

	public function read(string $der, int $offset = 0): ?array
	{
		return $this->pssDerRead($der, $offset);
	}

	public function parameters(string $digest, int $salt): ?string
	{
		return $this->pssParameters($digest, $salt);
	}

	public function rewrite(string $pem, string $digest, int $salt, bool $private): ?string
	{
		return $this->rewriteAsPss($pem, $digest, $salt, $private);
	}

	public function normalize(string $material, bool $private): ?string
	{
		return $this->normalizeRsaKey($material, $private);
	}

	public function toDer(string $raw, int $size): ?string
	{
		return $this->derFromRaw($raw, $size);
	}

	public function fromDer(string $der, int $size): ?string
	{
		return $this->rawFromDer($der, $size);
	}
}

class TWebhookDerTest extends PHPUnit\Framework\TestCase
{
	private TestDerProbe $_der;

	protected function setUp(): void
	{
		$this->_der = new TestDerProbe();
	}

	// ── Lengths ────────────────────────────────────────────────────────────────

	public function testShortAndLongFormLengthsRoundTrip()
	{
		foreach ([0, 1, 127, 128, 255, 256, 1000, 70000] as $size) {
			$contents = str_repeat("\x41", $size);
			$element = $this->_der->encode(0x04, $contents);
			$read = $this->_der->read($element);

			$this->assertNotNull($read, "length {$size} reads back");
			$this->assertSame(0x04, $read[0]);
			$this->assertSame($contents, $read[1], "length {$size} round trips");
			$this->assertSame(strlen($element), $read[2]);
		}
	}

	public function testIntegersNeverEncodeAsNegative()
	{
		foreach ([0, 1, 20, 64, 127, 128, 200, 255, 256, 65535] as $value) {
			$element = $this->_der->encodeInteger($value);
			$read = $this->_der->read($element);

			$this->assertNotNull($read);
			$this->assertSame(0x02, $read[0]);
			// A DER integer is signed, so the leading byte must not have its high bit set.
			$this->assertLessThanOrEqual(0x7f, ord($read[1][0]), "integer {$value} is positive");
			$this->assertSame($value, (int) hexdec(bin2hex($read[1])), "integer {$value} round trips");
		}
	}

	public function testReadingPastTheEndIsNullRatherThanAWarning()
	{
		foreach ([
			'',
			"\x30",
			"\x30\x05" . 'abc',          // says 5 bytes, carries 3
			"\x30\x81",                  // long form with no length byte
			"\x30\x84\xff\xff\xff\xff",  // four-byte length, nothing behind it
			"\x30\x80",                  // indefinite length, which DER does not have
			"\x30\x85\x01\x01\x01\x01\x01", // more length bytes than this reads
		] as $der) {
			$this->assertNull($this->_der->read($der), bin2hex($der));
		}
	}

	public function testReadingAtAnOffsetPastTheEndIsNull()
	{
		$this->assertNull($this->_der->read($this->_der->encode(0x04, 'abc'), 99));
	}

	// ── PSS parameters ─────────────────────────────────────────────────────────

	public function testParametersAreBuiltForEveryDigestAndRefusedOtherwise()
	{
		foreach (['sha256', 'sha384', 'sha512'] as $digest) {
			$this->assertNotNull($this->_der->parameters($digest, 32), $digest);
		}
		$this->assertNull($this->_der->parameters('sha1', 20));
		$this->assertNull($this->_der->parameters('md5', 16));
		$this->assertNull($this->_der->parameters('sha256', -1));
	}

	// ── Key rewriting ──────────────────────────────────────────────────────────

	public function testRewritingRefusesAnythingThatIsNotTheStructureItExpects()
	{
		foreach ([
			'',
			'not a pem at all',
			"-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----",              // 'ABC'
			"-----BEGIN PUBLIC KEY-----\n" . base64_encode("\x02\x01\x00") . "\n-----END PUBLIC KEY-----",
		] as $pem) {
			$this->assertNull($this->_der->rewrite($pem, 'sha256', 32, false), $pem);
			$this->assertNull($this->_der->rewrite($pem, 'sha256', 32, true), $pem);
		}
	}

	public function testRewritingRefusesAnUnknownDigestBeforeItParsesAnything()
	{
		$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

		$this->assertNull($this->_der->rewrite(openssl_pkey_get_details($key)['key'], 'sha1', 20, false));
	}

	public function testRewritingRefusesAPublicKeyGivenAsPrivateAndTheReverse()
	{
		$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		openssl_pkey_export($key, $private);
		$public = openssl_pkey_get_details($key)['key'];

		// The key material is an OCTET STRING in one and a BIT STRING in the other.
		$this->assertNull($this->_der->rewrite($public, 'sha256', 32, true));
		$this->assertNull($this->_der->rewrite((string) $private, 'sha256', 32, false));
	}

	public function testNormalizingRefusesKeysThatAreNotRsa()
	{
		$ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
		openssl_pkey_export($ec, $ecPrivate);

		$this->assertNull($this->_der->normalize(openssl_pkey_get_details($ec)['key'], false));
		$this->assertNull($this->_der->normalize((string) $ecPrivate, true));
		$this->assertNull($this->_der->normalize('not a key', false));
		$this->assertNull($this->_der->normalize('not a key', true));
	}

	// ── ECDSA coordinates ──────────────────────────────────────────────────────

	public function testCoordinatesRoundTripThroughDer()
	{
		foreach ([32, 48, 66] as $size) {
			foreach ([
				random_bytes($size * 2),
				str_repeat("\x00", $size) . random_bytes($size),   // a leading-zero coordinate
				str_repeat("\xff", $size * 2),                     // both high bits set
				str_repeat("\x00", $size * 2),                     // both zero
			] as $raw) {
				$der = $this->_der->toDer($raw, $size);
				$this->assertNotNull($der, 'size ' . $size);
				$this->assertSame($raw, $this->_der->fromDer($der, $size), 'size ' . $size);
			}
		}
	}

	public function testCoordinatesOfTheWrongLengthAreRefused()
	{
		$this->assertNull($this->_der->toDer(random_bytes(63), 32));
		$this->assertNull($this->_der->toDer('', 32));
	}

	public function testMalformedDerCoordinatesAreRefused()
	{
		foreach ([
			'',
			"\x31\x06\x02\x01\x01\x02\x01\x01",   // not a SEQUENCE
			"\x30\x06\x04\x01\x01\x02\x01\x01",   // first element is not an INTEGER
			"\x30\x06\x02\x01\x01\x04\x01\x01",   // second element is not an INTEGER
			"\x30\x03\x02\x01\x01",               // only one INTEGER
		] as $der) {
			$this->assertNull($this->_der->fromDer($der, 32), bin2hex($der));
		}
	}

	public function testACoordinateTooLargeForTheCurveIsRefused()
	{
		$oversized = "\x30\x26\x02\x21\x00" . str_repeat("\x11", 32) . "\x02\x01\x01";

		$this->assertNull($this->_der->fromDer($oversized, 16));
	}
}
