<?php

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookEncoding;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Belisoful\Prado\Web\Webhooks\TWebhookSource;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;

class THmacWebhookSignatureTest extends PHPUnit\Framework\TestCase
{
	private const SECRET = 'It\'s a Secret to Everybody';
	private const BODY = '{"action":"opened","number":1}';

	private function request(array $headers = [], string $body = self::BODY, string $url = '', array $parameters = []): TWebhookRequest
	{
		return new TWebhookRequest('POST', $body, $headers, $url, $parameters);
	}

	/** A signature configured the way the most common providers send one. */
	private function keyed(): THmacWebhookSignature
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Hub-Signature-256');
		$signature->setPrefix('sha256=');

		return $signature;
	}

	private function keyedHeader(string $body, string $secret = self::SECRET): string
	{
		return 'sha256=' . hash_hmac('sha256', $body, $secret);
	}

	public function testVerifiesAKeyedHashOfTheBody()
	{
		$this->assertTrue($this->keyed()->verify(
			$this->request(['X-Hub-Signature-256' => $this->keyedHeader(self::BODY)])
		));
	}

	public function testHeaderLookupIgnoresCase()
	{
		// Which case the header arrives in is the web server's business, not the scheme's.
		foreach (['x-hub-signature-256', 'X-HUB-SIGNATURE-256'] as $name) {
			$this->assertTrue($this->keyed()->verify($this->request([$name => $this->keyedHeader(self::BODY)])));
		}
	}

	public function testRejectsASignatureMadeWithAnotherSecret()
	{
		$this->assertFalse($this->keyed()->verify(
			$this->request(['X-Hub-Signature-256' => $this->keyedHeader(self::BODY, 'not the secret')])
		));
	}

	public function testRejectsAModifiedBody()
	{
		$header = $this->keyedHeader(self::BODY);
		$this->assertFalse($this->keyed()->verify($this->request(['X-Hub-Signature-256' => $header], self::BODY . ' ')));
	}

	public function testRejectsAMissingOrEmptyHeader()
	{
		$this->assertFalse($this->keyed()->verify($this->request()));
		$this->assertFalse($this->keyed()->verify($this->request(['X-Hub-Signature-256' => ''])));
	}

	public function testRejectsASignatureWithoutItsPrefix()
	{
		// The prefix is part of the header value, so a bare hex digest is not a match.
		$this->assertFalse($this->keyed()->verify(
			$this->request(['X-Hub-Signature-256' => hash_hmac('sha256', self::BODY, self::SECRET)])
		));
	}

	public function testSignsWhatItVerifies()
	{
		$signature = $this->keyed();
		$headers = $signature->sign($this->request());

		$this->assertSame(['X-Hub-Signature-256' => $this->keyedHeader(self::BODY)], $headers);
		$this->assertTrue($signature->verify($this->request($headers)));
	}

	public function testBase64Encoding()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Hmac-Sha256');
		$signature->setEncoding('base64');

		$expected = base64_encode(hash_hmac('sha256', self::BODY, self::SECRET, true));
		$this->assertSame($expected, $signature->sign($this->request())['X-Hmac-Sha256']);
		$this->assertTrue($signature->verify($this->request(['X-Hmac-Sha256' => $expected])));
		$this->assertSame(TWebhookEncoding::Base64, $signature->getEncoding());
	}

	public function testAnotherAlgorithm()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setAlgorithm('md5');

		$this->assertTrue($signature->verify(
			$this->request(['X-Signature' => hash_hmac('md5', self::BODY, self::SECRET)])
		));
	}

	public function testASecretThatEncodesTheKeyIsDecodedFirst()
	{
		// The Standard Webhooks arrangement: a displayed secret that is a marker plus base64.
		$key = random_bytes(24);
		$signature = new THmacWebhookSignature();
		$signature->setSecret('whsec_' . base64_encode($key));
		$signature->setSecretPrefix('whsec_');
		$signature->setSecretEncoding('base64');
		$signature->setHeader('X-Signature');
		$signature->setEncoding('base64');

		$expected = base64_encode(hash_hmac('sha256', self::BODY, $key, true));
		$this->assertTrue($signature->verify($this->request(['X-Signature' => $expected])));
	}

	public function testASecretThatWillNotDecodeIsAConfigurationError()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('!!!not base64!!!');
		$signature->setSecretEncoding('base64');

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testSeveralSignaturesInOneHeaderAreEachTried()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setPrefix('v1,');
		$signature->setSeparator(' ');

		$valid = 'v1,' . hash_hmac('sha256', self::BODY, self::SECRET);
		$other = 'v1,' . hash_hmac('sha256', self::BODY, 'a retired secret');

		$this->assertTrue($signature->verify($this->request(['X-Signature' => $other . ' ' . $valid])));
		$this->assertTrue($signature->verify($this->request(['X-Signature' => $valid . ' ' . $other])));
		$this->assertFalse($signature->verify($this->request(['X-Signature' => $other . ' ' . $other])));
	}

	// ── The payload template ───────────────────────────────────────────────────

	public function testTheUrlAndBodyCanBeSignedTogether()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setEncoding('base64');
		$signature->setPayloadFormat('{url}{body}');
		$url = 'https://example.com/index.php?webhook=payments';

		$expected = base64_encode(hash_hmac('sha256', $url . self::BODY, self::SECRET, true));
		$this->assertTrue($signature->verify($this->request(['X-Signature' => $expected], self::BODY, $url)));
		// A delivery replayed at another URL no longer verifies.
		$this->assertFalse($signature->verify(
			$this->request(['X-Signature' => $expected], self::BODY, 'https://example.com/index.php?webhook=other')
		));
	}

	public function testTheUrlAndSortedParametersCanBeSigned()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setAlgorithm('sha1');
		$signature->setEncoding('base64');
		$signature->setPayloadFormat('{url}{params}');

		$url = 'https://example.com/hook';
		// Sorted by name, each name immediately followed by its value.
		$expected = base64_encode(hash_hmac('sha1', $url . 'CallSidCA123From+15005550006', self::SECRET, true));

		$this->assertTrue($signature->verify($this->request(
			['X-Signature' => $expected],
			'',
			$url,
			['From' => '+15005550006', 'CallSid' => 'CA123']
		)));
	}

	public function testTheQueryStringIsSignedThroughTheUrlAndNotThroughTheParameters()
	{
		// Every inbound URL carries ?webhook=<id>, which the provider signed as part of the
		// URL and nowhere else. The parameters are the posted fields alone, so the service
		// parameter must not turn up a second time among them.
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setAlgorithm('sha1');
		$signature->setEncoding('base64');
		$signature->setPayloadFormat('{url}{params}');

		$url = 'https://example.com/index.php?webhook=twilio';
		$fields = ['From' => '+15005550006', 'CallSid' => 'CA123'];
		$expected = base64_encode(hash_hmac('sha1', $url . 'CallSidCA123From+15005550006', self::SECRET, true));

		$this->assertSame(['X-Signature' => $expected], $signature->sign($this->request([], '', $url, $fields)));
		$this->assertTrue($signature->verify($this->request(['X-Signature' => $expected], '', $url, $fields)));

		// What the merged view of the request would have produced is a forgery.
		$merged = base64_encode(hash_hmac('sha1', $url . 'CallSidCA123From+15005550006webhooktwilio', self::SECRET, true));
		$this->assertFalse($signature->verify($this->request(['X-Signature' => $merged], '', $url, $fields)));
	}

	public function testParametersAndHeadersCanBeSignedByName()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setPayloadFormat('{param:timestamp}{param:token}');

		$expected = hash_hmac('sha256', '1700000000nonce', self::SECRET);

		$this->assertTrue($signature->verify($this->request(
			['X-Signature' => $expected],
			'',
			'',
			['timestamp' => '1700000000', 'token' => 'nonce']
		)));
	}

	public function testAConstantAndTheBodyChecksumCanBeSigned()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setPayloadFormat('{header:X-Transmission-Id}|{const:WEBHOOK_ID}|{crc32}');
		$signature->setConstants('WEBHOOK_ID=WH-1234');

		$expected = hash_hmac('sha256', 'tx-9|WH-1234|' . crc32(self::BODY), self::SECRET);

		$this->assertTrue($signature->verify($this->request([
			'X-Transmission-Id' => 'tx-9',
			'X-Signature' => $expected,
		])));
	}

	public function testTheMethodCanBeSigned()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setPayloadFormat('{method}{body}');

		$expected = hash_hmac('sha256', 'POST' . self::BODY, self::SECRET);
		$this->assertTrue($signature->verify($this->request(['X-Signature' => $expected])));
	}

	public function testAQueryParameterCanBeSigned()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setPayloadFormat('{query:tenant}{body}');

		$expected = hash_hmac('sha256', '7' . self::BODY, self::SECRET);
		$this->assertTrue($signature->verify(
			$this->request(['X-Signature' => $expected], self::BODY, 'https://example.com/hook?tenant=7')
		));
	}

	public function testAnUnknownTokenIsAConfigurationError()
	{
		$signature = $this->keyed();
		$signature->setPayloadFormat('{nonsense}');

		$this->expectException(TConfigurationException::class);
		$this->expectExceptionMessage('{nonsense}');
		$signature->sign($this->request());
	}

	public function testATemplateWithNoTokenIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new THmacWebhookSignature())->setPayloadFormat('a fixed string');
	}

	// ── Binding the body when the payload does not include it ──────────────────

	public function testADigestInTheUrlBindsASignatureThatOnlySignsTheUrl()
	{
		// A provider that posts JSON but signs only the URL puts a digest of the body in
		// that URL. The signature covers the digest; this check covers the body.
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setHeader('X-Signature');
		$signature->setAlgorithm('sha1');
		$signature->setEncoding('base64');
		$signature->setPayloadFormat('{url}');
		$signature->setBodyHashName('bodySHA256');
		$signature->setBodyHashSource('query');

		$url = 'https://example.com/hook?bodySHA256=' . hash('sha256', self::BODY);
		$header = ['X-Signature' => base64_encode(hash_hmac('sha1', $url, self::SECRET, true))];

		$this->assertTrue($signature->verify($this->request($header, self::BODY, $url)));
		// Same signature, same URL, a different body: the digest no longer matches.
		$this->assertFalse($signature->verify($this->request($header, '{"action":"closed"}', $url)));
	}

	public function testAMissingBodyDigestIsRejectedWhenOneIsRequired()
	{
		$signature = $this->keyed();
		$signature->setBodyHashName('X-Body-Sha256');

		$this->assertFalse($signature->verify(
			$this->request(['X-Hub-Signature-256' => $this->keyedHeader(self::BODY)])
		));
	}

	public function testABodyDigestInTheSameSourceAsTheSignature()
	{
		$signature = $this->keyed();
		$signature->setBodyHashName('X-Body-Sha256');

		$this->assertSame(TWebhookSource::Header, $signature->getBodyHashSource());
		$this->assertTrue($signature->verify($this->request([
			'X-Hub-Signature-256' => $this->keyedHeader(self::BODY),
			'X-Body-Sha256' => hash('sha256', self::BODY),
		])));
	}

	public function testTheBodyDigestAlgorithmAndEncodingAreConfigurable()
	{
		$signature = $this->keyed();
		$signature->setBodyHashName('X-Body-Digest');
		$signature->setBodyHashAlgorithm('SHA512');
		$signature->setBodyHashEncoding('base64');

		$this->assertSame('sha512', $signature->getBodyHashAlgorithm());
		$this->assertTrue($signature->verify($this->request([
			'X-Hub-Signature-256' => $this->keyedHeader(self::BODY),
			'X-Body-Digest' => base64_encode(hash('sha512', self::BODY, true)),
		])));
	}

	public function testTheBodyDigestBindingClearsBackOff()
	{
		$signature = $this->keyed();
		$signature->setBodyHashName('X-Body-Sha256');
		$signature->setBodyHashName('');
		$signature->setBodyHashSource('');

		$this->assertNull($signature->getBodyHashName());
		$this->assertSame(TWebhookSource::Header, $signature->getBodyHashSource());
		$this->assertTrue($signature->verify(
			$this->request(['X-Hub-Signature-256' => $this->keyedHeader(self::BODY)])
		));
	}

	public function testAnUnknownBodyDigestAlgorithmIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new THmacWebhookSignature())->setBodyHashAlgorithm('rot13');
	}

	// ── Timestamps ─────────────────────────────────────────────────────────────

	private function timestamped(): THmacWebhookSignature
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setTimestampHeader('X-Webhook-Timestamp');
		$signature->setPayloadFormat('{timestamp}.{body}');
		$signature->setTolerance(300);

		return $signature;
	}

	public function testATimestampedSignatureRoundTrips()
	{
		$signature = $this->timestamped();
		$headers = $signature->sign($this->request());

		$this->assertArrayHasKey('X-Webhook-Timestamp', $headers);
		$this->assertTrue($signature->verify($this->request($headers)));
	}

	public function testATimestampOutsideToleranceIsRejected()
	{
		$stale = (string) (time() - 3600);
		$this->assertFalse($this->timestamped()->verify($this->request([
			'X-Webhook-Timestamp' => $stale,
			'X-Webhook-Signature' => hash_hmac('sha256', $stale . '.' . self::BODY, self::SECRET),
		])));
	}

	public function testATimestampInsideToleranceIsAccepted()
	{
		$recent = (string) (time() - 60);
		$this->assertTrue($this->timestamped()->verify($this->request([
			'X-Webhook-Timestamp' => $recent,
			'X-Webhook-Signature' => hash_hmac('sha256', $recent . '.' . self::BODY, self::SECRET),
		])));
	}

	public function testReplayingASignatureUnderANewTimestampFails()
	{
		// The whole point of binding the timestamp into the payload: moving the clock forward
		// on a captured request invalidates the signature that came with it.
		$signature = $this->timestamped();
		$captured = $signature->sign($this->request());
		$captured['X-Webhook-Timestamp'] = (string) (time() + 100);

		$this->assertFalse($signature->verify($this->request($captured)));
	}

	public function testAZeroToleranceAcceptsAnyTimestamp()
	{
		$signature = $this->timestamped();
		$signature->setTolerance(0);
		$ancient = '1000000000';

		$this->assertTrue($signature->verify($this->request([
			'X-Webhook-Timestamp' => $ancient,
			'X-Webhook-Signature' => hash_hmac('sha256', $ancient . '.' . self::BODY, self::SECRET),
		])));
	}

	public function testATimestampedSchemeNeedsItsTimestamp()
	{
		$this->assertFalse($this->timestamped()->verify($this->request([
			'X-Webhook-Signature' => hash_hmac('sha256', '.' . self::BODY, self::SECRET),
		])));
	}

	public function testANonNumericTimestampIsRejected()
	{
		$this->assertFalse($this->timestamped()->verify($this->request([
			'X-Webhook-Timestamp' => 'yesterday',
			'X-Webhook-Signature' => hash_hmac('sha256', 'yesterday.' . self::BODY, self::SECRET),
		])));
	}

	public function testAnIdIsMintedAndSignedWhenTheSchemeNamesOne()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setIdHeader('webhook-id');
		$signature->setTimestampHeader('webhook-timestamp');
		$signature->setPayloadFormat('{id}.{timestamp}.{body}');

		$headers = $signature->sign($this->request());

		$this->assertArrayHasKey('webhook-id', $headers);
		$this->assertArrayHasKey('webhook-timestamp', $headers);
		$this->assertTrue($signature->verify($this->request($headers)));
		// Another id against the same signature no longer verifies.
		$headers['webhook-id'] = 'msg_someone_elses';
		$this->assertFalse($signature->verify($this->request($headers)));
	}

	// ── Sources other than headers ─────────────────────────────────────────────

	public function testASignatureInARequestParameter()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setSource('parameter');
		$signature->setName('signature');
		$signature->setPayloadFormat('{param:timestamp}{param:token}');

		$expected = hash_hmac('sha256', '1700000000nonce', self::SECRET);

		$this->assertTrue($signature->verify($this->request([], '', '', [
			'timestamp' => '1700000000',
			'token' => 'nonce',
			'signature' => $expected,
		])));
		$this->assertSame(TWebhookSource::Parameter, $signature->getSource());
		$this->assertNull($signature->getHeader());
	}

	public function testASignatureInTheQueryString()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setSource('query');
		$signature->setName('sig');

		$expected = hash_hmac('sha256', self::BODY, self::SECRET);
		$this->assertTrue($signature->verify(
			$this->request([], self::BODY, 'https://example.com/hook?sig=' . $expected)
		));
	}

	// ── Configuration ──────────────────────────────────────────────────────────

	public function testDefaults()
	{
		$signature = new THmacWebhookSignature();

		$this->assertSame('sha256', $signature->getAlgorithm());
		$this->assertSame(THmacWebhookSignature::DEFAULT_HEADER, $signature->getName());
		$this->assertSame(TWebhookSource::Header, $signature->getSource());
		$this->assertSame('', $signature->getPrefix());
		$this->assertSame('', $signature->getSeparator());
		$this->assertSame(TWebhookEncoding::Hex, $signature->getEncoding());
		$this->assertSame(TWebhookEncoding::Raw, $signature->getSecretEncoding());
		$this->assertNull($signature->getTimestampName());
		$this->assertNull($signature->getIdName());
		$this->assertSame(300, $signature->getTolerance());
		$this->assertSame('{body}', $signature->getPayloadFormat());
		$this->assertSame([], $signature->getConstants());
	}

	public function testTheHeaderShorthandsReportBackWhileTheSourceIsHeaders()
	{
		$signature = $this->keyed();
		$signature->setTimestampHeader('X-Timestamp');
		$signature->setIdHeader('X-Delivery');
		$signature->setSecretPrefix('whsec_');
		$signature->setBodyHashEncoding('base64');

		$this->assertSame('X-Hub-Signature-256', $signature->getHeader());
		$this->assertSame('X-Timestamp', $signature->getTimestampHeader());
		$this->assertSame('X-Delivery', $signature->getIdHeader());
		$this->assertSame('whsec_', $signature->getSecretPrefix());
		$this->assertSame(TWebhookEncoding::Base64, $signature->getBodyHashEncoding());

		// Away from headers they report null, because there is no header to name.
		$signature->setSource('query');
		$this->assertNull($signature->getHeader());
		$this->assertNull($signature->getTimestampHeader());
		$this->assertNull($signature->getIdHeader());
	}

	public function testConstantsCanBeConfiguredAsText()
	{
		$signature = new THmacWebhookSignature();
		$signature->setConstants("WEBHOOK_ID=WH-1234\nTENANT=7");

		$this->assertSame(['WEBHOOK_ID' => 'WH-1234', 'TENANT' => '7'], $signature->getConstants());
	}

	public function testTimestampAndIdNamesClearBackToNull()
	{
		$signature = $this->timestamped();
		$signature->setTimestampHeader('');
		$signature->setIdHeader('');

		$this->assertNull($signature->getTimestampName());
		$this->assertNull($signature->getIdName());
		$this->assertSame(['X-Webhook-Signature'], array_keys($signature->sign($this->request())));
	}

	public function testAnUnkeyableAlgorithmIsRefused()
	{
		$this->expectException(TInvalidDataValueException::class);
		(new THmacWebhookSignature())->setAlgorithm('rot13');
	}

	public function testAnEmptyNameIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new THmacWebhookSignature())->setHeader('  ');
	}

	public function testSigningWithoutASecretIsAConfigurationError()
	{
		$this->expectException(TConfigurationException::class);
		(new THmacWebhookSignature())->sign($this->request());
	}

	public function testVerifyingWithoutASecretIsAConfigurationError()
	{
		// A verifier with no secret must not quietly answer false: that would be an endpoint
		// nobody can reach, reported as a stream of forged requests.
		$this->expectException(TConfigurationException::class);
		(new THmacWebhookSignature())->verify($this->request(['X-Webhook-Signature' => 'abc']));
	}

	public function testVerifyingWithoutASecretIsAConfigurationErrorEvenWhenNoHeaderIsPresented()
	{
		// The same, for a request carrying no signature at all: the configuration is what is
		// wrong, and it is wrong before the request is looked at.
		$this->expectException(TConfigurationException::class);
		(new THmacWebhookSignature())->verify($this->request());
	}

	public function testASecretThatWillNotDecodeIsAConfigurationErrorEvenWhenNoHeaderIsPresented()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('!!!not base64!!!');
		$signature->setSecretEncoding('base64');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request());
	}
}
