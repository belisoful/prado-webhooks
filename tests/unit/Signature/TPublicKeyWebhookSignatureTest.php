<?php

use Belisoful\Prado\Web\Webhooks\Signature\TPublicKeyWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookPadding;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\IO\HttpClient\THttpClient;
use Prado\IO\HttpClient\THttpClientException;
use Prado\Caching\ICache;
use Prado\IO\HttpClient\THttpClientResponse;

/**
 * A transport that answers certificate fetches from a script, and records what was asked.
 */
class TestCertificateHttpClient extends THttpClient
{
	public array $urls = [];
	public ?THttpClientResponse $response = null;
	public ?Throwable $failure = null;

	public function download(string $method, string $url, array $headers = [], ?string $body = null): THttpClientResponse
	{
		$this->urls[] = $url;
		if ($this->failure !== null) {
			throw $this->failure;
		}

		return $this->response ?? new THttpClientResponse(200);
	}
}

/**
 * The smallest cache that satisfies ICache, so the fetch-once behavior can be observed.
 */
class TestWebhookCache implements ICache
{
	public array $entries = [];
	public int $reads = 0;
	public int $writes = 0;

	public static function getIsAvailable(): bool
	{
		return true;
	}

	public function get($id)
	{
		$this->reads++;

		return $this->entries[$id] ?? false;
	}

	public function set($id, $value, $expire = 0, $dependency = null)
	{
		$this->writes++;
		$this->entries[$id] = $value;

		return true;
	}

	public function add($id, $value, $expire = 0, $dependency = null)
	{
		return isset($this->entries[$id]) ? false : $this->set($id, $value, $expire, $dependency);
	}

	public function delete($id)
	{
		unset($this->entries[$id]);

		return true;
	}

	public function flush()
	{
		$this->entries = [];

		return true;
	}
}

class TPublicKeyWebhookSignatureTest extends PHPUnit\Framework\TestCase
{
	private const BODY = '{"event_type":"PAYMENT.CAPTURE.COMPLETED"}';

	private static string $privateKey;
	private static string $publicKey;
	private static string $otherPublicKey;

	public static function setUpBeforeClass(): void
	{
		[self::$privateKey, self::$publicKey] = self::newKeyPair();
		self::$otherPublicKey = self::newKeyPair()[1];
	}

	/** @return array{0: string, 1: string} the PEM private key and its public key */
	private static function newKeyPair(): array
	{
		$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		openssl_pkey_export($key, $private);
		$public = openssl_pkey_get_details($key)['key'];

		return [$private, $public];
	}

	private function request(array $headers = [], string $body = self::BODY): TWebhookRequest
	{
		return new TWebhookRequest('POST', $body, $headers);
	}

	private function verifier(): TPublicKeyWebhookSignature
	{
		$signature = new TPublicKeyWebhookSignature();
		$signature->setPublicKey(self::$publicKey);
		$signature->setHeader('X-Signature');

		return $signature;
	}

	private function signer(): TPublicKeyWebhookSignature
	{
		$signature = $this->verifier();
		$signature->setPrivateKey(self::$privateKey);

		return $signature;
	}

	public function testSignsWhatItVerifies()
	{
		$signature = $this->signer();
		$headers = $signature->sign($this->request());

		$this->assertArrayHasKey('X-Signature', $headers);
		$this->assertTrue($signature->verify($this->request($headers)));
	}

	public function testAPublicKeyAloneVerifies()
	{
		// The usual arrangement: the application has no private key and does not need one.
		$headers = $this->signer()->sign($this->request());

		$this->assertTrue($this->verifier()->verify($this->request($headers)));
	}

	public function testAnotherKeysSignatureIsRejected()
	{
		$headers = $this->signer()->sign($this->request());
		$signature = $this->verifier();
		$signature->setPublicKey(self::$otherPublicKey);

		$this->assertFalse($signature->verify($this->request($headers)));
	}

	public function testAModifiedBodyIsRejected()
	{
		$headers = $this->signer()->sign($this->request());

		$this->assertFalse($this->verifier()->verify($this->request($headers, '{"event_type":"OTHER"}')));
	}

	public function testAMissingOrMalformedSignatureIsRejected()
	{
		$this->assertFalse($this->verifier()->verify($this->request()));
		$this->assertFalse($this->verifier()->verify($this->request(['X-Signature' => ''])));
		$this->assertFalse($this->verifier()->verify($this->request(['X-Signature' => 'not base64 !!'])));
	}

	public function testAKeyReadFromAFile()
	{
		$file = tempnam(sys_get_temp_dir(), 'pem');
		file_put_contents($file, self::$publicKey);

		$signature = $this->verifier();
		$signature->setPublicKey($file);
		$headers = $this->signer()->sign($this->request());

		$this->assertTrue($signature->verify($this->request($headers)));
		unlink($file);
	}

	public function testAPayloadTemplateOfSeveralRequestParts()
	{
		// The shape used by providers that sign a canonical string rather than the body.
		$format = '{header:X-Transmission-Id}|{header:X-Transmission-Time}|{const:WEBHOOK_ID}|{crc32}';
		$signer = $this->signer();
		$signer->setPayloadFormat($format);
		$signer->setConstants('WEBHOOK_ID=WH-1234');

		$request = $this->request(['X-Transmission-Id' => 'tx-9', 'X-Transmission-Time' => '2026-09-21T00:00:00Z']);
		$headers = $signer->sign($request);

		$verifier = $this->verifier();
		$verifier->setPayloadFormat($format);
		$verifier->setConstants(['WEBHOOK_ID' => 'WH-1234']);

		$this->assertTrue($verifier->verify($request->withHeaders(array_merge($request->getHeaders(), $headers))));

		// A different webhook id is a different signed string.
		$verifier->setConstants('WEBHOOK_ID=WH-9999');
		$this->assertFalse($verifier->verify($request->withHeaders(array_merge($request->getHeaders(), $headers))));
	}

	// ── PSS padding ────────────────────────────────────────────────────────────

	/**
	 * @dataProvider pssDigests
	 * @param string $digest
	 * @param int $salt
	 */
	public function testPssRoundTripsAtEveryDigest(string $digest, int $salt)
	{
		$signer = $this->signer();
		$signer->setPadding('pss');
		$signer->setAlgorithm($digest);

		$verifier = $this->verifier();
		$verifier->setPadding('pss');
		$verifier->setAlgorithm($digest);

		$this->assertSame($salt, $verifier->getSaltLength());
		$signed = $this->request($signer->sign($this->request()));
		$this->assertTrue($verifier->verify($signed));
		$this->assertFalse($verifier->verify($this->request($signed->getHeaders(), 'a different body')));
	}

	public static function pssDigests(): array
	{
		return [['sha256', 32], ['sha384', 48], ['sha512', 64]];
	}

	public function testAPssSignatureIsCheckedByOpenSslItself()
	{
		// Cross-implementation, because our own round trip would only prove self-consistency:
		// this signature was produced by the openssl command line.
		$signer = $this->signer();
		$signer->setPadding('pss');
		$signer->setAlgorithm('sha512');
		$signature = base64_decode($signer->sign($this->request())['X-Signature'], true);

		$key = tempnam(sys_get_temp_dir(), 'pub');
		$signatureFile = tempnam(sys_get_temp_dir(), 'sig');
		$message = tempnam(sys_get_temp_dir(), 'msg');
		file_put_contents($key, self::$publicKey);
		file_put_contents($signatureFile, $signature);
		file_put_contents($message, self::BODY);

		exec(sprintf(
			'openssl dgst -sha512 -verify %s -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 '
				. '-signature %s %s 2>&1',
			escapeshellarg($key),
			escapeshellarg($signatureFile),
			escapeshellarg($message)
		), $output, $status);
		array_map('unlink', [$key, $signatureFile, $message]);

		if ($status === 127) {
			$this->markTestSkipped('the openssl command line is not available');
		}
		$this->assertSame('Verified OK', trim(implode(' ', $output)));
	}

	public function testThePaddingsAreNotInterchangeable()
	{
		// Neither is detectable from the signature, so a provider that sends one against the
		// other fails exactly as a wrong key would. Stated as a test so the failure mode is
		// on the record.
		$pss = $this->signer();
		$pss->setPadding('pss');

		$pkcs1 = $this->verifier();
		$this->assertSame(TWebhookPadding::Pkcs1, $pkcs1->getPadding());
		$this->assertFalse($pkcs1->verify($this->request($pss->sign($this->request()))));

		$pssVerifier = $this->verifier();
		$pssVerifier->setPadding('pss');
		$this->assertFalse($pssVerifier->verify($this->request($this->signer()->sign($this->request()))));
	}

	public function testAPssSaltLengthMismatchRefusesEveryDelivery()
	{
		$signer = $this->signer();
		$signer->setPadding('pss');
		$signed = $this->request($signer->sign($this->request()));

		$verifier = $this->verifier();
		$verifier->setPadding('pss');
		$this->assertTrue($verifier->verify($signed));

		$verifier->setSaltLength(48);
		$this->assertSame(48, $verifier->getSaltLength());
		$this->assertFalse($verifier->verify($signed));
	}

	public function testAnExplicitSaltLengthRoundTrips()
	{
		$signer = $this->signer();
		$signer->setPadding('pss');
		$signer->setSaltLength(20);

		$verifier = $this->verifier();
		$verifier->setPadding('pss');
		$verifier->setSaltLength(20);

		$this->assertTrue($verifier->verify($this->request($signer->sign($this->request()))));
	}

	public function testASaltLengthOfZeroFollowsTheDigest()
	{
		$verifier = $this->verifier();
		$verifier->setSaltLength(-5);

		$this->assertSame(32, $verifier->getSaltLength());
		$verifier->setAlgorithm('sha384');
		$this->assertSame(48, $verifier->getSaltLength());
	}

	public function testAPssKeyMayBeAPkcs1PrivateKeyOrACertificate()
	{
		// The key is normalized through OpenSSL before it is rewritten, so whatever shape the
		// provider published arrives here.
		$traditional = tempnam(sys_get_temp_dir(), 'rsa');
		exec('openssl genrsa -traditional -out ' . escapeshellarg($traditional) . ' 2048 2>/dev/null', $ignored, $status);
		if ($status !== 0) {
			unlink($traditional);
			$this->markTestSkipped('the openssl command line is not available');
		}
		$certificate = tempnam(sys_get_temp_dir(), 'crt');
		exec(sprintf(
			'openssl req -x509 -new -key %s -subj /CN=test -days 1 -out %s 2>/dev/null',
			escapeshellarg($traditional),
			escapeshellarg($certificate)
		));

		$signer = new TPublicKeyWebhookSignature();
		$signer->setHeader('X-Signature');
		$signer->setPadding('pss');
		$signer->setPrivateKey((string) file_get_contents($traditional));

		$verifier = new TPublicKeyWebhookSignature();
		$verifier->setHeader('X-Signature');
		$verifier->setPadding('pss');
		$verifier->setPublicKey((string) file_get_contents($certificate));

		$this->assertTrue($verifier->verify($this->request($signer->sign($this->request()))));
		array_map('unlink', [$traditional, $certificate]);
	}

	public function testALargePssSaltLengthIsEncodedAsAPositiveInteger()
	{
		// A salt of 128 or more has its high bit set, and used to encode as a negative DER
		// integer, which is not a salt length any reader would accept.
		$signer = $this->signer();
		$signer->setPadding('pss');
		$signer->setAlgorithm('sha512');
		$signer->setSaltLength(128);

		$verifier = $this->verifier();
		$verifier->setPadding('pss');
		$verifier->setAlgorithm('sha512');
		$verifier->setSaltLength(128);

		$this->assertTrue($verifier->verify($this->request($signer->sign($this->request()))));
	}

	public function testAKeyThatIsNotAKeyAtAllIsRefusedUnderPss()
	{
		foreach (['', 'not a key', '-----BEGIN PUBLIC KEY-----\nZ m9v\n-----END PUBLIC KEY-----'] as $material) {
			$signature = new TPublicKeyWebhookSignature();
			$signature->setHeader('X-Signature');
			$signature->setPadding('pss');
			$signature->setPublicKey($material === '' ? 'x' : $material);

			try {
				$signature->verify($this->request(['X-Signature' => 'abc']));
				$this->fail('a key that will not parse should be refused');
			} catch (TConfigurationException $e) {
				$this->assertNotSame('', $e->getMessage());
			}
		}
	}

	public function testABodyDigestBindingAppliesHereToo()
	{
		$signer = $this->signer();
		$signer->setPayloadFormat('{url}');
		$signer->setBodyHashName('X-Body-Sha256');

		$verifier = $this->verifier();
		$verifier->setPayloadFormat('{url}');
		$verifier->setBodyHashName('X-Body-Sha256');

		$request = new TWebhookRequest('POST', self::BODY, [], 'https://example.com/hook');
		$headers = $signer->sign($request) + ['X-Body-Sha256' => hash('sha256', self::BODY)];

		$this->assertTrue($verifier->verify($request->withHeaders($headers)));
		// The URL and signature are unchanged; only the body is not the one digested.
		$this->assertFalse($verifier->verify($request->withHeaders($headers)->withBody('another body')));
	}

	public function testSigningRefusesAPrivateKeyThatWillNotParse()
	{
		$signature = new TPublicKeyWebhookSignature();
		$signature->setHeader('X-Signature');
		$signature->setPrivateKey("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----");

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testSigningRefusesAKeyTooSmallForTheDigest()
	{
		// A 512-bit modulus cannot hold a PKCS#1 v1.5 SHA-512 signature: the padded digest
		// is wider than the key, and openssl_sign refuses rather than truncating.
		$key = @openssl_pkey_new(['private_key_bits' => 512, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		if ($key === false) {
			$this->markTestSkipped('this OpenSSL will not generate a 512-bit key');
		}
		openssl_pkey_export($key, $private);

		$signature = new TPublicKeyWebhookSignature();
		$signature->setHeader('X-Signature');
		$signature->setAlgorithm('sha512');
		$signature->setPrivateKey((string) $private);

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testTheKeysAreReadableBack()
	{
		$signature = $this->signer();

		$this->assertSame(self::$publicKey, $signature->getPublicKey());
		$this->assertSame(self::$privateKey, $signature->getPrivateKey());
	}

	public function testAnEcKeyCannotBeUsedWithPss()
	{
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
		$signature = new TPublicKeyWebhookSignature();
		$signature->setHeader('X-Signature');
		$signature->setPadding('pss');
		$signature->setPublicKey(openssl_pkey_get_details($key)['key']);

		$this->expectException(TConfigurationException::class);
		$this->expectExceptionMessage('PSS');
		$signature->verify($this->request(['X-Signature' => 'abc']));
	}

	public function testARewrittenKeyIsReusedRatherThanRebuilt()
	{
		$verifier = $this->verifier();
		$verifier->setPadding('pss');
		$signer = $this->signer();
		$signer->setPadding('pss');

		$signed = $this->request($signer->sign($this->request()));
		$this->assertTrue($verifier->verify($signed));
		$this->assertTrue($verifier->verify($signed));
	}

	// ── Certificates named by the request ──────────────────────────────────────

	private function certificateVerifier(TestCertificateHttpClient $client): TPublicKeyWebhookSignature
	{
		$signature = new TPublicKeyWebhookSignature();
		$signature->setHeader('X-Signature');
		$signature->setCertificateUrlName('X-Cert-Url');
		$signature->setCertificateUrlPattern('#^https://certs\.example\.com/#');
		$signature->setHttpClient($client);

		return $signature;
	}

	public function testACertificateNamedByTheRequestIsFetchedAndUsed()
	{
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(200, [], self::$publicKey);
		$signature = $this->certificateVerifier($client);

		$headers = $this->signer()->sign($this->request());
		$headers['X-Cert-Url'] = 'https://certs.example.com/key.pem';

		$this->assertTrue($signature->verify($this->request($headers)));
		$this->assertSame(['https://certs.example.com/key.pem'], $client->urls);
	}

	public function testACertificateUrlOutsideTheAllowListIsNeverFetched()
	{
		// The server-side request forgery this guard exists for.
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(200, [], self::$publicKey);
		$signature = $this->certificateVerifier($client);

		$headers = $this->signer()->sign($this->request());
		$headers['X-Cert-Url'] = 'https://attacker.example.net/key.pem';

		$this->assertFalse($signature->verify($this->request($headers)));
		$this->assertSame([], $client->urls);
	}

	public function testACertificateUrlIsRefusedOutrightWithoutAnAllowList()
	{
		$client = new TestCertificateHttpClient();
		$signature = $this->certificateVerifier($client);
		$signature->setCertificateUrlPattern('');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request(['X-Cert-Url' => 'https://certs.example.com/key.pem']));
	}

	public function testAFetchThatFailsRefusesTheDeliveryRatherThanThrowing()
	{
		$client = new TestCertificateHttpClient();
		$client->failure = new THttpClientException('Connection refused');
		$signature = $this->certificateVerifier($client);

		$headers = $this->signer()->sign($this->request());
		$headers['X-Cert-Url'] = 'https://certs.example.com/key.pem';

		$this->assertFalse($signature->verify($this->request($headers)));
	}

	public function testAFetchedThingThatIsNotAKeyRefusesTheDelivery()
	{
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(200, [], 'not a certificate');
		$signature = $this->certificateVerifier($client);

		$headers = $this->signer()->sign($this->request());
		$headers['X-Cert-Url'] = 'https://certs.example.com/key.pem';

		$this->assertFalse($signature->verify($this->request($headers)));
	}

	public function testANotFoundCertificateRefusesTheDelivery()
	{
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(404, [], '');
		$signature = $this->certificateVerifier($client);

		$this->assertFalse($signature->verify($this->request(['X-Cert-Url' => 'https://certs.example.com/key.pem'])));
	}

	public function testAFetchedCertificateIsCachedAndNotFetchedAgain()
	{
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(200, [], self::$publicKey);
		$cache = new TestWebhookCache();

		$headers = $this->signer()->sign($this->request());
		$headers['X-Cert-Url'] = 'https://certs.example.com/key.pem';

		// A fresh verifier each time, so the trait's own memo cannot be what is doing it.
		foreach ([1, 2, 3] as $ignored) {
			$signature = $this->certificateVerifier($client);
			$signature->setCache($cache);
			$this->assertTrue($signature->verify($this->request($headers)));
		}

		$this->assertCount(1, $client->urls, 'the certificate is fetched once');
		$this->assertSame(1, $cache->writes);
		$this->assertGreaterThanOrEqual(3, $cache->reads);
	}

	public function testTheCacheTtlIsHonouredAsConfigured()
	{
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(200, [], self::$publicKey);
		$signature = $this->certificateVerifier($client);
		$signature->setCacheTtl(60);
		$cache = new TestWebhookCache();
		$signature->setCache($cache);

		$headers = $this->signer()->sign($this->request());
		$headers['X-Cert-Url'] = 'https://certs.example.com/key.pem';
		$signature->verify($this->request($headers));

		$this->assertSame(60, $signature->getCacheTtl());
		$this->assertSame([self::$publicKey], array_values($cache->entries));
	}

	public function testARequestNamingNoCertificateIsRefused()
	{
		$client = new TestCertificateHttpClient();

		$this->assertFalse($this->certificateVerifier($client)->verify($this->request(['X-Signature' => 'abc'])));
		$this->assertSame([], $client->urls);
	}

	public function testARequestPresentingNoSignatureNeverFetchesTheCertificate()
	{
		// The cheapest thing an attacker can send must not cost a network round trip: the
		// presented signature is checked for before the URL it names is ever fetched.
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(200, [], self::$publicKey);
		$signature = $this->certificateVerifier($client);

		$this->assertFalse($signature->verify($this->request(['X-Cert-Url' => 'https://certs.example.com/key.pem'])));
		$this->assertFalse($signature->verify($this->request([
			'X-Cert-Url' => 'https://certs.example.com/key.pem',
			'X-Signature' => '',
		])));
		$this->assertSame([], $client->urls);
	}

	public function testAConfiguredKeyStillFailsAsConfigurationWhenNothingIsPresented()
	{
		// Reordering the checks must not turn a broken configuration into a quiet false.
		$signature = new TPublicKeyWebhookSignature();
		$signature->setHeader('X-Signature');
		$signature->setPublicKey('-----BEGIN PUBLIC KEY----- nonsense -----END PUBLIC KEY-----');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request());
	}

	public function testNoKeyAndNoAllowListIsConfigurationEvenWhenNothingIsPresented()
	{
		$signature = new TPublicKeyWebhookSignature();
		$signature->setHeader('X-Signature');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request());
	}

	public function testAFetchedBodyThatIsNotAKeyIsNotCached()
	{
		// Caching a non-key would refuse every delivery until it expired, and would let one
		// bad response from the provider's host outlive itself.
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(200, [], 'not a certificate');
		$cache = new TestWebhookCache();
		$signature = $this->certificateVerifier($client);
		$signature->setCache($cache);

		$headers = $this->signer()->sign($this->request());
		$headers['X-Cert-Url'] = 'https://certs.example.com/key.pem';

		$this->assertFalse($signature->verify($this->request($headers)));
		$this->assertSame(0, $cache->writes);
		$this->assertSame([], $cache->entries);

		// Once the host serves the key, it is used and cached.
		$client->response = new THttpClientResponse(200, [], self::$publicKey);
		$this->assertTrue($signature->verify($this->request($headers)));
		$this->assertSame(1, $cache->writes);
		$this->assertCount(2, $client->urls);
	}

	public function testAnOversizedCertificateBodyIsRefusedAndNotCached()
	{
		$client = new TestCertificateHttpClient();
		$client->response = new THttpClientResponse(200, [], self::$publicKey);
		$cache = new TestWebhookCache();
		$signature = $this->certificateVerifier($client);
		$signature->setCache($cache);
		$signature->setCertificateMaxSize(strlen(self::$publicKey) - 1);

		$headers = $this->signer()->sign($this->request());
		$headers['X-Cert-Url'] = 'https://certs.example.com/key.pem';

		$this->assertFalse($signature->verify($this->request($headers)));
		$this->assertSame(0, $cache->writes);

		// Exactly the size is fine: the limit is inclusive.
		$signature->setCertificateMaxSize(strlen(self::$publicKey));
		$this->assertTrue($signature->verify($this->request($headers)));
		$this->assertSame(1, $cache->writes);
	}

	public function testTheCertificateMaxSizeHasAFloorOfOne()
	{
		$signature = new TPublicKeyWebhookSignature();
		$this->assertSame(TPublicKeyWebhookSignature::DEFAULT_CERTIFICATE_MAX_SIZE, $signature->getCertificateMaxSize());
		$this->assertSame(65536, $signature->getCertificateMaxSize());

		$signature->setCertificateMaxSize('4096');
		$this->assertSame(4096, $signature->getCertificateMaxSize());

		foreach ([0, -1, '-500'] as $value) {
			$signature->setCertificateMaxSize($value);
			$this->assertSame(1, $signature->getCertificateMaxSize(), (string) $value);
		}
	}

	public function testAValueWithoutTheConfiguredPrefixIsNotACandidate()
	{
		// Consistent with the keyed schemes: the prefix names the scheme, and a value under
		// no prefix, or another one, is not this scheme's signature however it decodes.
		$signer = $this->signer();
		$headers = $signer->sign($this->request());
		$bare = $headers['X-Signature'];

		$verifier = $this->verifier();
		$verifier->setPrefix('rsa-sha256=');

		$this->assertTrue($verifier->verify($this->request(['X-Signature' => 'rsa-sha256=' . $bare])));
		$this->assertFalse($verifier->verify($this->request(['X-Signature' => $bare])));
		$this->assertFalse($verifier->verify($this->request(['X-Signature' => 'sha256=' . $bare])));
		$this->assertFalse($verifier->verify($this->request(['X-Signature' => 'RSA-SHA256=' . $bare])));
	}

	public function testAmongSeveralCandidatesOnlyThePrefixedOnesCount()
	{
		$signer = $this->signer();
		$bare = $signer->sign($this->request())['X-Signature'];

		$verifier = $this->verifier();
		$verifier->setPrefix('v1=');
		$verifier->setSeparator(',');

		$this->assertTrue($verifier->verify($this->request(['X-Signature' => 'v0=' . $bare . ',v1=' . $bare])));
		$this->assertFalse($verifier->verify($this->request(['X-Signature' => 'v0=' . $bare . ',' . $bare])));
	}

	public function testAPssDigestOpenSslKnowsButHashDoesNotIsAConfigurationError()
	{
		// setAlgorithm accepts what OpenSSL can sign with, which is a longer list than PSS
		// parameters can name; it used to surface as a ValueError from hash().
		$candidates = array_values(array_diff(array_map('strtolower', openssl_get_md_methods()), hash_algos()));
		if ($candidates === []) {
			$this->markTestSkipped('every OpenSSL digest here is one hash() knows');
		}
		$signature = $this->verifier();
		$signature->setPadding('pss');
		$signature->setAlgorithm($candidates[0]);

		try {
			$signature->getSaltLength();
			$this->fail('the salt length should be refused');
		} catch (TConfigurationException $e) {
			$this->assertStringContainsString('PSS', $e->getMessage());
		}

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request(['X-Signature' => 'abc']));
	}

	public function testAPssDigestWithNoParametersIsAConfigurationError()
	{
		// hash() knows sha1, but a PSS key names its hash by identifier and this package
		// carries only the SHA-2 family, so it is refused as configuration rather than as
		// an unreadable key.
		$signer = $this->signer();
		$signer->setPadding('pss');
		$signer->setAlgorithm('sha1');

		try {
			$signer->sign($this->request());
			$this->fail('signing should be refused');
		} catch (TConfigurationException $e) {
			$this->assertStringContainsString('sha1', $e->getMessage());
		}

		$verifier = $this->verifier();
		$verifier->setPadding('pss');
		$verifier->setAlgorithm('sha1');
		$this->expectException(TConfigurationException::class);
		$verifier->verify($this->request(['X-Signature' => 'abc']));
	}

	public function testAnExplicitSaltLengthDoesNotNeedTheDigestLength()
	{
		$candidates = array_values(array_diff(array_map('strtolower', openssl_get_md_methods()), hash_algos()));
		if ($candidates === []) {
			$this->markTestSkipped('every OpenSSL digest here is one hash() knows');
		}
		$signature = new TPublicKeyWebhookSignature();
		$signature->setAlgorithm($candidates[0]);
		$signature->setSaltLength(32);

		$this->assertSame(32, $signature->getSaltLength());
	}

	// ── Configuration ──────────────────────────────────────────────────────────

	public function testDefaults()
	{
		$signature = new TPublicKeyWebhookSignature();

		$this->assertSame('sha256', $signature->getAlgorithm());
		$this->assertSame('base64', $signature->getEncoding()->value);
		$this->assertNull($signature->getCertificateUrlName());
		$this->assertNull($signature->getCertificateUrlPattern());
		$this->assertSame(TPublicKeyWebhookSignature::DEFAULT_CACHE_TTL, $signature->getCacheTtl());
	}

	public function testTheDefaultTransportIsBuiltOnDemand()
	{
		$signature = new TPublicKeyWebhookSignature();
		$client = $signature->getHttpClient();

		$this->assertInstanceOf(THttpClient::class, $client);
		$this->assertFalse($client->getFollowRedirects());
	}

	public function testPropertiesRoundTrip()
	{
		$signature = new TPublicKeyWebhookSignature();
		$signature->setAlgorithm('SHA512');
		$signature->setCertificateUrlName(' X-Cert-Url ');
		$signature->setCacheTtl(-5);
		$signature->setCache(null);

		$this->assertSame('sha512', $signature->getAlgorithm());
		$this->assertSame('X-Cert-Url', $signature->getCertificateUrlName());
		$this->assertSame(0, $signature->getCacheTtl());
		$this->assertNull($signature->getCache());

		$signature->setCertificateUrlName('');
		$this->assertNull($signature->getCertificateUrlName());
	}

	public function testATimestampedAsymmetricSchemeRoundTripsAndExpires()
	{
		$signer = $this->signer();
		$signer->setTimestampHeader('X-Timestamp');
		$signer->setPayloadFormat('{timestamp}.{body}');

		$verifier = $this->verifier();
		$verifier->setTimestampHeader('X-Timestamp');
		$verifier->setPayloadFormat('{timestamp}.{body}');

		$headers = $signer->sign($this->request());
		$this->assertTrue($verifier->verify($this->request($headers)));

		$headers['X-Timestamp'] = (string) (time() - 3600);
		$this->assertFalse($verifier->verify($this->request($headers)));
	}

	public function testASignaturePrefixIsStrippedBeforeDecoding()
	{
		$signer = $this->signer();
		$signer->setPrefix('rsa-sha256=');
		$verifier = $this->verifier();
		$verifier->setPrefix('rsa-sha256=');

		$headers = $signer->sign($this->request());

		$this->assertStringStartsWith('rsa-sha256=', $headers['X-Signature']);
		$this->assertTrue($verifier->verify($this->request($headers)));
	}

	public function testAnUnusablePatternIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TPublicKeyWebhookSignature())->setCertificateUrlPattern('#unterminated');
	}

	public function testAnUnknownDigestIsRefused()
	{
		$this->expectException(TInvalidDataValueException::class);
		(new TPublicKeyWebhookSignature())->setAlgorithm('rot13');
	}

	public function testVerifyingWithNoKeyAtAllIsAConfigurationError()
	{
		$signature = new TPublicKeyWebhookSignature();
		$signature->setHeader('X-Signature');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request(['X-Signature' => 'abc']));
	}

	public function testSigningWithoutAPrivateKeyIsAConfigurationError()
	{
		$this->expectException(TConfigurationException::class);
		$this->verifier()->sign($this->request());
	}

	public function testAKeyThatWillNotParseIsAConfigurationError()
	{
		$signature = new TPublicKeyWebhookSignature();
		$signature->setHeader('X-Signature');
		$signature->setPublicKey('-----BEGIN PUBLIC KEY----- nonsense -----END PUBLIC KEY-----');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request(['X-Signature' => 'abc']));
	}

	public function testAVerifierWithNothingToVerifyAgainstThrowsForARequestMissingTheBodyHash()
	{
		// It returned false for a request without the body-hash header and threw only for
		// one carrying it, so a misconfigured endpoint saw a stream of forgeries for probes
		// and an error page for the real provider.
		$verifier = new TPublicKeyWebhookSignature();
		$verifier->setHeader('X-Signature');
		$verifier->setBodyHashName('X-Body-Sha256');

		$this->expectException(TConfigurationException::class);
		$verifier->verify($this->request(['X-Signature' => 'abc']));
	}

	public function testAVerifierWithNothingToVerifyAgainstThrowsForARequestMissingTheTimestamp()
	{
		$verifier = new TPublicKeyWebhookSignature();
		$verifier->setHeader('X-Signature');
		$verifier->setTimestampName('X-Timestamp');

		$this->expectException(TConfigurationException::class);
		$verifier->verify($this->request(['X-Signature' => 'abc']));
	}
}
