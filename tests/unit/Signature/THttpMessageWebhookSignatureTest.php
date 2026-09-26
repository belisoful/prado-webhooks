<?php

use Belisoful\Prado\Web\Webhooks\Signature\THttpMessageWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;

class THttpMessageWebhookSignatureTest extends PHPUnit\Framework\TestCase
{
	private const SECRET = 'a shared signing secret';
	private const BODY = '{"hello": "world"}';
	private const URL = 'https://example.com/index.php?webhook=provider';

	/** The fixture for {@see testAPssSignatureOpenSslMadeEarlierStillVerifies}. */
	private const KNOWN_ANSWER_KEY = <<<'PEM'
		-----BEGIN PUBLIC KEY-----
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0nVeprlV0WgP67i2YUDE
		edoqZLdds3TGYyvb41+37ty3NkW0JMJ1ZyRrgXPYe4fkKKEpCoEsWnQ+6GhwynQI
		m/GlwyyCSDWRpj+UgNcogoXaWr7BllU9j0dCZus2sc7f1ND/kSHoGPR9l5kC5VHu
		64QqsL5/ZPF6LcCetpkWEDffs/44+eDsVzBV5XPKlTPfDk4iQEpoKb7VocaZ8jv4
		HL2Fe3bccB6KGk3MzhQNzTdrMh8WiSMVdTAJjzvXl1VR6IVd6cpS/noO7qXzjZq2
		42Xu7rs9ZEWXYlk4SeKmYgggl9CMy0raZLo8UALEMlso7z37DAJ5WNv1JWWxjWUG
		kQIDAQAB
		-----END PUBLIC KEY-----
		PEM;

	private const KNOWN_ANSWER_SIGNATURE = 'HIQlYgCUgauXvVHamq0hlaXsBPXBkI5GiWeICRMS6WXp3g7BArme0a9mNT9y/qMv'
		. 'UGL6EKPYehS/kGeBh0j9XBD2EdE6EiMVJNRER/1VYan8rhX24BXAMBZAv83gKTKrURgb6BAxHt3WQJsavm8GtN7d5dTNFCw2'
		. '1bQVia8NTpN0ln860t27nrXbzy8cGDc7vbKbkKab8qlPsALod0zQ4dmY56dqmyJYoDD9AB9XQIrwWZJTg6XJu05SdgIVD+pe'
		. '+76y2giOP4W/kq84q8cMz9CrhAWva/7HXpsZmQLMXbhiE7z20ku3ByPnnSveY8iJvdpJGWAQQGlqTjqon0q54g==';

	private static array $rsa;
	private static array $p256;
	private static array $p384;

	public static function setUpBeforeClass(): void
	{
		self::$rsa = self::newKeyPair(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		self::$p256 = self::newKeyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
		self::$p384 = self::newKeyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
	}

	/** @return array{private: string, public: string} */
	private static function newKeyPair(array $options): array
	{
		$key = openssl_pkey_new($options);
		openssl_pkey_export($key, $private);

		return ['private' => (string) $private, 'public' => openssl_pkey_get_details($key)['key']];
	}

	private function request(array $headers = [], string $body = self::BODY, string $method = 'POST'): TWebhookRequest
	{
		return new TWebhookRequest($method, $body, $headers, self::URL);
	}

	private function hmac(): THttpMessageWebhookSignature
	{
		$signature = new THttpMessageWebhookSignature();
		$signature->setSecret(self::SECRET);
		$signature->setKeyId('prado');

		return $signature;
	}

	/** Signs a request and folds the headers back into it, as a sender would. */
	private function signed(THttpMessageWebhookSignature $signature, ?TWebhookRequest $request = null): TWebhookRequest
	{
		$request ??= $this->request();
		$headers = $signature->sign($request);

		return $request->withHeaders(array_merge($request->getHeaders(), $headers));
	}

	public function testSignsWhatItVerifies()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);

		$this->assertTrue($signature->verify($signed));
	}

	public function testTheSignedHeadersHaveTheShapeTheSpecDescribes()
	{
		$headers = $this->hmac()->sign($this->request());

		$this->assertMatchesRegularExpression(
			'/^sig1=\("@method" "@target-uri" "content-digest"\);created=\d+;keyid="prado";alg="hmac-sha256"$/',
			$headers['Signature-Input']
		);
		$this->assertMatchesRegularExpression('/^sig1=:[A-Za-z0-9+\/=]+:$/', $headers['Signature']);
		$this->assertMatchesRegularExpression('/^sha-256=:[A-Za-z0-9+\/=]+:$/', $headers['Content-Digest']);
	}

	public function testTheContentDigestIsOfTheBody()
	{
		$headers = $this->hmac()->sign($this->request());

		$this->assertSame(
			'sha-256=:' . base64_encode(hash('sha256', self::BODY, true)) . ':',
			$headers['Content-Digest']
		);
	}

	public function testAModifiedBodyIsRejected()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);

		$this->assertFalse($signature->verify($signed->withBody('{"hello": "moon"}')));
	}

	public function testAModifiedDigestIsRejected()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();
		$headers['Content-Digest'] = 'sha-256=:' . base64_encode(hash('sha256', 'something else', true)) . ':';

		$this->assertFalse($signature->verify($signed->withHeaders($headers)));
	}

	public function testAModifiedMethodOrUrlIsRejected()
	{
		$signature = $this->hmac();
		$request = $this->request();
		$signed = $this->signed($signature, $request);

		$moved = new TWebhookRequest('PUT', self::BODY, $signed->getHeaders(), self::URL);
		$this->assertFalse($signature->verify($moved));

		$elsewhere = new TWebhookRequest('POST', self::BODY, $signed->getHeaders(), 'https://example.com/other');
		$this->assertFalse($signature->verify($elsewhere));
	}

	public function testAnEditedComponentListBreaksItsOwnSignature()
	{
		// @signature-params is part of the base, so the list cannot be rewritten in place.
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();
		$headers['Signature-Input'] = str_replace('"@target-uri" ', '', $headers['Signature-Input']);

		$this->assertFalse($signature->verify($signed->withHeaders($headers)));
	}

	public function testASignatureThatCoversTooLittleIsRefused()
	{
		// The security of the scheme: the message chooses what it signs, the application
		// chooses what that has to include.
		$narrow = new THttpMessageWebhookSignature();
		$narrow->setSecret(self::SECRET);
		$narrow->setKeyId('prado');
		$narrow->setRequiredComponents('@method');

		$signed = $this->signed($narrow);

		// The narrow signer is happy with its own work...
		$this->assertTrue($narrow->verify($signed));
		// ...and the endpoint that requires more is not.
		$this->assertFalse($this->hmac()->verify($signed));
	}

	public function testAMissingSignatureOrInputIsRejected()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);

		$headers = $signed->getHeaders();
		unset($headers['Signature']);
		$this->assertFalse($signature->verify($signed->withHeaders($headers)));

		$headers = $signed->getHeaders();
		unset($headers['Signature-Input']);
		$this->assertFalse($signature->verify($signed->withHeaders($headers)));

		$this->assertFalse($signature->verify($this->request()));
	}

	public function testMalformedHeadersAreRejectedRatherThanThrowing()
	{
		$signature = $this->hmac();
		foreach ([
			['Signature-Input' => 'sig1=nonsense', 'Signature' => 'sig1=:abc:'],
			['Signature-Input' => 'sig1=("@method")', 'Signature' => 'sig1=notabytesequence'],
			['Signature-Input' => '=("@method")', 'Signature' => 'sig1=:abc:'],
			['Signature-Input' => 'sig1=("@method");created=x', 'Signature' => 'sig1=:abc:'],
		] as $headers) {
			$this->assertFalse($signature->verify($this->request($headers)), (string) json_encode($headers));
		}
	}

	public function testALabelThatHasNoSignatureIsSkipped()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();
		$headers['Signature-Input'] = $headers['Signature-Input'] . ', sig2=("@method");created=' . time();

		$this->assertTrue($signature->verify($signed->withHeaders($headers)));
	}

	public function testOnlyTheConfiguredLabelIsRead()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);

		$signature->setLabel('sig2');
		$this->assertFalse($signature->verify($signed));

		$signature->setLabel('sig1');
		$this->assertTrue($signature->verify($signed));

		$signature->setLabel('');
		$this->assertNull($signature->getLabel());
		$this->assertTrue($signature->verify($signed));
	}

	public function testAnAlgorithmOutsideTheAllowListIsRejected()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();
		$headers['Signature-Input'] = str_replace('hmac-sha256', 'hmac-sha512', $headers['Signature-Input']);

		$this->assertFalse($signature->verify($signed->withHeaders($headers)));
	}

	public function testAMessageNamingNoAlgorithmIsAcceptedOnlyWhenOneIsConfigured()
	{
		// Built by hand rather than by sign(), both because the class always names its
		// algorithm and because a signature it did not make is the better thing to check.
		$request = $this->request($this->headersWithoutAlgorithm());
		$signature = $this->hmac();

		$this->assertTrue($signature->verify($request));

		// With two configured there is no telling which was meant.
		$signature->setAlgorithms('hmac-sha256, hmac-sha512');
		$this->assertFalse($signature->verify($request));
	}

	/**
	 * Assembles a signature base the way RFC 9421 describes it, with no `alg` parameter.
	 * @return array<string, string> the three headers a signed request carries.
	 */
	private function headersWithoutAlgorithm(): array
	{
		$digest = 'sha-256=:' . base64_encode(hash('sha256', self::BODY, true)) . ':';
		$input = '("@method" "@target-uri" "content-digest");created=' . time() . ';keyid="prado"';
		$base = '"@method": POST' . "\n"
			. '"@target-uri": ' . self::URL . "\n"
			. '"content-digest": ' . $digest . "\n"
			. '"@signature-params": ' . $input;

		return [
			'Content-Digest' => $digest,
			'Signature-Input' => 'sig1=' . $input,
			'Signature' => 'sig1=:' . base64_encode(hash_hmac('sha256', $base, self::SECRET, true)) . ':',
		];
	}

	public function testAnExpiredOrStaleSignatureIsRejected()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();

		$stale = str_replace(
			'created=' . time(),
			'created=' . (time() - 3600),
			$headers['Signature-Input']
		);
		$this->assertFalse($signature->verify($signed->withHeaders(['Signature-Input' => $stale] + $headers)));

		$signature->setMaxAge(0);
		$this->assertSame(0, $signature->getMaxAge());
	}

	public function testASignatureThatHasExpiredIsRejected()
	{
		$signature = $this->hmac();
		$signature->setMaxAge(0);
		$now = time();

		foreach ([$now + 300 => true, $now - 1 => false] as $expires => $expected) {
			$headers = $this->headersWithParameters(';created=' . $now . ';keyid="prado";expires=' . $expires);
			$this->assertSame(
				$expected,
				$signature->verify($this->request($headers)),
				'expires=' . $expires
			);
		}
	}

	public function testAMissingOrUnreadableCreatedIsRejectedWhileAgeIsChecked()
	{
		$signature = $this->hmac();

		foreach ([';keyid="prado"', ';created=whenever;keyid="prado"'] as $parameters) {
			$this->assertFalse(
				$signature->verify($this->request($this->headersWithParameters($parameters))),
				$parameters
			);
		}

		// With the age check off, a signature carrying no `created` is fine.
		$signature->setMaxAge(0);
		$this->assertTrue($signature->verify($this->request($this->headersWithParameters(';keyid="prado"'))));
	}

	public function testASignatureThatIsNotAByteSequenceIsRejected()
	{
		$headers = $this->headersWithParameters(';created=' . time() . ';keyid="prado"');
		foreach (['abc', ':abc', 'abc:', ':!!!:', ':'] as $value) {
			$headers['Signature'] = 'sig1=' . $value;
			$this->assertFalse($this->hmac()->verify($this->request($headers)), $value);
		}
	}

	/**
	 * Builds a correctly signed request whose signature parameters are whatever is given,
	 * so the parameter checks can be exercised without sign() choosing them.
	 * @param string $parameters
	 * @return array<string, string> the three headers.
	 */
	private function headersWithParameters(string $parameters): array
	{
		$digest = 'sha-256=:' . base64_encode(hash('sha256', self::BODY, true)) . ':';
		$input = '("@method" "@target-uri" "content-digest")' . $parameters;
		$base = '"@method": POST' . "\n"
			. '"@target-uri": ' . self::URL . "\n"
			. '"content-digest": ' . $digest . "\n"
			. '"@signature-params": ' . $input;

		return [
			'Content-Digest' => $digest,
			'Signature-Input' => 'sig1=' . $input,
			'Signature' => 'sig1=:' . base64_encode(hash_hmac('sha256', $base, self::SECRET, true)) . ':',
		];
	}

	public function testAnEd25519KeyOfTheWrongLengthIsAConfigurationErrorNotASodiumException()
	{
		// It used to reach the provider as a 500 error page, which is what this package's
		// own rules say never to do.
		if (!function_exists('sodium_crypto_sign_keypair')) {
			$this->markTestSkipped('ext-sodium is not loaded');
		}
		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('ed25519');
		$verifier->setPublicKey(base64_encode('too short'));
		$verifier->setRequiredComponents('@method');

		$headers = $this->headersWithParameters(';created=' . time() . ';alg="ed25519"');
		$headers['Signature'] = 'sig1=:' . base64_encode(str_repeat('A', SODIUM_CRYPTO_SIGN_BYTES)) . ':';

		$this->expectException(TConfigurationException::class);
		$verifier->verify($this->request($headers));
	}

	public function testTheKeysAreReadableBack()
	{
		$signature = new THttpMessageWebhookSignature();
		$signature->setPublicKey(self::$rsa['public']);
		$signature->setPrivateKey(self::$rsa['private']);

		$this->assertSame(self::$rsa['public'], $signature->getPublicKey());
		$this->assertSame(self::$rsa['private'], $signature->getPrivateKey());
	}

	public function testAKeyIdThatDoesNotMatchIsRejected()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);

		$signature->setKeyId('someone-else');
		$this->assertFalse($signature->verify($signed));

		$signature->setKeyId('');
		$this->assertNull($signature->getKeyId());
		$this->assertTrue($signature->verify($signed));
	}

	public function testDerivedComponentsOtherThanTheDefaults()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@authority, @scheme, @path, @query, @request-target, content-digest');

		$this->assertTrue($signature->verify($this->signed($signature)));
	}

	public function testAHeaderComponentIsCovered()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, x-tenant');

		$request = $this->request(['X-Tenant' => '7']);
		$signed = $this->signed($signature, $request);
		$this->assertTrue($signature->verify($signed));

		// Changing the covered header breaks it.
		$headers = $signed->getHeaders();
		$headers['X-Tenant'] = '8';
		$this->assertFalse($signature->verify($signed->withHeaders($headers)));
	}

	public function testACoveredComponentTheRequestDoesNotCarryIsRejected()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, x-tenant');
		$signed = $this->signed($signature, $this->request(['X-Tenant' => '7']));

		$headers = $signed->getHeaders();
		unset($headers['X-Tenant']);
		$this->assertFalse($signature->verify($signed->withHeaders($headers)));
	}

	public function testSigningARequestMissingACoveredComponentIsAConfigurationError()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, x-tenant');

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testRsaPssRoundTrips()
	{
		$signer = new THttpMessageWebhookSignature();
		$signer->setAlgorithms('rsa-pss-sha512');
		$signer->setPrivateKey(self::$rsa['private']);

		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('rsa-pss-sha512');
		$verifier->setPublicKey(self::$rsa['public']);

		$signed = $this->signed($signer);
		$this->assertStringContainsString('alg="rsa-pss-sha512"', $signed->getHeader('Signature-Input'));
		$this->assertTrue($verifier->verify($signed));
		$this->assertFalse($verifier->verify($signed->withBody('{"hello": "moon"}')));
	}

	public function testRsaPssDoesNotAcceptAPkcs1Signature()
	{
		// The same key, the same digest, a different padding: not interchangeable.
		$signer = new THttpMessageWebhookSignature();
		$signer->setAlgorithms('rsa-v1_5-sha512');
		$signer->setPrivateKey(self::$rsa['private']);

		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('rsa-pss-sha512');
		$verifier->setPublicKey(self::$rsa['public']);

		$signed = $this->signed($signer);
		$headers = $signed->getHeaders();
		$headers['Signature-Input'] = str_replace('rsa-v1_5-sha512', 'rsa-pss-sha512', $headers['Signature-Input']);

		$this->assertFalse($verifier->verify($signed->withHeaders($headers)));
	}

	public function testAPssSignatureOpenSslMadeEarlierStillVerifies()
	{
		// A known answer: this key, base and signature were produced once by the openssl
		// command line, so the test is a cross-implementation check rather than a round trip.
		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('rsa-pss-sha512');
		$verifier->setPublicKey(self::KNOWN_ANSWER_KEY);
		$verifier->setRequiredComponents('@method, @target-uri');
		$verifier->setKeyId('kat');
		$verifier->setMaxAge(0);

		$request = new TWebhookRequest('POST', '', [
			'Signature-Input' => 'sig1=("@method" "@target-uri");created=1700000000;keyid="kat";alg="rsa-pss-sha512"',
			'Signature' => 'sig1=:' . self::KNOWN_ANSWER_SIGNATURE . ':',
		], 'https://example.com/hook');

		$this->assertTrue($verifier->verify($request));

		// And the same signature against a different target URI does not.
		$elsewhere = new TWebhookRequest('POST', '', $request->getHeaders(), 'https://example.com/other');
		$this->assertFalse($verifier->verify($elsewhere));
	}

	public function testRsaRoundTrips()
	{
		$signer = new THttpMessageWebhookSignature();
		$signer->setAlgorithms('rsa-v1_5-sha256');
		$signer->setPrivateKey(self::$rsa['private']);

		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('rsa-v1_5-sha256');
		$verifier->setPublicKey(self::$rsa['public']);

		$this->assertTrue($verifier->verify($this->signed($signer)));
	}

	public function testEcdsaP256RoundTrips()
	{
		$this->assertEcdsaRoundTrips('ecdsa-p256-sha256', self::$p256);
	}

	public function testEcdsaP384RoundTrips()
	{
		$this->assertEcdsaRoundTrips('ecdsa-p384-sha384', self::$p384);
	}

	private function assertEcdsaRoundTrips(string $algorithm, array $keys): void
	{
		$signer = new THttpMessageWebhookSignature();
		$signer->setAlgorithms($algorithm);
		$signer->setPrivateKey($keys['private']);

		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms($algorithm);
		$verifier->setPublicKey($keys['public']);

		// Repeated: ECDSA coordinates vary in length, and a short one has to be padded.
		for ($i = 0; $i < 5; $i++) {
			$request = $this->request([], '{"n":' . $i . '}');
			$this->assertTrue($verifier->verify($this->signed($signer, $request)), $algorithm . ' round trip');
		}
	}

	public function testEd25519RoundTrips()
	{
		if (!function_exists('sodium_crypto_sign_keypair')) {
			$this->markTestSkipped('ext-sodium is not loaded');
		}
		$pair = sodium_crypto_sign_keypair();

		$signer = new THttpMessageWebhookSignature();
		$signer->setAlgorithms('ed25519');
		$signer->setPrivateKey(base64_encode(sodium_crypto_sign_secretkey($pair)));

		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('ed25519');
		$verifier->setPublicKey(base64_encode(sodium_crypto_sign_publickey($pair)));

		$signed = $this->signed($signer);
		$this->assertTrue($verifier->verify($signed));
		$this->assertFalse($verifier->verify($signed->withBody('{"hello": "moon"}')));
	}

	public function testASha512ContentDigest()
	{
		$signature = $this->hmac();
		$signature->setDigestAlgorithm('sha-512');

		$signed = $this->signed($signature);

		$this->assertStringStartsWith('sha-512=:', $signed->getHeader('Content-Digest'));
		$this->assertTrue($signature->verify($signed));
	}

	public function testACoveredContentDigestThatIsNotThereIsRejected()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();
		unset($headers['Content-Digest']);

		$this->assertFalse($signature->verify($signed->withHeaders($headers)));
	}

	public function testADigestHeaderNamingNoAlgorithmThisPackageKnowsIsNotEnough()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();
		$headers['Content-Digest'] = 'md5=:' . base64_encode(md5(self::BODY, true)) . ':';

		$this->assertFalse($signature->verify($signed->withHeaders($headers)));
	}

	public function testDefaults()
	{
		$signature = new THttpMessageWebhookSignature();

		$this->assertSame(['hmac-sha256'], $signature->getAlgorithms());
		$this->assertSame(
			THttpMessageWebhookSignature::DEFAULT_REQUIRED_COMPONENTS,
			$signature->getRequiredComponents()
		);
		$this->assertNull($signature->getLabel());
		$this->assertNull($signature->getKeyId());
		$this->assertSame(300, $signature->getMaxAge());
		$this->assertSame('sha-256', $signature->getDigestAlgorithm());
	}

	public function testAnEmptyOrUnknownAlgorithmListIsRefused()
	{
		foreach ([' , ', 'rsa-pss-oaep', 'made-up'] as $value) {
			try {
				(new THttpMessageWebhookSignature())->setAlgorithms($value);
				$this->fail("'{$value}' should be refused");
			} catch (TConfigurationException $e) {
				$this->assertNotSame('', $e->getMessage());
			}
		}
	}

	public function testAnEmptyComponentListIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new THttpMessageWebhookSignature())->setRequiredComponents(' , ');
	}

	public function testAnUnknownDigestAlgorithmIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new THttpMessageWebhookSignature())->setDigestAlgorithm('md5');
	}

	public function testVerifyingWithoutASecretIsAConfigurationError()
	{
		$signature = new THttpMessageWebhookSignature();
		$signed = $this->signed($this->hmac());

		$this->expectException(TConfigurationException::class);
		$signature->verify($signed);
	}

	/**
	 * Every way a key can be unusable, in both directions. Each is configuration rather than
	 * anything a caller sent, so each has to be an exception and not a quiet false.
	 * @dataProvider unusableKeys
	 * @param string $algorithm
	 * @param string $property
	 * @param string $material
	 */
	public function testAnUnusableKeyIsAConfigurationError(string $algorithm, string $property, string $material)
	{
		$signature = new THttpMessageWebhookSignature();
		$signature->setAlgorithms($algorithm);
		$signature->setRequiredComponents('@method');
		if ($material !== '') {
			$signature->{'set' . $property}($material);
		}

		$this->expectException(TConfigurationException::class);
		if ($property === 'PrivateKey') {
			$signature->sign($this->request());

			return;
		}
		$headers = $this->headersWithParameters(';created=' . time() . ';alg="' . $algorithm . '"');
		$signature->verify($this->request($headers));
	}

	public static function unusableKeys(): array
	{
		$ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
		openssl_pkey_export($ec, $ecPrivate);
		$ecPublic = openssl_pkey_get_details($ec)['key'];
		$rubbish = "-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----";

		return [
			'rsa, no key at all' => ['rsa-v1_5-sha256', 'PublicKey', ''],
			'rsa, unreadable key' => ['rsa-v1_5-sha256', 'PublicKey', $rubbish],
			'pss, an EC key' => ['rsa-pss-sha512', 'PublicKey', $ecPublic],
			'pss, unreadable key' => ['rsa-pss-sha512', 'PublicKey', $rubbish],
			'rsa, no private key' => ['rsa-v1_5-sha256', 'PrivateKey', ''],
			'rsa, unreadable private key' => ['rsa-v1_5-sha256', 'PrivateKey', $rubbish],
			'pss, an EC private key' => ['rsa-pss-sha512', 'PrivateKey', (string) $ecPrivate],
			'ecdsa, no key' => ['ecdsa-p256-sha256', 'PublicKey', ''],
		];
	}

	public function testAnEcdsaSignatureOfTheWrongLengthIsRefused()
	{
		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('ecdsa-p256-sha256');
		$verifier->setPublicKey(self::$p256['public']);
		$verifier->setRequiredComponents('@method');

		$headers = $this->headersWithParameters(';created=' . time() . ';alg="ecdsa-p256-sha256"');
		$headers['Signature'] = 'sig1=:' . base64_encode('too short') . ':';

		$this->assertFalse($verifier->verify($this->request($headers)));
	}

	public function testSigningAnEcdsaBaseWithAnRsaKeyIsAConfigurationError()
	{
		// openssl_sign succeeds and hands back a PKCS#1 signature, which is not the pair of
		// coordinates an ECDSA algorithm promises, so the conversion refuses it.
		$signer = new THttpMessageWebhookSignature();
		$signer->setAlgorithms('ecdsa-p256-sha256');
		$signer->setPrivateKey(self::$rsa['private']);

		$this->expectException(TConfigurationException::class);
		$signer->sign($this->request());
	}

	public function testSigningWithoutAKeyIsAConfigurationError()
	{
		$signature = new THttpMessageWebhookSignature();
		$signature->setAlgorithms('rsa-v1_5-sha256');

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	// ── Header components ──────────────────────────────────────────────────────

	/**
	 * Signs a base assembled by hand over the given component lines, so the test rather
	 * than sign() decides what each component's value is.
	 * @param array<string, string> $lines component identifier (serialized) => value.
	 * @param string $parameters the signature parameters, `;created=...`.
	 * @return array<string, string> the two signature headers.
	 */
	private function handSigned(array $lines, string $parameters): array
	{
		$input = '(' . implode(' ', array_map(
			static fn ($identifier) => $identifier,
			array_keys($lines)
		)) . ')' . $parameters;
		$base = '';
		foreach ($lines as $identifier => $value) {
			$base .= $identifier . ': ' . $value . "\n";
		}
		$base .= '"@signature-params": ' . $input;

		return [
			'Signature-Input' => 'sig1=' . $input,
			'Signature' => 'sig1=:' . base64_encode(hash_hmac('sha256', $base, self::SECRET, true)) . ':',
		];
	}

	public function testARepeatedHeaderContributesEveryInstanceJoinedByCommaSpace()
	{
		// RFC 9421 section 2.1. Reading only the first instance would let the second be
		// rewritten under a valid signature.
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, x-tenant');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(['"@method"' => 'POST', '"x-tenant"' => '7, 8'], ';created=' . time() . ';keyid="prado"');

		$this->assertTrue($signature->verify($this->request($headers + ['X-Tenant' => ['7', '8']])));
		$this->assertFalse($signature->verify($this->request($headers + ['X-Tenant' => ['7', '9']])));
		$this->assertFalse($signature->verify($this->request($headers + ['X-Tenant' => ['7']])));
		$this->assertFalse($signature->verify($this->request($headers + ['X-Tenant' => '7'])));
	}

	public function testEachHeaderInstanceIsTrimmedAndLineFoldingCollapsed()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, x-tenant');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(['"@method"' => 'POST', '"x-tenant"' => 'a b, c'], ';created=' . time() . ';keyid="prado"');

		$this->assertTrue($signature->verify($this->request($headers + ['X-Tenant' => ["  a\r\n\t b  ", "\tc "]])));
		$this->assertTrue($signature->verify($this->request($headers + ['x-tenant' => ['a b', 'c']])), 'case of the name');
	}

	public function testARepeatedHeaderRoundTripsThroughSigning()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, x-tenant');

		$request = $this->request(['X-Tenant' => ['7', '8']]);
		$signed = $this->signed($signature, $request);

		$this->assertTrue($signature->verify($signed));
		$headers = $signed->getHeaders();
		$headers['X-Tenant'] = ['8', '7'];
		$this->assertFalse($signature->verify($signed->withHeaders($headers)), 'order is part of the value');
	}

	public function testAnEmptyHeaderInstanceListIsAbsentButAnEmptyValueIsPresent()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, x-tenant');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(['"@method"' => 'POST', '"x-tenant"' => ''], ';created=' . time() . ';keyid="prado"');

		$this->assertTrue($signature->verify($this->request($headers + ['X-Tenant' => ''])));
		$this->assertFalse($signature->verify($this->request($headers + ['X-Tenant' => []])));
		$this->assertFalse($signature->verify($this->request($headers)));
	}

	public function testTheSignatureHeadersThemselvesMayBeRepeated()
	{
		// A dictionary field split over two header lines is one dictionary.
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();
		$headers['Signature-Input'] = ['sig0=("@method");created=' . time(), $headers['Signature-Input']];
		$headers['Signature'] = ['sig0=:YWJj:', $headers['Signature']];

		$this->assertTrue($signature->verify($signed->withHeaders($headers)));
	}

	// ── Derived components ─────────────────────────────────────────────────────

	/**
	 * @dataProvider authorities
	 * @param string $url
	 * @param string $authority
	 */
	public function testTheAuthorityIsLowerCaseWithoutADefaultPort(string $url, string $authority)
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@authority');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(['"@authority"' => $authority], ';created=' . time() . ';keyid="prado"');

		$this->assertTrue(
			$signature->verify(new TWebhookRequest('POST', self::BODY, $headers, $url)),
			$url . ' has the authority ' . $authority
		);
	}

	public static function authorities(): array
	{
		return [
			['https://example.com/hook', 'example.com'],
			['https://Example.COM/hook', 'example.com'],
			['https://example.com:443/hook', 'example.com'],
			['HTTPS://example.com:443/hook', 'example.com'],
			['http://example.com:80/hook', 'example.com'],
			['https://example.com:80/hook', 'example.com:80'],
			['http://example.com:443/hook', 'example.com:443'],
			['https://example.com:8443/hook', 'example.com:8443'],
			['https://[::1]:8443/hook', '[::1]:8443'],
		];
	}

	public function testASignerAndAVerifierAgreeOnTheAuthorityWhateverThePortSpelling()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@authority, @path');

		$signed = $this->signed($signature, new TWebhookRequest('POST', self::BODY, [], 'https://Example.com:443/hook'));

		$this->assertTrue($signature->verify(new TWebhookRequest('POST', self::BODY, $signed->getHeaders(), 'https://example.com/hook')));
	}

	/**
	 * @dataProvider paths
	 * @param string $url
	 * @param string $path
	 * @param string $target
	 */
	public function testThePathOfAUrlWithNoPathIsASlash(string $url, string $path, string $target)
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@path, @request-target');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(['"@path"' => $path, '"@request-target"' => $target], ';created=' . time() . ';keyid="prado"');

		$this->assertTrue($signature->verify(new TWebhookRequest('POST', self::BODY, $headers, $url)), $url);
	}

	public static function paths(): array
	{
		return [
			['https://example.com', '/', '/'],
			['https://example.com?a=1', '/', '/?a=1'],
			['https://example.com/', '/', '/'],
			['https://example.com/hook?a=1', '/hook', '/hook?a=1'],
		];
	}

	public function testARequestWithNoUrlHasNoPath()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@path');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(['"@path"' => '/'], ';created=' . time() . ';keyid="prado"');

		$this->assertFalse($signature->verify(new TWebhookRequest('POST', self::BODY, $headers, '')));
	}

	// ── Signature-Input parsing ────────────────────────────────────────────────

	public function testAQuotedParameterValueMayHoldASemicolonOrAnEscapedQuote()
	{
		$signature = $this->hmac();
		$signature->setMaxAge(0);

		foreach (['a;b', 'say "hi"', 'x=y;z="w"', '(paren)'] as $keyId) {
			$signature->setKeyId($keyId);
			$quoted = '"' . addcslashes($keyId, '\\"') . '"';
			$headers = $this->headersWithParameters(';created=' . time() . ';keyid=' . $quoted);

			$this->assertTrue($signature->verify($this->request($headers)), $keyId);
		}
	}

	public function testAComponentParameterDoesNotLeakIntoTheSignatureParameters()
	{
		// Before this was parsed properly, `;key="x"` attached to a component was read as
		// the signature parameter `key`, and `;keyid="k"` on a component could satisfy the
		// key id check.
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method');
		$signature->setMaxAge(0);

		// The message's key id is on a component, not in the signature parameters.
		$headers = $this->handSigned(['"@method";keyid="prado"' => 'POST'], ';created=' . time());
		$this->assertFalse($signature->verify($this->request($headers)));

		// Without a key id to check, the same message is still refused: a component
		// parameter this class does not implement fails closed.
		$signature->setKeyId('');
		$this->assertFalse($signature->verify($this->request($headers)));
	}

	public function testAComponentParameterDoesNotLeakIntoTheComponentList()
	{
		// `"x-tenant";key="a"` used to be read as the component `x-tenant`, satisfying a
		// requirement it does not meet.
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, x-tenant');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(['"@method"' => 'POST', '"x-tenant";key="a"' => '1'], ';created=' . time() . ';keyid="prado"');

		$this->assertFalse($signature->verify($this->request($headers + ['X-Tenant' => 'a=1'])));
	}

	/**
	 * @dataProvider unsupportedComponentParameters
	 * @param string $identifier
	 */
	public function testAComponentParameterThisClassDoesNotImplementIsRefusedNotMisread(string $identifier)
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method');
		$signature->setMaxAge(0);

		$headers = $this->handSigned([$identifier => 'POST'], ';created=' . time() . ';keyid="prado"');

		$this->assertFalse($signature->verify($this->request($headers)), $identifier);
	}

	public static function unsupportedComponentParameters(): array
	{
		return [
			['"@method";sf'],
			['"@method";bs'],
			['"@method";req'],
			['"@method";tr'],
			['"@method";key="x"'],
			['"@method";name="x"'],
			['"@query-param";name="x";sf'],
			['"@query-param";name=x'],
			['"@query-param"'],
		];
	}

	public function testADuplicateComponentIsRefused()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method');
		$signature->setMaxAge(0);

		// A hand-built base with the component twice, signed correctly for that base.
		$input = '("@method" "@method");created=' . time() . ';keyid="prado"';
		$base = '"@method": POST' . "\n" . '"@method": POST' . "\n" . '"@signature-params": ' . $input;
		$headers = [
			'Signature-Input' => 'sig1=' . $input,
			'Signature' => 'sig1=:' . base64_encode(hash_hmac('sha256', $base, self::SECRET, true)) . ':',
		];
		$this->assertFalse($signature->verify($this->request($headers)));

		// Also when the duplicate differs only in spelling.
		$headers['Signature-Input'] = 'sig1=("@method" "@METHOD");created=' . time() . ';keyid="prado"';
		$this->assertFalse($signature->verify($this->request($headers)));

		// The same name with different parameters is two components, not a duplicate.
		$headers = $this->handSigned(
			['"@query-param";name="a"' => '1', '"@query-param";name="b"' => '2'],
			';created=' . time() . ';keyid="prado"'
		);
		$signature->setRequiredComponents('@query-param;name="a"');
		$this->assertTrue($signature->verify(new TWebhookRequest('POST', self::BODY, $headers, 'https://example.com/h?a=1&b=2')));
	}

	public function testMalformedInnerListsAreRefusedRatherThanThrowing()
	{
		$signature = $this->hmac();
		$signature->setMaxAge(0);
		foreach ([
			'("@method"',
			'("@method" @target-uri)',
			'(@method)',
			'("@method");created="abc',
			'("@method");=1',
			'("@method");created=1;Keyid="x"',
			'("@method");created=1 trailing',
			'("@method";)',
			'("@method" "x\u0001y")',
			'("@method" "unterminated)',
			'()',
			'',
			'@method',
		] as $input) {
			$this->assertFalse($signature->verify($this->request([
				'Signature-Input' => 'sig1=' . $input,
				'Signature' => 'sig1=:YWJj:',
			])), $input);
		}
	}

	public function testTheSignatureParamsLineIsTheOriginalInputVerbatim()
	{
		// Whatever spelling the sender used -- spaces after semicolons, parameters in an
		// unusual order -- the base carries it exactly, because that is what was signed.
		$signature = $this->hmac();
		$signature->setMaxAge(0);

		$input = '("@method" "@target-uri" "content-digest"); keyid="prado";created=' . time();
		$digest = 'sha-256=:' . base64_encode(hash('sha256', self::BODY, true)) . ':';
		$base = '"@method": POST' . "\n"
			. '"@target-uri": ' . self::URL . "\n"
			. '"content-digest": ' . $digest . "\n"
			. '"@signature-params": ' . $input;

		$this->assertTrue($signature->verify($this->request([
			'Content-Digest' => $digest,
			'Signature-Input' => 'sig1=' . $input,
			'Signature' => 'sig1=:' . base64_encode(hash_hmac('sha256', $base, self::SECRET, true)) . ':',
		])));
	}

	// ── @query-param ───────────────────────────────────────────────────────────

	public function testAQueryParameterComponentVerifiesAgainstAHandBuiltBase()
	{
		// RFC 9421 section 2.2.8: the value is percent-decoded and re-encoded strictly.
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, "@query-param";name="id"');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(
			['"@method"' => 'POST', '"@query-param";name="id"' => 'evt%2F1%20a'],
			';created=' . time() . ';keyid="prado"'
		);

		foreach ([
			'https://example.com/hook?id=evt%2F1%20a',
			'https://example.com/hook?id=evt/1%20a',
			'https://example.com/hook?id=evt%2f1%20a',
			'https://example.com/hook?other=1&id=evt%2F1%20a&more=2',
		] as $url) {
			$this->assertTrue($signature->verify(new TWebhookRequest('POST', self::BODY, $headers, $url)), $url);
		}
		foreach ([
			'https://example.com/hook?id=evt%2F2',
			'https://example.com/hook?id=evt%2F1%20a&id=evt%2F1%20a',
			'https://example.com/hook?ID=evt%2F1%20a',
			'https://example.com/hook',
			'https://example.com/hook?id',
		] as $url) {
			$this->assertFalse($signature->verify(new TWebhookRequest('POST', self::BODY, $headers, $url)), $url);
		}
	}

	public function testAQueryParameterComponentRoundTripsThroughSigning()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@method, @query-param;name="id", content-digest');

		$this->assertSame(['@method', '@query-param;name="id"', 'content-digest'], $signature->getRequiredComponents());

		$request = new TWebhookRequest('POST', self::BODY, [], 'https://example.com/hook?id=evt_1&x=y');
		$signed = $this->signed($signature, $request);

		$this->assertStringContainsString('("@method" "@query-param";name="id" "content-digest")', $signed->getHeader('Signature-Input'));
		$this->assertTrue($signature->verify($signed));
		$this->assertFalse($signature->verify(new TWebhookRequest('POST', self::BODY, $signed->getHeaders(), 'https://example.com/hook?id=evt_2&x=y')));
		// An uncovered parameter may change.
		$this->assertTrue($signature->verify(new TWebhookRequest('POST', self::BODY, $signed->getHeaders(), 'https://example.com/hook?id=evt_1&x=z')));
	}

	public function testAnEmptyQueryParameterValueIsAnEmptyComponent()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@query-param;name="qux"');
		$signature->setMaxAge(0);

		$headers = $this->handSigned(['"@query-param";name="qux"' => ''], ';created=' . time() . ';keyid="prado"');

		$this->assertTrue($signature->verify(new TWebhookRequest('POST', self::BODY, $headers, 'https://example.com/?qux=')));
		$this->assertTrue($signature->verify(new TWebhookRequest('POST', self::BODY, $headers, 'https://example.com/?qux')));
	}

	public function testSigningAQueryParameterTheUrlDoesNotCarryIsAConfigurationError()
	{
		$signature = $this->hmac();
		$signature->setRequiredComponents('@query-param;name="id"');

		$this->expectException(TConfigurationException::class);
		$signature->sign(new TWebhookRequest('POST', self::BODY, [], 'https://example.com/hook?other=1'));
	}

	public function testRequiredComponentsAreNormalizedToOneSpelling()
	{
		$signature = new THttpMessageWebhookSignature();
		$signature->setRequiredComponents(['"@Method"', ' X-Tenant ', '"@query-param"; name="Pet"', '@query-param;name="a";sf']);

		$this->assertSame(
			['@method', 'x-tenant', '@query-param;name="Pet"', '@query-param;name="a";sf'],
			$signature->getRequiredComponents()
		);
	}

	// ── Labels ─────────────────────────────────────────────────────────────────

	public function testWhenTheFirstLabelFailsTheSecondMayStillPass()
	{
		$signature = $this->hmac();
		$signed = $this->signed($signature);
		$headers = $signed->getHeaders();

		// A first label that verifies against nothing, then the genuine one.
		$headers['Signature-Input'] = 'sig0=("@method");created=' . time() . ';keyid="prado", ' . $headers['Signature-Input'];
		$headers['Signature'] = 'sig0=:' . base64_encode(str_repeat("\0", 32)) . ':, ' . $headers['Signature'];

		$this->assertTrue($signature->verify($signed->withHeaders($headers)));

		// And pinned to the label, the failing one alone is refused.
		$signature->setLabel('sig0');
		$this->assertFalse($signature->verify($signed->withHeaders($headers)));
	}

	// ── Parameters ─────────────────────────────────────────────────────────────

	public function testANonNumericExpiresRejectsTheSignature()
	{
		// It used to be overlooked, which let a signature declare itself unexpiring in words.
		$signature = $this->hmac();
		$signature->setMaxAge(0);

		foreach ([';expires=never', ';expires="' . (time() + 300) . '"', ';expires=?1', ';expires'] as $expires) {
			$headers = $this->headersWithParameters(';created=' . time() . ';keyid="prado"' . $expires);
			$this->assertFalse($signature->verify($this->request($headers)), $expires);
		}
		$headers = $this->headersWithParameters(';created=' . time() . ';keyid="prado";expires=' . (time() + 300));
		$this->assertTrue($signature->verify($this->request($headers)));
	}

	public function testACreatedInTheFutureBeyondMaxAgeIsRejected()
	{
		$signature = $this->hmac();

		$headers = $this->headersWithParameters(';created=' . (time() + 3600) . ';keyid="prado"');
		$this->assertFalse($signature->verify($this->request($headers)));

		$headers = $this->headersWithParameters(';created=' . (time() + 60) . ';keyid="prado"');
		$this->assertTrue($signature->verify($this->request($headers)), 'inside the window in either direction');
	}

	// ── Mixed algorithm lists ──────────────────────────────────────────────────

	public function testWithAMixedListTheSenderCannotChooseWhichExceptionIsRaised()
	{
		// Only a public key is configured; a message declaring hmac-sha256 is refused,
		// not reported as a 500 of the sender's choosing.
		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('rsa-v1_5-sha256, hmac-sha256');
		$verifier->setPublicKey(self::$rsa['public']);
		$verifier->setMaxAge(0);

		$hmac = $this->headersWithParameters(';created=' . time() . ';alg="hmac-sha256"');
		$this->assertFalse($verifier->verify($this->request($hmac)));

		$signer = new THttpMessageWebhookSignature();
		$signer->setAlgorithms('rsa-v1_5-sha256');
		$signer->setPrivateKey(self::$rsa['private']);
		$this->assertTrue($verifier->verify($this->signed($signer)));
	}

	public function testWithAMixedListAndOnlyASecretAnAsymmetricSignatureIsRefusedNotAnError()
	{
		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('hmac-sha256, rsa-pss-sha512, ecdsa-p256-sha256, ed25519');
		$verifier->setSecret(self::SECRET);
		$verifier->setMaxAge(0);

		foreach (['rsa-pss-sha512', 'ecdsa-p256-sha256', 'ed25519'] as $algorithm) {
			$headers = $this->headersWithParameters(';created=' . time() . ';alg="' . $algorithm . '"');
			$this->assertFalse($verifier->verify($this->request($headers)), $algorithm);
		}
		$this->assertTrue($verifier->verify($this->request($this->headersWithParameters(';created=' . time() . ';alg="hmac-sha256"'))));
	}

	public function testASingleFamilyWithNoKeyStillThrows()
	{
		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('hmac-sha256, hmac-sha512');

		$this->expectException(TConfigurationException::class);
		$verifier->verify($this->request($this->headersWithParameters(';created=' . time() . ';alg="hmac-sha256"')));
	}

	public function testAMixedListWithNoKeyAtAllStillThrows()
	{
		$verifier = new THttpMessageWebhookSignature();
		$verifier->setAlgorithms('rsa-v1_5-sha256, hmac-sha256');

		$this->expectException(TConfigurationException::class);
		$verifier->verify($this->request($this->headersWithParameters(';created=' . time() . ';alg="hmac-sha256"')));
	}

	public function testVerifyingWithoutAnyKeyIsAConfigurationErrorEvenWhenNothingIsPresented()
	{
		$this->expectException(TConfigurationException::class);
		(new THttpMessageWebhookSignature())->verify($this->request());
	}
}
