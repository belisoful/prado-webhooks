<?php

use Belisoful\Prado\Web\Webhooks\Signature\TJwtWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookEncoding;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;

class TJwtWebhookSignatureTest extends PHPUnit\Framework\TestCase
{
	private const SECRET = 'a shared signing secret';
	private const BODY = '{"id":"evt_1"}';

	private static array $rsa;
	private static array $ec;

	/** @var array<string, array{private: string, public: string}> a key per ECDSA curve */
	private static array $curves;

	public static function setUpBeforeClass(): void
	{
		self::$rsa = self::newKeyPair(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		self::$curves = [
			'ES256' => self::newKeyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']),
			'ES384' => self::newKeyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']),
			'ES512' => self::newKeyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']),
		];
		self::$ec = self::$curves['ES256'];
	}

	/** @return array{private: string, public: string} */
	private static function newKeyPair(array $options): array
	{
		$key = openssl_pkey_new($options);
		openssl_pkey_export($key, $private);

		return ['private' => $private, 'public' => openssl_pkey_get_details($key)['key']];
	}

	private function request(array $headers = [], string $body = self::BODY): TWebhookRequest
	{
		return new TWebhookRequest('POST', $body, $headers);
	}

	private function hs256(): TJwtWebhookSignature
	{
		$signature = new TJwtWebhookSignature();
		$signature->setSecret(self::SECRET);

		return $signature;
	}

	/** Builds a token by hand, so verification is tested against something it did not make. */
	private function token(array $header, array $claims, string $secret = self::SECRET): string
	{
		$signing = TWebhookEncoding::Base64Url->encode((string) json_encode($header))
			. '.' . TWebhookEncoding::Base64Url->encode((string) json_encode($claims));

		return $signing . '.' . TWebhookEncoding::Base64Url->encode(hash_hmac('sha256', $signing, $secret, true));
	}

	public function testVerifiesATokenSignedWithTheSharedSecret()
	{
		$token = $this->token(['alg' => 'HS256', 'typ' => 'JWT'], ['exp' => time() + 300]);

		$this->assertTrue($this->hs256()->verify($this->request(['Authorization' => 'Bearer ' . $token])));
	}

	public function testRejectsATokenSignedWithAnotherSecret()
	{
		$token = $this->token(['alg' => 'HS256'], ['exp' => time() + 300], 'not the secret');

		$this->assertFalse($this->hs256()->verify($this->request(['Authorization' => 'Bearer ' . $token])));
	}

	public function testSignsWhatItVerifies()
	{
		$signature = $this->hs256();
		$headers = $signature->sign($this->request());

		$this->assertStringStartsWith('Bearer ', $headers['Authorization']);
		$this->assertTrue($signature->verify($this->request($headers)));
	}

	public function testRejectsAnythingThatIsNotAToken()
	{
		foreach (['', 'Bearer ', 'Bearer not.a', 'Bearer a.b.c', 'no prefix at all'] as $header) {
			$this->assertFalse(
				$this->hs256()->verify($this->request(['Authorization' => $header])),
				"'{$header}' is not a token"
			);
		}
		$this->assertFalse($this->hs256()->verify($this->request()));
	}

	public function testAnAlgorithmOutsideTheAllowListIsRejected()
	{
		// `none` and algorithm substitution are the classic JWT attacks; the allow list is
		// what closes both, so the token's own `alg` is never what decides.
		foreach (['none', 'HS512', 'RS256'] as $algorithm) {
			$token = $this->token(['alg' => $algorithm], ['exp' => time() + 300]);
			$this->assertFalse(
				$this->hs256()->verify($this->request(['Authorization' => 'Bearer ' . $token])),
				"{$algorithm} is not allow listed"
			);
		}
	}

	public function testAnAlgorithmThisPackageDoesNotImplementIsRefusedAtConfiguration()
	{
		$this->expectException(TConfigurationException::class);
		(new TJwtWebhookSignature())->setAlgorithms('none');
	}

	public function testAnEmptyAlgorithmListIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TJwtWebhookSignature())->setAlgorithms(' , ');
	}

	public function testAnExpiredTokenIsRejected()
	{
		$token = $this->token(['alg' => 'HS256'], ['exp' => time() - 3600]);

		$this->assertFalse($this->hs256()->verify($this->request(['Authorization' => 'Bearer ' . $token])));
	}

	public function testATokenExpiringInsideTheLeewayIsStillAccepted()
	{
		$signature = $this->hs256();
		$signature->setLeeway(120);
		$token = $this->token(['alg' => 'HS256'], ['exp' => time() - 60]);

		$this->assertTrue($signature->verify($this->request(['Authorization' => 'Bearer ' . $token])));
	}

	public function testATokenNotYetValidIsRejected()
	{
		$token = $this->token(['alg' => 'HS256'], ['nbf' => time() + 3600]);

		$this->assertFalse($this->hs256()->verify($this->request(['Authorization' => 'Bearer ' . $token])));
	}

	public function testTheIssuerAndAudienceAreCheckedWhenSet()
	{
		$signature = $this->hs256();
		$signature->setIssuer('https://provider.example');
		$signature->setAudience('my-app');

		$good = $this->token(['alg' => 'HS256'], ['iss' => 'https://provider.example', 'aud' => 'my-app']);
		$this->assertTrue($signature->verify($this->request(['Authorization' => 'Bearer ' . $good])));

		// A token the same provider minted for someone else.
		$other = $this->token(['alg' => 'HS256'], ['iss' => 'https://provider.example', 'aud' => 'another-app']);
		$this->assertFalse($signature->verify($this->request(['Authorization' => 'Bearer ' . $other])));

		$elsewhere = $this->token(['alg' => 'HS256'], ['iss' => 'https://elsewhere.example', 'aud' => 'my-app']);
		$this->assertFalse($signature->verify($this->request(['Authorization' => 'Bearer ' . $elsewhere])));
	}

	public function testSigningCarriesTheIssuerAndAudienceItChecks()
	{
		$signature = $this->hs256();
		$signature->setIssuer('https://provider.example');
		$signature->setAudience('my-app');

		$headers = $signature->sign($this->request());
		$claims = json_decode(
			(string) TWebhookEncoding::Base64Url->decode(explode('.', substr($headers['Authorization'], 7))[1]),
			true
		);

		$this->assertSame('https://provider.example', $claims['iss']);
		$this->assertSame('my-app', $claims['aud']);
		$this->assertTrue($signature->verify($this->request($headers)));
	}

	public function testTheSecretIsReadable()
	{
		$this->assertSame(self::SECRET, $this->hs256()->getSecret());
	}

	public function testAnAudienceListIsAccepted()
	{
		$signature = $this->hs256();
		$signature->setAudience('my-app');
		$token = $this->token(['alg' => 'HS256'], ['aud' => ['someone-else', 'my-app']]);

		$this->assertTrue($signature->verify($this->request(['Authorization' => 'Bearer ' . $token])));
	}

	public function testABodyHashClaimTiesTheTokenToTheDelivery()
	{
		// Without it, a captured token verifies against any body until it expires.
		$signature = $this->hs256();
		$signature->setBodyHashClaim('body_sha256');

		$token = $this->token(['alg' => 'HS256'], ['body_sha256' => hash('sha256', self::BODY)]);

		$this->assertTrue($signature->verify($this->request(['Authorization' => 'Bearer ' . $token])));
		$this->assertFalse($signature->verify($this->request(['Authorization' => 'Bearer ' . $token], '{"id":"evt_2"}')));
	}

	public function testAMissingBodyHashClaimIsRejectedWhenOneIsRequired()
	{
		$signature = $this->hs256();
		$signature->setBodyHashClaim('body_sha256');
		$token = $this->token(['alg' => 'HS256'], ['exp' => time() + 300]);

		$this->assertFalse($signature->verify($this->request(['Authorization' => 'Bearer ' . $token])));
	}

	public function testABodyHashClaimRoundTripsThroughSigning()
	{
		$signature = $this->hs256();
		$signature->setBodyHashClaim('body_sha256');
		$signature->setBodyHashEncoding('base64');

		$headers = $signature->sign($this->request());

		$this->assertTrue($signature->verify($this->request($headers)));
		$this->assertFalse($signature->verify($this->request($headers, 'a different body')));
	}

	public function testAnRsaTokenRoundTrips()
	{
		$signer = new TJwtWebhookSignature();
		$signer->setAlgorithms('RS256');
		$signer->setPrivateKey(self::$rsa['private']);

		$verifier = new TJwtWebhookSignature();
		$verifier->setAlgorithms('RS256');
		$verifier->setPublicKey(self::$rsa['public']);

		$headers = $signer->sign($this->request());

		$this->assertTrue($verifier->verify($this->request($headers)));
		$this->assertFalse($verifier->verify($this->request(['Authorization' => 'Bearer x.y.z'])));
	}

	/**
	 * JWS carries the raw ECDSA coordinates while OpenSSL wants DER, so each curve exercises
	 * both halves of that conversion -- and each has its own coordinate size, P-521 being the
	 * awkward one at 66 bytes for 521 bits.
	 * @dataProvider ecdsaAlgorithms
	 */
	public function testAnEcdsaTokenRoundTrips(string $algorithm)
	{
		$keys = self::$curves[$algorithm];
		$signer = new TJwtWebhookSignature();
		$signer->setAlgorithms($algorithm);
		$signer->setPrivateKey($keys['private']);

		$verifier = new TJwtWebhookSignature();
		$verifier->setAlgorithms($algorithm);
		$verifier->setPublicKey($keys['public']);

		for ($i = 0; $i < 8; $i++) {
			// Repeated because coordinates vary in length: a short one has to be left padded
			// rather than shifted, and that only happens in a fraction of signatures.
			$body = '{"n":' . $i . '}';
			$headers = $signer->sign($this->request([], $body));
			$this->assertTrue($verifier->verify($this->request($headers, $body)), $algorithm . ' round trip');
		}
	}

	/**
	 * @dataProvider ecdsaAlgorithms
	 */
	public function testAnEcdsaTokenFromAnotherCurveIsRejected(string $algorithm)
	{
		$verifier = new TJwtWebhookSignature();
		$verifier->setAlgorithms($algorithm);
		$verifier->setPublicKey(self::$curves[$algorithm]['public']);

		foreach (self::$curves as $other => $keys) {
			if ($other === $algorithm) {
				continue;
			}
			$signer = new TJwtWebhookSignature();
			$signer->setAlgorithms($other);
			$signer->setPrivateKey($keys['private']);

			$this->assertFalse(
				$verifier->verify($this->request($signer->sign($this->request()))),
				$other . ' must not verify as ' . $algorithm
			);
		}
	}

	public static function ecdsaAlgorithms(): array
	{
		return [['ES256'], ['ES384'], ['ES512']];
	}

	public function testAnEcdsaSignatureOfTheWrongLengthIsRejected()
	{
		$verifier = new TJwtWebhookSignature();
		$verifier->setAlgorithms('ES256');
		$verifier->setPublicKey(self::$curves['ES256']['public']);

		$signing = TWebhookEncoding::Base64Url->encode('{"alg":"ES256"}')
			. '.' . TWebhookEncoding::Base64Url->encode('{}');
		$token = $signing . '.' . TWebhookEncoding::Base64Url->encode('too short');

		$this->assertFalse($verifier->verify($this->request(['Authorization' => 'Bearer ' . $token])));
	}

	public function testATokenInItsOwnHeaderWithoutAPrefix()
	{
		$signature = $this->hs256();
		$signature->setHeader('X-Provider-Token');
		$signature->setPrefix('');

		$headers = $signature->sign($this->request());

		$this->assertArrayHasKey('X-Provider-Token', $headers);
		$this->assertStringNotContainsString('Bearer', $headers['X-Provider-Token']);
		$this->assertTrue($signature->verify($this->request($headers)));
	}

	public function testDefaults()
	{
		$signature = new TJwtWebhookSignature();

		$this->assertSame(['HS256'], $signature->getAlgorithms());
		$this->assertSame('Authorization', $signature->getName());
		$this->assertSame('Bearer ', $signature->getPrefix());
		$this->assertSame(TJwtWebhookSignature::DEFAULT_LEEWAY, $signature->getLeeway());
		$this->assertNull($signature->getIssuer());
		$this->assertNull($signature->getAudience());
		$this->assertNull($signature->getBodyHashClaim());
		$this->assertSame('sha256', $signature->getBodyHashAlgorithm());
		$this->assertSame(300, $signature->getLifetime());
	}

	public function testPropertiesRoundTrip()
	{
		$signature = new TJwtWebhookSignature();
		$signature->setAlgorithms(['RS256', 'ES256']);
		$signature->setPublicKey(self::$rsa['public']);
		$signature->setPrivateKey(self::$rsa['private']);
		$signature->setIssuer('https://provider.example');
		$signature->setAudience('my-app');
		$signature->setLeeway(-5);
		$signature->setLifetime(0);
		$signature->setBodyHashAlgorithm('SHA512');

		$this->assertSame(['RS256', 'ES256'], $signature->getAlgorithms());
		$this->assertSame(self::$rsa['public'], $signature->getPublicKey());
		$this->assertSame(self::$rsa['private'], $signature->getPrivateKey());
		$this->assertSame('https://provider.example', $signature->getIssuer());
		$this->assertSame('my-app', $signature->getAudience());
		$this->assertSame(0, $signature->getLeeway());
		$this->assertSame(1, $signature->getLifetime());
		$this->assertSame('sha512', $signature->getBodyHashAlgorithm());

		$signature->setIssuer('');
		$signature->setAudience('');
		$signature->setBodyHashClaim('');
		$this->assertNull($signature->getIssuer());
		$this->assertNull($signature->getAudience());
		$this->assertNull($signature->getBodyHashClaim());
	}

	public function testAKeyReadFromAFile()
	{
		$file = tempnam(sys_get_temp_dir(), 'pem');
		file_put_contents($file, self::$rsa['public']);

		$signer = new TJwtWebhookSignature();
		$signer->setAlgorithms('RS256');
		$signer->setPrivateKey(self::$rsa['private']);

		$verifier = new TJwtWebhookSignature();
		$verifier->setAlgorithms('RS256');
		$verifier->setPublicKey($file);

		$this->assertTrue($verifier->verify($this->request($signer->sign($this->request()))));
		unlink($file);
	}

	public function testAnRsaTokenSignedWithTheWrongKeyIsRejected()
	{
		$other = self::newKeyPair(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		$signer = new TJwtWebhookSignature();
		$signer->setAlgorithms('RS256');
		$signer->setPrivateKey($other['private']);

		$verifier = new TJwtWebhookSignature();
		$verifier->setAlgorithms('RS256');
		$verifier->setPublicKey(self::$rsa['public']);

		$this->assertFalse($verifier->verify($this->request($signer->sign($this->request()))));
	}

	public function testVerifyingWithoutASecretIsAConfigurationError()
	{
		$signature = new TJwtWebhookSignature();
		$token = $this->token(['alg' => 'HS256'], ['exp' => time() + 300]);

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request(['Authorization' => 'Bearer ' . $token]));
	}

	public function testVerifyingAnRsaTokenWithoutAKeyIsAConfigurationError()
	{
		$signature = new TJwtWebhookSignature();
		$signature->setAlgorithms('RS256');
		$signing = TWebhookEncoding::Base64Url->encode('{"alg":"RS256"}')
			. '.' . TWebhookEncoding::Base64Url->encode('{}');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request([
			'Authorization' => 'Bearer ' . $signing . '.' . TWebhookEncoding::Base64Url->encode('sig'),
		]));
	}

	public function testSigningAnRsaTokenWithoutAKeyIsAConfigurationError()
	{
		$signature = new TJwtWebhookSignature();
		$signature->setAlgorithms('RS256');

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testAnUnreadablePublicKeyIsAConfigurationError()
	{
		$signature = new TJwtWebhookSignature();
		$signature->setAlgorithms('RS256');
		$signature->setPublicKey("-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----");
		$signing = TWebhookEncoding::Base64Url->encode('{"alg":"RS256"}')
			. '.' . TWebhookEncoding::Base64Url->encode('{}');

		$this->expectException(TConfigurationException::class);
		$signature->verify($this->request([
			'Authorization' => 'Bearer ' . $signing . '.' . TWebhookEncoding::Base64Url->encode('sig'),
		]));
	}

	public function testAnUnreadablePrivateKeyIsAConfigurationError()
	{
		$signature = new TJwtWebhookSignature();
		$signature->setAlgorithms('RS256');
		$signature->setPrivateKey("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----");

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testSigningAnEcdsaTokenWithAnRsaKeyIsAConfigurationError()
	{
		$signature = new TJwtWebhookSignature();
		$signature->setAlgorithms('ES256');
		$signature->setPrivateKey(self::$rsa['private']);

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testSigningAnHsTokenWithoutASecretIsAConfigurationError()
	{
		$signature = new TJwtWebhookSignature();

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testAnUnknownBodyHashAlgorithmIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TJwtWebhookSignature())->setBodyHashAlgorithm('rot13');
	}
}
