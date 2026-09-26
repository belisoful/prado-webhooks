<?php

use Belisoful\Prado\Web\Webhooks\Signature\TSnsWebhookVerifier;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\IO\HttpClient\THttpClient;
use Prado\IO\HttpClient\THttpClientResponse;

/**
 * Serves the signing certificate the message names.
 */
class TestSnsHttpClient extends THttpClient
{
	public array $urls = [];
	public string $certificate = '';

	public function download(string $method, string $url, array $headers = [], ?string $body = null): THttpClientResponse
	{
		$this->urls[] = $url;

		return new THttpClientResponse(200, [], $this->certificate);
	}
}

class TSnsWebhookVerifierTest extends PHPUnit\Framework\TestCase
{
	private const TOPIC = 'arn:aws:sns:us-east-1:123456789012:my-topic';
	private const CERT_URL = 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem';

	private static string $privateKey;
	private static string $publicKey;

	private TestSnsHttpClient $_client;

	public static function setUpBeforeClass(): void
	{
		$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		openssl_pkey_export($key, $private);
		self::$privateKey = (string) $private;
		self::$publicKey = openssl_pkey_get_details($key)['key'];
	}

	protected function setUp(): void
	{
		$this->_client = new TestSnsHttpClient();
		$this->_client->certificate = self::$publicKey;
	}

	private function verifier(string $topic = self::TOPIC): TSnsWebhookVerifier
	{
		$verifier = new TSnsWebhookVerifier();
		$verifier->setTopicArn($topic);
		$verifier->setHttpClient($this->_client);

		return $verifier;
	}

	/** Builds and signs a message the way SNS does, without going through the class. */
	private function message(array $overrides = [], string $version = '2'): array
	{
		$message = array_merge([
			'Type' => 'Notification',
			'MessageId' => '22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324',
			'TopicArn' => self::TOPIC,
			'Message' => 'Hello from SNS',
			'Timestamp' => gmdate('Y-m-d\TH:i:s.000\Z'),
			'SignatureVersion' => $version,
			'SigningCertURL' => self::CERT_URL,
		], $overrides);

		$fields = TSnsWebhookVerifier::SIGNED_FIELDS[$message['Type']] ?? [];
		$canonical = '';
		foreach ($fields as $field) {
			if (isset($message[$field])) {
				$canonical .= $field . "\n" . $message[$field] . "\n";
			}
		}
		$signature = '';
		openssl_sign($canonical, $signature, self::$privateKey, $version === '1' ? 'sha1' : 'sha256');
		$message['Signature'] = base64_encode($signature);

		return $message;
	}

	private function request(array $message): TWebhookRequest
	{
		return new TWebhookRequest('POST', (string) json_encode($message), ['x-amz-sns-message-type' => $message['Type'] ?? '']);
	}

	public function testVerifiesASignedNotification()
	{
		$this->assertTrue($this->verifier()->verify($this->request($this->message())));
		$this->assertSame([self::CERT_URL], $this->_client->urls);
	}

	public function testTheSubjectIsSignedOnlyWhenTheMessageCarriesIt()
	{
		// The field that breaks a naive implementation: skipped entirely when absent, rather
		// than contributing an empty value.
		$this->assertTrue($this->verifier()->verify($this->request($this->message())));
		$this->assertTrue($this->verifier()->verify($this->request($this->message(['Subject' => 'A subject']))));
	}

	public function testAModifiedFieldIsRejected()
	{
		$message = $this->message();
		$message['Message'] = 'Something else entirely';

		$this->assertFalse($this->verifier()->verify($this->request($message)));
	}

	public function testAddingAnUnsignedFieldDoesNotHelpAnAttacker()
	{
		// Subject is signed, so bolting one on after the fact invalidates the signature.
		$message = $this->message();
		$message['Subject'] = 'injected';

		$this->assertFalse($this->verifier()->verify($this->request($message)));
	}

	public function testAMessageFromAnotherTopicIsRejected()
	{
		// The check that matters: the certificate is Amazon's, so a message from any SNS
		// topic in any AWS account verifies cryptographically.
		$message = $this->message(['TopicArn' => 'arn:aws:sns:us-east-1:999999999999:someone-elses']);

		$this->assertFalse($this->verifier()->verify($this->request($message)));
	}

	public function testSeveralTopicsMayBeAccepted()
	{
		$other = 'arn:aws:sns:eu-west-1:123456789012:another-topic';
		$verifier = $this->verifier(self::TOPIC . ', ' . $other);

		$this->assertSame([self::TOPIC, $other], $verifier->getTopicArns());
		$this->assertTrue($verifier->verify($this->request($this->message(['TopicArn' => $other]))));
	}

	public function testASubscriptionConfirmationSignsDifferentFields()
	{
		$message = $this->message([
			'Type' => 'SubscriptionConfirmation',
			'Token' => 'a-very-long-token',
			'SubscribeURL' => 'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription',
		]);

		$this->assertTrue($this->verifier()->verify($this->request($message)));
	}

	public function testAnUnsubscribeConfirmationVerifies()
	{
		$message = $this->message([
			'Type' => 'UnsubscribeConfirmation',
			'Token' => 'another-token',
			'SubscribeURL' => 'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription',
		]);

		$this->assertTrue($this->verifier()->verify($this->request($message)));
	}

	public function testAnUnknownMessageTypeIsRejected()
	{
		$this->assertFalse($this->verifier()->verify($this->request($this->message(['Type' => 'SomethingNew']))));
		$this->assertNull($this->verifier()->canonicalString(['Type' => 'SomethingNew']));
	}

	public function testABodyThatIsNotJsonIsRejected()
	{
		$this->assertFalse($this->verifier()->verify(new TWebhookRequest('POST', 'not json')));
	}

	public function testSignatureVersionOneUsesSha1()
	{
		$this->assertTrue($this->verifier()->verify($this->request($this->message([], '1'))));
	}

	public function testAVersionOutsideTheAllowListIsRejected()
	{
		// What an application sets once its topic is on SHA-256.
		$verifier = $this->verifier();
		$verifier->setSignatureVersions('2');

		$this->assertTrue($verifier->verify($this->request($this->message([], '2'))));
		$this->assertFalse($verifier->verify($this->request($this->message([], '1'))));
	}

	public function testAnUnknownSignatureVersionIsRejected()
	{
		$message = $this->message();
		$message['SignatureVersion'] = '3';

		$this->assertFalse($this->verifier()->verify($this->request($message)));
	}

	public function testACertificateUrlOutsideAmazonIsNeverFetched()
	{
		$message = $this->message(['SigningCertURL' => 'https://attacker.example.net/key.pem']);

		$this->assertFalse($this->verifier()->verify($this->request($message)));
		$this->assertSame([], $this->_client->urls);
	}

	public function testTheDefaultCertificatePatternAcceptsAnyRegionAndChina()
	{
		foreach ([
			'https://sns.us-east-1.amazonaws.com/cert.pem',
			'https://sns.eu-west-3.amazonaws.com/cert.pem',
			'https://sns.cn-north-1.amazonaws.com.cn/cert.pem',
		] as $url) {
			$this->assertMatchesRegularExpression(
				TSnsWebhookVerifier::DEFAULT_CERTIFICATE_URL_PATTERN,
				$url
			);
		}
		foreach ([
			'http://sns.us-east-1.amazonaws.com/cert.pem',
			'https://sns.us-east-1.amazonaws.com.attacker.net/cert.pem',
			'https://attacker.net/sns.us-east-1.amazonaws.com/cert.pem',
		] as $url) {
			$this->assertDoesNotMatchRegularExpression(
				TSnsWebhookVerifier::DEFAULT_CERTIFICATE_URL_PATTERN,
				$url
			);
		}
	}

	public function testAMessageOlderThanMaxAgeIsRejected()
	{
		$verifier = $this->verifier();
		$verifier->setMaxAge(300);

		$this->assertTrue($verifier->verify($this->request($this->message())));
		$this->assertFalse($verifier->verify($this->request($this->message([
			'Timestamp' => gmdate('Y-m-d\TH:i:s.000\Z', time() - 3600),
		]))));
	}

	public function testMaxAgeIsOffByDefault()
	{
		$message = $this->message(['Timestamp' => gmdate('Y-m-d\TH:i:s.000\Z', time() - 86400)]);

		$this->assertSame(0, $this->verifier()->getMaxAge());
		$this->assertTrue($this->verifier()->verify($this->request($message)));
	}

	public function testAnUnparseableTimestampIsRejectedWhenAgeIsChecked()
	{
		$verifier = $this->verifier();
		$verifier->setMaxAge(300);

		$this->assertFalse($verifier->verify($this->request($this->message(['Timestamp' => 'whenever']))));
	}

	public function testItVerifiesAndDoesNotSign()
	{
		// The signature belongs in the body, and a signer returns headers.
		$this->expectException(TConfigurationException::class);
		$this->verifier()->sign($this->request($this->message()));
	}

	public function testVerifyingWithoutATopicIsAConfigurationError()
	{
		$verifier = new TSnsWebhookVerifier();
		$verifier->setHttpClient($this->_client);

		$this->expectException(TConfigurationException::class);
		$verifier->verify($this->request($this->message()));
	}

	public function testAnEmptyTopicIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TSnsWebhookVerifier())->setTopicArn(' , ');
	}

	public function testAnEmptyOrUnknownSignatureVersionListIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TSnsWebhookVerifier())->setSignatureVersions('3');
	}

	public function testAnEmptySignatureVersionListIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TSnsWebhookVerifier())->setSignatureVersions(' , ');
	}

	public function testDefaults()
	{
		$verifier = new TSnsWebhookVerifier();

		$this->assertSame(['1', '2'], $verifier->getSignatureVersions());
		$this->assertSame('SigningCertURL', $verifier->getCertificateUrlName());
		$this->assertSame(TSnsWebhookVerifier::DEFAULT_CERTIFICATE_URL_PATTERN, $verifier->getCertificateUrlPattern());
		$this->assertSame([], $verifier->getTopicArns());
		$this->assertSame('', $verifier->getTopicArn());
	}

	public function testTheCanonicalStringIsTheDocumentedShape()
	{
		$verifier = $this->verifier();
		$canonical = $verifier->canonicalString([
			'Type' => 'Notification',
			'MessageId' => 'id-1',
			'TopicArn' => self::TOPIC,
			'Message' => 'body',
			'Timestamp' => '2026-09-21T00:00:00.000Z',
		]);

		$this->assertSame(
			"Message\nbody\nMessageId\nid-1\nTimestamp\n2026-09-21T00:00:00.000Z\n"
			. "TopicArn\n" . self::TOPIC . "\nType\nNotification\n",
			$canonical
		);
	}

	// ── Fields of the wrong type ───────────────────────────────────────────────

	/**
	 * The values a JSON body can carry where a string is expected. Each used to reach a
	 * cast, an array offset, or a concatenation that PHP reports, and PRADO turns a
	 * reported warning into an exception -- which the provider sees as a 500.
	 * @return array<string, array{0: mixed}>
	 */
	public static function wrongTypes(): array
	{
		return [
			'a list' => [['2']],
			'an object' => [['version' => '2']],
			'a nested object' => [['a' => ['b' => ['c' => '2']]]],
			'null' => [null],
			'true' => [true],
			'false' => [false],
			'a float' => [2.5],
		];
	}

	/**
	 * @dataProvider wrongTypes
	 * @param mixed $value
	 */
	public function testASignatureVersionOfTheWrongTypeIsRefusedRatherThanRaising(mixed $value)
	{
		$message = $this->message();
		$message['SignatureVersion'] = $value;

		$this->assertFalse($this->verifier()->verify($this->request($message)));
		$this->assertSame([], $this->_client->urls, 'nothing is fetched for a message that cannot be verified');
	}

	public function testAWholeNumberSignatureVersionIsReadAsItsText()
	{
		// A JSON encoder somewhere may write the version as a number; "2" and 2 are the same
		// version, and the canonical string does not include it.
		$message = $this->message();
		$message['SignatureVersion'] = 2;

		$this->assertTrue($this->verifier()->verify($this->request($message)));
	}

	/**
	 * @dataProvider wrongTypes
	 * @param mixed $value
	 */
	public function testASignatureOfTheWrongTypeIsRefused(mixed $value)
	{
		$message = $this->message();
		$message['Signature'] = $value;

		$this->assertFalse($this->verifier()->verify($this->request($message)));
		$this->assertSame([], $this->_client->urls, 'no signature, no fetch');
	}

	/**
	 * @dataProvider wrongTypes
	 * @param mixed $value
	 */
	public function testACertificateUrlOfTheWrongTypeIsRefusedAndNeverFetched(mixed $value)
	{
		$message = $this->message();
		$message['SigningCertURL'] = $value;

		$this->assertFalse($this->verifier()->verify($this->request($message)));
		$this->assertSame([], $this->_client->urls);
	}

	/**
	 * @dataProvider wrongTypes
	 * @param mixed $value
	 */
	public function testATopicArnOfTheWrongTypeIsRefused(mixed $value)
	{
		$message = $this->message();
		$message['TopicArn'] = $value;

		$this->assertFalse($this->verifier()->verify($this->request($message)));
	}

	/**
	 * @dataProvider wrongTypes
	 * @param mixed $value
	 */
	public function testATypeOfTheWrongTypeIsRefusedInVerifyAndInTheCanonicalString(mixed $value)
	{
		$message = $this->message();
		$message['Type'] = $value;

		$this->assertFalse($this->verifier()->verify($this->request($message)));
		// canonicalString() is public, and an array offset of the wrong type is a TypeError.
		$this->assertNull($this->verifier()->canonicalString($message));
	}

	/**
	 * @dataProvider wrongTypes
	 * @param mixed $value
	 */
	public function testATimestampOfTheWrongTypeIsRefusedWhenAgeIsChecked(mixed $value)
	{
		$verifier = $this->verifier();
		$verifier->setMaxAge(300);
		$message = $this->message();
		$message['Timestamp'] = $value;

		$this->assertFalse($verifier->verify($this->request($message)));
	}

	/**
	 * @dataProvider wrongTypes
	 * @param mixed $value
	 */
	public function testACanonicalFieldOfTheWrongTypeIsSkippedNotConcatenated(mixed $value)
	{
		// The signature was made over the real fields, so a message whose Message or
		// Subject has been replaced by a structure does not verify -- and does not raise.
		foreach (['Message', 'MessageId', 'Subject'] as $field) {
			$message = $this->message(['Subject' => 'A subject']);
			$message[$field] = $value;

			$this->assertFalse($this->verifier()->verify($this->request($message)), $field);
			$this->assertIsString($this->verifier()->canonicalString($message), $field . ' still canonicalizes');
		}
	}

	public function testANumericCanonicalFieldContributesItsText()
	{
		$this->assertSame(
			"Message\n42\nMessageId\n7\nType\nNotification\n",
			$this->verifier()->canonicalString(['Type' => 'Notification', 'Message' => 42, 'MessageId' => 7])
		);
		$this->assertSame(
			"Type\nNotification\n",
			$this->verifier()->canonicalString(['Type' => 'Notification', 'Message' => true, 'MessageId' => null, 'Subject' => []])
		);
	}

	public function testAJsonListBodyIsRefused()
	{
		$this->assertFalse($this->verifier()->verify(new TWebhookRequest('POST', '["Notification"]')));
		$this->assertFalse($this->verifier()->verify(new TWebhookRequest('POST', '"Notification"')));
		$this->assertFalse($this->verifier()->verify(new TWebhookRequest('POST', '')));
	}

	// ── The certificate URL shape ──────────────────────────────────────────────

	public function testTheDefaultCertificatePatternRequiresAPemPathAndNoQuery()
	{
		// What Amazon's own validator requires, so nothing SNS sends is refused by it.
		foreach ([
			'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-6aad65c2f9911b05cd53efda11f913f9.pem',
			'https://sns.cn-north-1.amazonaws.com.cn/SimpleNotificationService-abc.pem',
		] as $url) {
			$this->assertMatchesRegularExpression(TSnsWebhookVerifier::DEFAULT_CERTIFICATE_URL_PATTERN, $url, $url);
		}
		foreach ([
			'https://sns.us-east-1.amazonaws.com/cert.pem?x=1',
			'https://sns.us-east-1.amazonaws.com/cert.pem#frag',
			'https://sns.us-east-1.amazonaws.com/cert.txt',
			'https://sns.us-east-1.amazonaws.com/cert.pem.html',
			'https://sns.us-east-1.amazonaws.com/',
			'https://sns.us-east-1.amazonaws.com/.pem',
			'https://sns.us-east-1.amazonaws.com/a?b=c.pem',
			'https://sns.us-east-1.amazonaws.com/cert.PEM',
		] as $url) {
			$this->assertDoesNotMatchRegularExpression(TSnsWebhookVerifier::DEFAULT_CERTIFICATE_URL_PATTERN, $url, $url);
		}
	}

	public function testACertificateUrlThatIsNotAPemPathIsNeverFetched()
	{
		foreach ([
			'https://sns.us-east-1.amazonaws.com/cert.pem?redirect=elsewhere',
			'https://sns.us-east-1.amazonaws.com/index.html',
		] as $url) {
			$this->assertFalse($this->verifier()->verify($this->request($this->message(['SigningCertURL' => $url]))), $url);
		}
		$this->assertSame([], $this->_client->urls);
	}

	public function testAMessageWithNoSignatureNeverFetchesTheCertificate()
	{
		$message = $this->message();
		unset($message['Signature']);
		$this->assertFalse($this->verifier()->verify($this->request($message)));

		$message['Signature'] = '';
		$this->assertFalse($this->verifier()->verify($this->request($message)));

		$this->assertSame([], $this->_client->urls, 'an unsigned body must not cost a network round trip');
	}

	// ── MaxAge ─────────────────────────────────────────────────────────────────

	public function testWithoutMaxAgeAStaleMessageReplaysIndefinitely()
	{
		// Pinned so the default is a documented choice rather than an accident: the
		// timestamp is signed, but nothing bounds it until MaxAge is set.
		$verifier = $this->verifier();
		$this->assertSame(0, $verifier->getMaxAge());

		$stale = $this->message(['Timestamp' => '2016-01-01T00:00:00.000Z']);
		$this->assertTrue($verifier->verify($this->request($stale)));
		$this->assertTrue($verifier->verify($this->request($stale)), 'and again');

		$verifier->setMaxAge(300);
		$this->assertFalse($verifier->verify($this->request($stale)));
	}

	public function testMaxAgeBoundsBothDirections()
	{
		$verifier = $this->verifier();
		$verifier->setMaxAge(60);

		$this->assertTrue($verifier->verify($this->request($this->message())));
		$this->assertFalse($verifier->verify($this->request($this->message([
			'Timestamp' => gmdate('Y-m-d\TH:i:s.000\Z', time() + 3600),
		]))), 'a timestamp from the future is as wrong as a stale one');
		$this->assertFalse($verifier->verify($this->request($this->message([
			'Timestamp' => gmdate('Y-m-d\TH:i:s.000\Z', time() - 61),
		]))));
	}

	public function testAMissingTimestampIsRefusedOnlyWhenAgeIsChecked()
	{
		$message = $this->message();
		unset($message['Timestamp']);
		$unsigned = $this->message(['Timestamp' => null]);
		unset($unsigned['Timestamp']);

		// Re-sign without the field so the signature itself is not what refuses it.
		$fields = TSnsWebhookVerifier::SIGNED_FIELDS['Notification'];
		$canonical = '';
		foreach ($fields as $field) {
			if (isset($message[$field]) && $field !== 'Timestamp') {
				$canonical .= $field . "\n" . $message[$field] . "\n";
			}
		}
		openssl_sign($canonical, $signature, self::$privateKey, 'sha256');
		$message['Signature'] = base64_encode($signature);

		$this->assertTrue($this->verifier()->verify($this->request($message)));

		$verifier = $this->verifier();
		$verifier->setMaxAge(300);
		$this->assertFalse($verifier->verify($this->request($message)));
	}
}
