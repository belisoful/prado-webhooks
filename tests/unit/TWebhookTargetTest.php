<?php

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\TTokenWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookTarget;
use Prado\Exceptions\TConfigurationException;

class TWebhookTargetTest extends PHPUnit\Framework\TestCase
{
	private const URL = 'https://example.com/hooks/prado';

	protected function tearDown(): void
	{
		TWebhookTarget::setUrlValidator(null);
	}

	public function testATargetPassesThroughEnsureUnchanged()
	{
		$target = new TWebhookTarget();
		$target->setUrl(self::URL);

		$this->assertSame($target, TWebhookTarget::ensure($target));
	}

	public function testAStringIsAUrl()
	{
		$this->assertSame(self::URL, TWebhookTarget::ensure(self::URL)->getUrl());
	}

	public function testAnArraySetsPropertiesByName()
	{
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'events' => ['invoice.paid'],
			'timeout' => 4,
			'data' => 42,
		]);

		$this->assertSame(self::URL, $target->getUrl());
		$this->assertSame(['invoice.paid'], $target->getEvents());
		$this->assertSame(4, $target->getTimeout());
		$this->assertSame(42, $target->getData());
	}

	public function testSecretIsShorthandForAnHmacSignature()
	{
		// The shape an application's own subscription row most often has.
		$target = TWebhookTarget::ensure(['url' => self::URL, 'secret' => 'per-subscriber']);

		$signature = $target->getSignature();
		$this->assertInstanceOf(THmacWebhookSignature::class, $signature);
		$this->assertSame('per-subscriber', $signature->getSecret());
	}

	public function testASignerCanBeGivenDirectly()
	{
		$signer = new TTokenWebhookSignature();
		$signer->setToken('t');
		$target = TWebhookTarget::ensure(['url' => self::URL, 'signature' => $signer]);

		$this->assertSame($signer, $target->getSignature());
	}

	public function testAnArrayWithoutAUrlIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		TWebhookTarget::ensure(['events' => ['a']]);
	}

	public function testSomethingElseEntirelyIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		TWebhookTarget::ensure(42);
	}

	public function testOnlyAbsoluteHttpUrlsAreAccepted()
	{
		foreach (['/hooks/prado', 'example.com/hook', 'ftp://example.com/hook', '', 'javascript:alert(1)'] as $url) {
			try {
				TWebhookTarget::ensure($url);
				$this->fail("'{$url}' should not be a usable webhook URL");
			} catch (TConfigurationException $e) {
				$this->assertStringContainsString('http', $e->getMessage());
			}
		}
		$this->assertSame('http://example.com/hook', TWebhookTarget::ensure('http://example.com/hook')->getUrl());
	}

	public function testATargetWithNoFilterWantsEveryEvent()
	{
		$target = TWebhookTarget::ensure(self::URL);

		$this->assertNull($target->getEvents());
		$this->assertTrue($target->acceptsEvent('invoice.paid'));
		$this->assertTrue($target->acceptsEvent(null));
	}

	public function testAFilteredTargetWantsOnlyWhatItListed()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'events' => 'invoice.paid, invoice.failed']);

		$this->assertSame(['invoice.paid', 'invoice.failed'], $target->getEvents());
		$this->assertTrue($target->acceptsEvent('invoice.paid'));
		$this->assertFalse($target->acceptsEvent('invoice.refunded'));
	}

	public function testAFilteredTargetWantsNothingFromAnUnnamedSend()
	{
		// A payload with no event cannot be shown to match a subscription, so it is not sent.
		$target = TWebhookTarget::ensure(['url' => self::URL, 'events' => ['invoice.paid']]);

		$this->assertFalse($target->acceptsEvent(null));
	}

	public function testAnEmptyEventListMeansNoFilter()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'events' => ' , ']);

		$this->assertNull($target->getEvents());
		$this->assertTrue($target->acceptsEvent('anything'));
	}

	public function testBuiltHeadersCarryTheContentTypeEventAndDeliveryId()
	{
		$headers = TWebhookTarget::ensure(self::URL)->buildHeaders('invoice.paid', 'abc123');

		$this->assertSame('application/json', $headers['Content-Type']);
		$this->assertSame('invoice.paid', $headers[TWebhookTarget::DEFAULT_EVENT_HEADER]);
		$this->assertSame('abc123', $headers[TWebhookTarget::DEFAULT_DELIVERY_HEADER]);
	}

	public function testAnUnnamedSendCarriesNoEventHeader()
	{
		$headers = TWebhookTarget::ensure(self::URL)->buildHeaders(null, 'abc123');

		$this->assertArrayNotHasKey(TWebhookTarget::DEFAULT_EVENT_HEADER, $headers);
	}

	public function testTheEventAndDeliveryHeadersCanBeRenamedOrSuppressed()
	{
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'eventHeader' => 'X-Stripe-Event',
			'deliveryHeader' => '',
		]);
		$headers = $target->buildHeaders('invoice.paid', 'abc123');

		$this->assertSame('invoice.paid', $headers['X-Stripe-Event']);
		$this->assertArrayNotHasKey(TWebhookTarget::DEFAULT_DELIVERY_HEADER, $headers);
	}

	public function testTheTargetsOwnHeadersWinOverTheDefaults()
	{
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'headers' => ['Content-Type' => 'application/vnd.example+json', 'X-Tenant' => '7'],
		]);
		$headers = $target->buildHeaders(null, 'abc');

		$this->assertSame('application/vnd.example+json', $headers['Content-Type']);
		$this->assertSame('7', $headers['X-Tenant']);
	}

	public function testHeadersCanBeConfiguredAsLines()
	{
		// What an XML attribute can carry.
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'headers' => "X-Tenant: 7\nX-Region: eu-west",
		]);

		$this->assertSame(['X-Tenant' => '7', 'X-Region' => 'eu-west'], $target->getHeaders());
	}

	public function testTheMethodAndContentTypeRoundTrip()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'method' => 'put', 'contentType' => 'text/plain']);

		$this->assertSame('PUT', $target->getMethod());
		$this->assertSame('text/plain', $target->getContentType());
	}

	public function testTheRetryDelayAndEnabledFlagRoundTrip()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'retryDelay' => 250, 'enabled' => '0']);

		$this->assertSame(250, $target->getRetryDelay());
		$this->assertFalse($target->getEnabled());
	}

	public function testAnEventFilterClearsBackToNull()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'events' => ['invoice.paid']]);
		$target->setEvents(null);

		$this->assertNull($target->getEvents());
		$this->assertTrue($target->acceptsEvent(null));
	}

	public function testTheEventAndDeliveryHeaderNamesAreReadable()
	{
		$target = TWebhookTarget::ensure(self::URL);

		$this->assertSame(TWebhookTarget::DEFAULT_EVENT_HEADER, $target->getEventHeader());
		$this->assertSame(TWebhookTarget::DEFAULT_DELIVERY_HEADER, $target->getDeliveryHeader());
	}

	public function testDefaults()
	{
		$target = TWebhookTarget::ensure(self::URL);

		$this->assertSame('POST', $target->getMethod());
		$this->assertSame('application/json', $target->getContentType());
		$this->assertSame([], $target->getHeaders());
		$this->assertNull($target->getSignature());
		$this->assertTrue($target->getEnabled());
		$this->assertNull($target->getData());
		// Zero everywhere the sender's own setting is the one that applies.
		$this->assertSame(0, $target->getTimeout());
		$this->assertSame(0, $target->getMaxAttempts());
		$this->assertSame(0, $target->getRetryDelay());
	}

	public function testNegativeOverridesFallBackToTheSenders()
	{
		$target = TWebhookTarget::ensure(['url' => self::URL, 'timeout' => -5, 'maxAttempts' => -1]);

		$this->assertSame(0, $target->getTimeout());
		$this->assertSame(0, $target->getMaxAttempts());
	}

	public function testAnEmptyMethodIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		TWebhookTarget::ensure(['url' => self::URL, 'method' => ' ']);
	}

	public function testABuiltTargetWithoutAUrlIsRefusedByEnsureToo()
	{
		// The object branch used to pass anything through; a target that was never given a
		// URL would then reach the transport as a delivery to nowhere.
		$this->expectException(TConfigurationException::class);
		$this->expectExceptionMessage('Url');
		TWebhookTarget::ensure(new TWebhookTarget());
	}

	public function testAnUnknownKeyIsAConfigurationMistakeThatNamesTheKey()
	{
		try {
			TWebhookTarget::ensure(['url' => self::URL, 'ulr' => 'typo']);
			$this->fail('an unknown key should be refused');
		} catch (TConfigurationException $e) {
			$this->assertStringContainsString("'ulr'", $e->getMessage());
			$this->assertStringContainsString('secret', $e->getMessage(), 'the message says what the keys are');
		}
	}

	public function testAnInvalidUrlIsStillReportedAsSuch()
	{
		// The unknown-key wrapping must not swallow the URL check's own message.
		$this->expectException(TConfigurationException::class);
		$this->expectExceptionMessage('http');
		TWebhookTarget::ensure(['url' => 'not a url']);
	}

	public function testTheTargetsHeadersReplaceTheDefaultsWhateverTheirCase()
	{
		// Header names are case-insensitive; a target's `content-type` beside the default
		// `Content-Type` sent both, and a receiver picked whichever it liked.
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'headers' => ['content-type' => 'application/vnd.example+json', 'x-webhook-event' => 'renamed'],
		]);
		$headers = $target->buildHeaders('invoice.paid', 'abc');

		$this->assertSame('application/vnd.example+json', $headers['content-type']);
		$this->assertArrayNotHasKey('Content-Type', $headers);
		$this->assertSame('renamed', $headers['x-webhook-event']);
		$this->assertArrayNotHasKey(TWebhookTarget::DEFAULT_EVENT_HEADER, $headers);
		$this->assertCount(1, array_filter(array_keys($headers), static fn ($name) => strcasecmp($name, 'Content-Type') === 0));
		$this->assertSame('abc', $headers[TWebhookTarget::DEFAULT_DELIVERY_HEADER], 'untouched headers stay');
	}

	public function testAUrlValidatorThatRefusesMakesTheTargetUnbuildable()
	{
		$seen = [];
		TWebhookTarget::setUrlValidator(static function (string $url) use (&$seen): bool {
			$seen[] = $url;

			return false;
		});

		try {
			TWebhookTarget::ensure(self::URL);
			$this->fail('the validator refused, so the target should not be built');
		} catch (TConfigurationException $e) {
			$this->assertStringContainsString(self::URL, $e->getMessage());
			$this->assertStringContainsString('refused', $e->getMessage());
		}
		$this->assertSame([self::URL], $seen, 'the validator saw the URL once');
	}

	public function testAUrlValidatorThatAcceptsLetsTheUrlBeSet()
	{
		TWebhookTarget::setUrlValidator(static fn (string $url): bool => true);

		$this->assertSame(self::URL, TWebhookTarget::ensure(self::URL)->getUrl());
		$this->assertSame(self::URL, TWebhookTarget::ensure(['url' => self::URL])->getUrl());
	}

	public function testTheValidatorIsNotAskedAboutAUrlThatIsAlreadyInvalid()
	{
		$asked = 0;
		TWebhookTarget::setUrlValidator(static function () use (&$asked): bool {
			$asked++;

			return true;
		});

		try {
			TWebhookTarget::ensure('ftp://example.com/hook');
		} catch (TConfigurationException $e) {
		}
		$this->assertSame(0, $asked);
	}

	public function testNoValidatorChangesNothing()
	{
		$this->assertNull(TWebhookTarget::getUrlValidator());
		$this->assertSame(self::URL, TWebhookTarget::ensure(self::URL)->getUrl());

		$validator = static fn (string $url): bool => false;
		TWebhookTarget::setUrlValidator($validator);
		$this->assertSame($validator, TWebhookTarget::getUrlValidator());

		TWebhookTarget::setUrlValidator(null);
		$this->assertNull(TWebhookTarget::getUrlValidator());
		$this->assertSame(self::URL, TWebhookTarget::ensure(self::URL)->getUrl(), 'accepted again');
	}

	public function testTheDocumentedValidatorRefusesPrivateAndLinkLocalAddresses()
	{
		// The example in the class docblock, run rather than trusted.
		TWebhookTarget::setUrlValidator(static function (string $url): bool {
			$host = trim((string) parse_url($url, PHP_URL_HOST), '[]');
			if (filter_var($host, FILTER_VALIDATE_IP) === false) {
				return true;
			}

			return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
		});

		foreach ([
			'http://127.0.0.1/hook', 'http://127.255.0.9/hook',
			'http://10.0.0.5/hook',
			'http://172.16.0.1/hook', 'http://172.31.255.254/hook',
			'http://192.168.1.1/hook',
			'http://169.254.169.254/latest/meta-data/',
			'http://[::1]/hook',
			'http://[fc00::1]/hook', 'http://[fd12::1]/hook',
			'http://[fe80::1]/hook',
		] as $url) {
			try {
				TWebhookTarget::ensure($url);
				$this->fail("{$url} should be refused");
			} catch (TConfigurationException $e) {
				$this->assertStringContainsString('refused', $e->getMessage(), $url);
			}
		}
		// 2001:db8::/32 is not here: it is the documentation range, which PHP counts as reserved.
		foreach (['http://93.184.216.34/hook', 'http://172.32.0.1/hook', 'http://[2606:4700::1111]/hook', 'https://example.com/hook'] as $url) {
			$this->assertSame($url, TWebhookTarget::ensure($url)->getUrl());
		}
	}

	public function testAnEmptyMethodSaysItIsTheMethodThatIsMissing()
	{
		try {
			TWebhookTarget::ensure(['url' => self::URL, 'method' => '']);
			$this->fail('an empty method should be refused');
		} catch (TConfigurationException $e) {
			$this->assertStringContainsString('Method', $e->getMessage());
			$this->assertStringNotContainsString('at least one', $e->getMessage(), 'not the endpoint\'s message');
		}
	}

	public function testASpecificationCannotReplaceTheUrlValidator()
	{
		// The validator is process-wide; a row that could name it could switch it off for
		// every target built after it.
		$refused = 0;
		TWebhookTarget::setUrlValidator(static function () use (&$refused): bool {
			$refused++;

			return false;
		});
		try {
			foreach (['urlValidator', 'UrlValidator', 'urlvalidator'] as $key) {
				try {
					TWebhookTarget::ensure([$key => 'is_string', 'url' => self::URL]);
					$this->fail("'$key' should be refused");
				} catch (TConfigurationException $e) {
					$this->assertStringContainsString("'$key'", $e->getMessage());
				}
			}
			$this->assertNotSame('is_string', TWebhookTarget::getUrlValidator());

			$this->expectException(TConfigurationException::class);
			TWebhookTarget::ensure(self::URL);
		} finally {
			TWebhookTarget::setUrlValidator(null);
		}
	}
}
