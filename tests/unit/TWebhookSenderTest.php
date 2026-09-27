<?php

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookDelivery;
use Belisoful\Prado\Web\Webhooks\TWebhookEndpoint;
use Belisoful\Prado\Web\Webhooks\TWebhookModule;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Belisoful\Prado\Web\Webhooks\TWebhookSender;
use Belisoful\Prado\Web\Webhooks\TWebhookService;
use Belisoful\Prado\Web\Webhooks\TWebhookTarget;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\IO\HttpClient\THttpClient;
use Prado\IO\HttpClient\THttpClientException;
use Prado\IO\HttpClient\THttpClientResponse;

/**
 * A transport that answers from a script and records what it was asked, so the retry policy
 * can be run without a network and without spending the wall clock on backoff.
 */
class TestHttpClient extends THttpClient
{
	/** @var array<int, array{method: string, url: string, headers: array, body: ?string}> */
	public array $requests = [];

	/** @var array<int, THttpClientResponse|Throwable> answers, in order; the last one repeats */
	public array $answers = [];

	public function download(string $method, string $url, array $headers = [], ?string $body = null): THttpClientResponse
	{
		$this->requests[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];

		$answer = count($this->answers) > 1 ? array_shift($this->answers) : ($this->answers[0] ?? null);
		if ($answer instanceof Throwable) {
			throw $answer;
		}

		return $answer ?? new THttpClientResponse(200);
	}
}

/**
 * A sender that records what it would have waited instead of waiting.
 */
class TestWebhookSender extends TWebhookSender
{
	/** @var int[] */
	public array $pauses = [];

	protected function pause(int $milliseconds): void
	{
		$this->pauses[] = $milliseconds;
	}

	/** Exposes the backoff arithmetic, so the overflow case can be checked without 64 requests. */
	public function backoffFor(int $delay, int $attempt): int
	{
		return $this->backoff($delay, $attempt);
	}
}

/**
 * Stands in for THttpResponse on the receiving end of a replayed delivery.
 */
class TestReplayResponse
{
	public int $statusCode = 200;

	public function setStatusCode($value, $reason = null): void
	{
		$this->statusCode = (int) $value;
	}

	public function appendHeader($value): void
	{
	}

	public function setContentType($value): void
	{
	}

	public function write($value): void
	{
	}
}

/**
 * The inbound service replaying a request the sender made. Only the readers the command
 * line cannot supply are replaced; the posted fields come through the service's own reader
 * of $_POST, which a test fills as PHP would have from the body.
 */
class TestReplayWebhookService extends TWebhookService
{
	public TestReplayResponse $response;

	public function __construct(private TWebhookRequest $_replayed, private string $_serviceParameter)
	{
		$this->response = new TestReplayResponse();
		parent::__construct();
	}

	public function getResponse()
	{
		return $this->response;
	}

	protected function getServiceParameter(): string
	{
		return $this->_serviceParameter;
	}

	protected function getRequestMethod(): string
	{
		return $this->_replayed->getMethod();
	}

	protected function getRequestHeaders(): array
	{
		return $this->_replayed->getHeaders();
	}

	protected function readBody(): string
	{
		return $this->_replayed->getBody();
	}

	protected function getRequestUrl(): string
	{
		return $this->_replayed->getUrl();
	}

	protected function getRemoteAddress(): ?string
	{
		return '192.0.2.1';
	}
}

class TWebhookSenderTest extends PHPUnit\Framework\TestCase
{
	private const URL = 'https://example.com/hooks/prado';

	private TestWebhookSender $_sender;
	private TestHttpClient $_client;

	protected function setUp(): void
	{
		$this->_client = new TestHttpClient();
		$this->_sender = new TestWebhookSender();
		$this->_sender->setHttpClient($this->_client);
	}

	private function answer(...$answers): void
	{
		$this->_client->answers = $answers;
	}

	/** Rebuilds the request the sender made, so a verifier can be pointed at it. */
	private function sent(int $index = 0): TWebhookRequest
	{
		$request = $this->_client->requests[$index];

		return new TWebhookRequest($request['method'], (string) $request['body'], $request['headers'], $request['url']);
	}

	public function testASuccessfulDeliveryIsSentOnce()
	{
		$this->answer(new THttpClientResponse(200));

		$deliveries = $this->_sender->send(self::URL, ['id' => 1], 'invoice.paid');

		$this->assertCount(1, $deliveries);
		$this->assertTrue($deliveries[0]->getSuccessful());
		$this->assertSame(1, $deliveries[0]->getAttempts());
		$this->assertCount(1, $this->_client->requests);
		$this->assertSame([], $this->_sender->pauses);
	}

	public function testTheRequestCarriesThePayloadAndItsHeaders()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_sender->send(self::URL, ['id' => 1], 'invoice.paid');

		$request = $this->_client->requests[0];
		$this->assertSame('POST', $request['method']);
		$this->assertSame(self::URL, $request['url']);
		$this->assertSame('{"id":1}', $request['body']);
		$this->assertSame('application/json', $request['headers']['Content-Type']);
		$this->assertSame('invoice.paid', $request['headers'][TWebhookTarget::DEFAULT_EVENT_HEADER]);
		$this->assertSame(TWebhookSender::getDefaultUserAgent(), $request['headers']['User-Agent']);
	}

	public function testEveryTargetGetsTheSameDeliveryIdOnItsOwnRetries()
	{
		$this->answer(new THttpClientResponse(500), new THttpClientResponse(200));
		$this->_sender->setMaxAttempts(2);

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$header = TWebhookTarget::DEFAULT_DELIVERY_HEADER;
		$this->assertSame($delivery->getID(), $this->_client->requests[0]['headers'][$header]);
		$this->assertSame($delivery->getID(), $this->_client->requests[1]['headers'][$header]);
	}

	public function testDeliveryIdsDifferBetweenDeliveries()
	{
		$this->answer(new THttpClientResponse(200));
		$deliveries = $this->_sender->send([self::URL, 'https://other.example/hook'], ['id' => 1]);

		$this->assertNotSame($deliveries[0]->getID(), $deliveries[1]->getID());
	}

	public function testAServerErrorIsRetriedUntilItSucceeds()
	{
		$this->answer(new THttpClientResponse(503), new THttpClientResponse(200));
		$this->_sender->setMaxAttempts(3);

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertTrue($delivery->getSuccessful());
		$this->assertSame(2, $delivery->getAttempts());
		$this->assertCount(2, $this->_client->requests);
	}

	public function testAClientErrorIsNotRetried()
	{
		// The receiver understood the request and refused it; sending it again cannot help.
		$this->answer(new THttpClientResponse(400));
		$this->_sender->setMaxAttempts(5);

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertFalse($delivery->getSuccessful());
		$this->assertSame(1, $delivery->getAttempts());
		$this->assertSame('HTTP 400', $delivery->getStatusText());
	}

	public function testATooManyRequestsIsRetriedEvenThoughItIsAClientError()
	{
		$this->answer(new THttpClientResponse(429), new THttpClientResponse(200));
		$this->_sender->setMaxAttempts(2);

		$this->assertTrue($this->_sender->send(self::URL, ['id' => 1])[0]->getSuccessful());
	}

	public function testRetriesRunOutAndTheDeliveryFails()
	{
		$this->answer(new THttpClientResponse(500));
		$this->_sender->setMaxAttempts(3);

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertFalse($delivery->getSuccessful());
		$this->assertSame(3, $delivery->getAttempts());
		$this->assertCount(3, $this->_client->requests);
	}

	public function testTheBackoffDoublesAndIsNotWaitedAfterTheLastAttempt()
	{
		$this->answer(new THttpClientResponse(500));
		$this->_sender->setMaxAttempts(4);
		$this->_sender->setRetryDelay(100);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame([100, 200, 400], $this->_sender->pauses);
	}

	public function testARetryAfterOverridesTheBackoff()
	{
		$this->answer(
			new THttpClientResponse(429, ['Retry-After' => '2'], ''),
			new THttpClientResponse(200)
		);
		$this->_sender->setMaxAttempts(2);
		$this->_sender->setRetryDelay(100);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame([2000], $this->_sender->pauses);
	}

	public function testAnAbsurdRetryAfterIsCapped()
	{
		$this->answer(new THttpClientResponse(503, ['Retry-After' => '86400'], ''), new THttpClientResponse(200));
		$this->_sender->setMaxAttempts(2);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame([TWebhookSender::MAX_RETRY_AFTER], $this->_sender->pauses);
	}

	public function testAnHttpDateRetryAfterIsHonoredAsTheTimeUntilThen()
	{
		// RFC 9110 §10.2.3 allows a date as well as a number of seconds.
		$this->answer(
			new THttpClientResponse(503, ['Retry-After' => gmdate('D, d M Y H:i:s', time() + 5) . ' GMT'], ''),
			new THttpClientResponse(200)
		);
		$this->_sender->setMaxAttempts(2);
		$this->_sender->setRetryDelay(100);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertCount(1, $this->_sender->pauses);
		// The second may have turned over between the header being written and read.
		$this->assertGreaterThanOrEqual(3000, $this->_sender->pauses[0]);
		$this->assertLessThanOrEqual(5000, $this->_sender->pauses[0]);
	}

	public function testAnHttpDateRetryAfterFarOutIsCapped()
	{
		$this->answer(
			new THttpClientResponse(503, ['Retry-After' => 'Wed, 21 Oct 2099 07:28:00 GMT'], ''),
			new THttpClientResponse(200)
		);
		$this->_sender->setMaxAttempts(2);
		$this->_sender->setMaxRetryDelay(4000);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame([4000], $this->_sender->pauses);
	}

	public function testAnHttpDateRetryAfterAlreadyPastMeansNow()
	{
		$this->answer(
			new THttpClientResponse(503, ['Retry-After' => 'Wed, 21 Oct 2015 07:28:00 GMT'], ''),
			new THttpClientResponse(200)
		);
		$this->_sender->setMaxAttempts(2);
		$this->_sender->setRetryDelay(100);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame([0], $this->_sender->pauses);
	}

	public function testAnUnreadableRetryAfterFallsBackToTheBackoff()
	{
		$this->answer(
			new THttpClientResponse(503, ['Retry-After' => 'soon'], ''),
			new THttpClientResponse(200)
		);
		$this->_sender->setMaxAttempts(2);
		$this->_sender->setRetryDelay(100);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame([100], $this->_sender->pauses);
	}

	public function testANegativeRetryAfterIsNotANegativeWait()
	{
		// A negative wait handed to usleep is an error at best; it must clamp to nothing.
		$this->answer(
			new THttpClientResponse(429, ['Retry-After' => '-5'], ''),
			new THttpClientResponse(200)
		);
		$this->_sender->setMaxAttempts(2);
		$this->_sender->setRetryDelay(100);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame([0], $this->_sender->pauses);
	}

	public function testParseRetryAfterReadsBothFormsAndCapsNothing()
	{
		$sender = new TWebhookSender();
		$sender->setMaxRetryDelay(1000);

		$this->assertSame(2000, $sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => '2'])));
		$this->assertSame(1500, $sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => ' 1.5 '])));
		$this->assertSame(0, $sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => '-1'])));
		$this->assertSame(86400000, $sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => '86400'])), 'uncapped: the cap is the caller\'s');
		$this->assertNull($sender->parseRetryAfter(new THttpClientResponse(429)));
		$this->assertNull($sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => ''])));
		$this->assertNull($sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => 'never'])));

		$future = $sender->parseRetryAfter(
			new THttpClientResponse(429, ['Retry-After' => gmdate('D, d M Y H:i:s', time() + 7200) . ' GMT'])
		);
		$this->assertGreaterThanOrEqual(7199000, $future);
		$this->assertLessThanOrEqual(7200000, $future);
		$this->assertSame(0, $sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => 'Thu, 01 Jan 2015 00:00:00 GMT'])));
	}

	public function testTheBackoffDoesNotOverflowAtHighAttemptCounts()
	{
		// 500 * 2 ** 63 is a float, and (int) of it is 0: the retry that should wait longest
		// used to wait not at all.
		$this->assertSame(TWebhookSender::MAX_RETRY_AFTER, $this->_sender->backoffFor(500, 64));
		$this->assertSame(TWebhookSender::MAX_RETRY_AFTER, $this->_sender->backoffFor(500, 1000));
		$this->assertSame(500, $this->_sender->backoffFor(500, 1));
		$this->assertSame(400, $this->_sender->backoffFor(100, 3));
		$this->assertSame(0, $this->_sender->backoffFor(0, 5), 'no delay stays no delay');
		$this->assertSame(500, $this->_sender->backoffFor(500, 0), 'an attempt below one is treated as the first');
	}

	public function testSixtyFourAttemptsNeverWaitNothingAndNeverWaitPastTheCeiling()
	{
		$this->answer(new THttpClientResponse(500));
		$this->_sender->setMaxAttempts(64);
		$this->_sender->setRetryDelay(1000);
		$this->_sender->setMaxRetryDelay(30000);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertCount(63, $this->_sender->pauses);
		foreach ($this->_sender->pauses as $index => $pause) {
			$this->assertGreaterThan(0, $pause, 'attempt ' . ($index + 1));
			$this->assertLessThanOrEqual(30000, $pause, 'attempt ' . ($index + 1));
		}
		$this->assertSame([1000, 2000, 4000, 8000, 16000, 30000, 30000], array_slice($this->_sender->pauses, 0, 7));
	}

	public function testMaxRetryDelayCapsTheBackoffAndTheRetryAfterAlike()
	{
		$this->answer(
			new THttpClientResponse(500),
			new THttpClientResponse(503, ['Retry-After' => '30'], ''),
			new THttpClientResponse(500),
			new THttpClientResponse(200)
		);
		$this->_sender->setMaxAttempts(4);
		$this->_sender->setRetryDelay(100);
		$this->_sender->setMaxRetryDelay(250);

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame([100, 250, 250], $this->_sender->pauses);
	}

	public function testMaxRetryDelayDefaultsAndIsAtLeastOne()
	{
		$sender = new TWebhookSender();
		$this->assertSame(TWebhookSender::MAX_RETRY_AFTER, $sender->getMaxRetryDelay());

		$sender->setMaxRetryDelay(0);
		$this->assertSame(1, $sender->getMaxRetryDelay());
		$sender->setMaxRetryDelay('2500');
		$this->assertSame(2500, $sender->getMaxRetryDelay());
	}

	public function testABadTargetAnywhereInTheListStopsTheWholeSendBeforeAnyDelivery()
	{
		// Built lazily inside the loop, a bad third specification threw after the first two
		// had been sent -- and their delivery records went with the exception.
		$this->answer(new THttpClientResponse(200));

		try {
			$this->_sender->send([self::URL, 'https://other.example/hook', 42], ['id' => 1]);
			$this->fail('a bad specification should be refused');
		} catch (TConfigurationException $e) {
			$this->assertSame([], $this->_client->requests, 'nothing was sent');
		}
	}

	public function testASubstitutedClientCannotFollowRedirects()
	{
		// Following a 3xx posts the signed body somewhere the subscriber did not name, so the
		// setting is forced off on every delivery rather than trusted on the client.
		$this->_client->setFollowRedirects(true);
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertFalse($this->_client->getFollowRedirects());

		$this->_client->setFollowRedirects(true);
		$this->_sender->send(self::URL, ['id' => 1]);
		$this->assertFalse($this->_client->getFollowRedirects(), 'and again on the next delivery');
	}

	public function testAThrowingDeliveredHandlerPropagatesFromAnInlineSend()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_sender->onDelivered[] = function () {
			throw new RuntimeException('the handler broke');
		};

		$this->assertFalse($this->_sender->getContainHandlerErrors());
		$this->expectException(RuntimeException::class);
		$this->_sender->send(self::URL, ['id' => 1]);
	}

	public function testAThrowingHandlerIsRecordedOnTheDeliveryWhenContained()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_sender->setContainHandlerErrors(true);
		$this->_sender->onDelivered[] = function () {
			throw new RuntimeException('the handler broke');
		};

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertTrue($delivery->getSuccessful(), 'the receiver has it regardless');
		$this->assertSame('the handler broke', $delivery->getHandlerError());
	}

	public function testAThrowingFailedHandlerIsContainedToo()
	{
		$this->answer(new THttpClientResponse(500));
		$this->_sender->setMaxAttempts(1);
		$this->_sender->setContainHandlerErrors(true);
		$this->_sender->onFailed[] = function () {
			throw new LogicException('failed handler broke');
		};

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertFalse($delivery->getSuccessful());
		$this->assertSame('failed handler broke', $delivery->getHandlerError());
	}

	public function testADeliveryWhoseHandlersReturnedHasNoHandlerError()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_sender->setContainHandlerErrors(true);
		$this->_sender->onDelivered[] = function () {
		};

		$this->assertNull($this->_sender->send(self::URL, ['id' => 1])[0]->getHandlerError());
	}

	public function testATransportFailureIsRetriedAndThenReported()
	{
		$this->answer(new THttpClientException('Connection refused'));
		$this->_sender->setMaxAttempts(2);

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertFalse($delivery->getSuccessful());
		$this->assertSame(2, $delivery->getAttempts());
		$this->assertSame('Connection refused', $delivery->getStatusText());
	}

	public function testATransportFailureFollowedByASuccess()
	{
		$this->answer(new THttpClientException('Connection refused'), new THttpClientResponse(200));
		$this->_sender->setMaxAttempts(2);

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertTrue($delivery->getSuccessful());
		$this->assertNull($delivery->getError());
	}

	public function testTheRetryStatusListIsConfigurable()
	{
		$this->answer(new THttpClientResponse(418));
		$this->_sender->setRetryStatusCodes('418, 500');
		$this->_sender->setMaxAttempts(2);

		$this->assertSame([418, 500], $this->_sender->getRetryStatusCodes());
		$this->assertSame(2, $this->_sender->send(self::URL, ['id' => 1])[0]->getAttempts());
	}

	public function testDeliveriesAreSigned()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('per-subscriber');
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send([['url' => self::URL, 'secret' => 'per-subscriber']], ['id' => 1]);

		$this->assertArrayHasKey(THmacWebhookSignature::DEFAULT_HEADER, $this->_client->requests[0]['headers']);
		$this->assertTrue($signature->verify($this->sent()));
	}

	public function testTheSendersSignatureCoversTargetsWithoutOneOfTheirOwn()
	{
		$fallback = new THmacWebhookSignature();
		$fallback->setSecret('shared');
		$this->_sender->setSignature($fallback);
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertTrue($fallback->verify($this->sent()));
	}

	public function testATargetsOwnSignatureWinsOverTheSenders()
	{
		$fallback = new THmacWebhookSignature();
		$fallback->setSecret('shared');
		$this->_sender->setSignature($fallback);
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send([['url' => self::URL, 'secret' => 'per-subscriber']], ['id' => 1]);

		$this->assertFalse($fallback->verify($this->sent()));

		$own = new THmacWebhookSignature();
		$own->setSecret('per-subscriber');
		$this->assertTrue($own->verify($this->sent()));
	}

	public function testEachRetryIsSignedAfresh()
	{
		// A timestamped signature made before a backoff would be stale by the time the retry
		// arrives, so the signature is computed per attempt rather than once.
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$signature->setTimestampHeader('X-Webhook-Timestamp');
		$signature->setPayloadFormat('{timestamp}.{body}');

		$target = TWebhookTarget::ensure(self::URL);
		$target->setSignature($signature);
		$this->answer(new THttpClientResponse(500), new THttpClientResponse(200));
		$this->_sender->setMaxAttempts(2);

		$this->_sender->send($target, ['id' => 1]);

		foreach (array_keys($this->_client->requests) as $index) {
			$this->assertTrue($signature->verify($this->sent($index)));
		}
	}

	/** A Twilio-shaped scheme: SHA-1 over the URL and the sorted posted fields, base64. */
	private function twilio(string $secret = 'twilio-auth-token'): THmacWebhookSignature
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret($secret);
		$signature->setHeader('X-Twilio-Signature');
		$signature->setAlgorithm('sha1');
		$signature->setEncoding('base64');
		$signature->setPayloadFormat('{url}{params}');

		return $signature;
	}

	public function testAFormEncodedDeliverySignedOverItsFieldsVerifiesThroughTheService()
	{
		// What the sender hashes under {params} has to be what a PRADO receiver computes
		// from $_POST: the decoded fields, sorted, and nothing from the query string the
		// URL carries -- that is covered once, through {url}.
		$url = self::URL . '?webhook=twilio';
		$target = TWebhookTarget::ensure(['url' => $url, 'contentType' => 'application/x-www-form-urlencoded']);
		$target->setSignature($this->twilio());
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send($target, ['From' => '+15005550006', 'CallSid' => 'CA123', 'Body' => 'a b']);

		$request = $this->_client->requests[0];
		$this->assertSame('From=%2B15005550006&CallSid=CA123&Body=a+b', $request['body']);
		$expected = base64_encode(hash_hmac('sha1', $url . 'Bodya bCallSidCA123From+15005550006', 'twilio-auth-token', true));
		$this->assertSame($expected, $request['headers']['X-Twilio-Signature']);

		// Replayed through the service, with $_POST holding what PHP parses that body into.
		$saved = $_POST;
		parse_str((string) $request['body'], $_POST);
		try {
			$service = new TestReplayWebhookService($this->sent(), 'twilio');
			$endpoint = new TWebhookEndpoint();
			$endpoint->setID('twilio');
			$endpoint->setRequireJson(false);
			$endpoint->setVerifier($this->twilio());
			$service->addEndpoint($endpoint);
			$accepted = 0;
			$endpoint->onWebhook[] = function () use (&$accepted) {
				$accepted++;
			};

			$service->run();

			$this->assertSame(1, $accepted);
			$this->assertSame(204, $service->response->statusCode);
		} finally {
			$_POST = $saved;
		}
	}

	public function testAJsonDeliveryShowsAParameterSigningSchemeNoFields()
	{
		// A JSON body parses to nothing in a receiver's $_POST, so {params} is empty there
		// and is empty here.
		$this->_sender->setSignature($this->twilio());
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send(self::URL, ['From' => '+15005550006']);

		$expected = base64_encode(hash_hmac('sha1', self::URL, 'twilio-auth-token', true));
		$this->assertSame($expected, $this->_client->requests[0]['headers']['X-Twilio-Signature']);
	}

	public function testARewrittenFormBodyIsSignedOverItsNewFieldsAndNestedOnesAreSkipped()
	{
		// The fields are decoded from the body as it will be sent, after any handler has
		// rewritten it; a nested field is skipped, as the receiving side skips it.
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$signature->setHeader('X-Signature');
		$signature->setPayloadFormat('{params}');
		$target = TWebhookTarget::ensure(['url' => self::URL, 'contentType' => 'application/x-www-form-urlencoded']);
		$target->setSignature($signature);
		$this->answer(new THttpClientResponse(200));
		$this->_sender->onSending[] = function ($sender, TWebhookDelivery $delivery) {
			$delivery->setBody('b=2&a=1&n%5Bx%5D=3');
		};

		$this->_sender->send($target, ['id' => 1]);

		$this->assertSame('b=2&a=1&n%5Bx%5D=3', $this->_client->requests[0]['body']);
		$this->assertSame(hash_hmac('sha256', 'a1b2', 's3cret'), $this->_client->requests[0]['headers']['X-Signature']);
	}

	public function testTheContentTypeActuallySentDecidesWhetherTheBodyIsAForm()
	{
		// A target's own Content-Type header replaces the default, and that is the header
		// the receiver's PHP parses by; a handler that drops the header leaves the target's
		// content type to decide.
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$signature->setHeader('X-Signature');
		$signature->setPayloadFormat('{params}');
		$target = TWebhookTarget::ensure([
			'url' => self::URL,
			'headers' => ['content-type' => 'application/x-www-form-urlencoded; charset=utf-8'],
		]);
		$target->setSignature($signature);
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send($target, 'a=1&b=2');

		$this->assertSame(hash_hmac('sha256', 'a1b2', 's3cret'), $this->_client->requests[0]['headers']['X-Signature']);

		$this->_sender->onSending[] = function ($sender, TWebhookDelivery $delivery) {
			$headers = $delivery->getHeaders();
			unset($headers['content-type']);
			$delivery->setHeaders($headers);
		};
		$this->_sender->send($target, 'a=1&b=2');

		$this->assertArrayNotHasKey('content-type', $this->_client->requests[1]['headers']);
		$this->assertSame(hash_hmac('sha256', '', 's3cret'), $this->_client->requests[1]['headers']['X-Signature']);
	}

	public function testAnEmptyFormBodyHasNoFields()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$signature->setHeader('X-Signature');
		$signature->setPayloadFormat('{params}');
		$target = TWebhookTarget::ensure(['url' => self::URL, 'contentType' => 'application/x-www-form-urlencoded']);
		$target->setSignature($signature);
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send($target, []);

		$this->assertSame('', $this->_client->requests[0]['body']);
		$this->assertSame(hash_hmac('sha256', '', 's3cret'), $this->_client->requests[0]['headers']['X-Signature']);
	}

	public function testAFormBodyPastTheInputLimitIsSignedOverNoFields()
	{
		// parse_str warns past max_input_vars and the framework turns the warning into an
		// exception; a receiver truncates such a body at the same limit, so the delivery
		// could not verify there in any case.
		$limit = (int) ini_get('max_input_vars');
		$this->assertGreaterThan(0, $limit, 'the test needs a max_input_vars limit to exceed');
		$fields = [];
		for ($i = 0; $i <= $limit; $i++) {
			$fields["p$i"] = '1';
		}
		$target = TWebhookTarget::ensure(['url' => self::URL, 'contentType' => 'application/x-www-form-urlencoded']);
		$target->setSignature($this->twilio());
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send($target, $fields);

		$expected = base64_encode(hash_hmac('sha1', self::URL, 'twilio-auth-token', true));
		$this->assertSame($expected, $this->_client->requests[0]['headers']['X-Twilio-Signature']);
	}

	public function testEventsAreRaisedForADeliveryThatSucceeds()
	{
		$this->answer(new THttpClientResponse(200));
		$seen = [];
		foreach (['onSending', 'onDelivered', 'onFailed'] as $event) {
			$this->_sender->attachEventHandler($event, function ($sender, $delivery) use (&$seen, $event) {
				$seen[] = $event;
			});
		}

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame(['onSending', 'onDelivered'], $seen);
	}

	public function testEventsAreRaisedForADeliveryThatFails()
	{
		$this->answer(new THttpClientResponse(500));
		$this->_sender->setMaxAttempts(1);
		$seen = [];
		foreach (['onSending', 'onDelivered', 'onFailed'] as $event) {
			$this->_sender->attachEventHandler($event, function ($sender, $delivery) use (&$seen, $event) {
				$seen[] = $event;
			});
		}

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame(['onSending', 'onFailed'], $seen);
	}

	public function testAHandlerMayAddHeadersBeforeSending()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_sender->onSending[] = function ($sender, TWebhookDelivery $delivery) {
			$delivery->setHeaders($delivery->getHeaders() + ['X-Tenant' => '7']);
		};

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame('7', $this->_client->requests[0]['headers']['X-Tenant']);
	}

	public function testAHandlerMayRewriteTheBodyAndTheSignatureFollowsIt()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$this->answer(new THttpClientResponse(200));
		$this->_sender->setSignature($signature);
		$this->_sender->onSending[] = function ($sender, TWebhookDelivery $delivery) {
			$delivery->setBody('{"rewritten":true}');
		};

		$this->_sender->send(self::URL, ['id' => 1]);

		$this->assertSame('{"rewritten":true}', $this->_client->requests[0]['body']);
		$this->assertTrue($signature->verify($this->sent()));
	}

	public function testACancelledDeliveryIsReturnedWithNoAttempts()
	{
		$this->_sender->onSending[] = function ($sender, TWebhookDelivery $delivery) {
			$delivery->setCancel(true);
		};

		$deliveries = $this->_sender->send(self::URL, ['id' => 1]);

		$this->assertCount(1, $deliveries);
		$this->assertSame(0, $deliveries[0]->getAttempts());
		$this->assertSame([], $this->_client->requests);
	}

	public function testADisabledTargetProducesNoDelivery()
	{
		$deliveries = $this->_sender->send([['url' => self::URL, 'enabled' => false]], ['id' => 1]);

		$this->assertSame([], $deliveries);
		$this->assertSame([], $this->_client->requests);
	}

	public function testATargetThatDidNotSubscribeToTheEventIsSkipped()
	{
		$this->answer(new THttpClientResponse(200));
		$deliveries = $this->_sender->send([
			['url' => self::URL, 'events' => ['invoice.paid']],
			['url' => 'https://other.example/hook', 'events' => ['invoice.failed']],
			'https://everything.example/hook',
		], ['id' => 1], 'invoice.paid');

		$this->assertCount(2, $deliveries);
		$this->assertSame(self::URL, $deliveries[0]->getTarget()->getUrl());
		$this->assertSame('https://everything.example/hook', $deliveries[1]->getTarget()->getUrl());
	}

	public function testOneTargetNeedNotBeWrappedInAnArray()
	{
		$this->answer(new THttpClientResponse(200));
		$target = TWebhookTarget::ensure(self::URL);

		$this->assertCount(1, $this->_sender->send($target, ['id' => 1]));
		$this->assertCount(1, $this->_sender->send(self::URL, ['id' => 1]));
	}

	public function testAStringPayloadIsSentAsGiven()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_sender->send(self::URL, '<xml/>');

		$this->assertSame('<xml/>', $this->_client->requests[0]['body']);
	}

	public function testAFormContentTypeEncodesAsAForm()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_sender->send(
			[['url' => self::URL, 'contentType' => 'application/x-www-form-urlencoded']],
			['id' => 1, 'name' => 'a b']
		);

		$this->assertSame('id=1&name=a+b', $this->_client->requests[0]['body']);
	}

	public function testAPayloadThatCannotBeEncodedIsRefused()
	{
		$this->expectException(TInvalidDataValueException::class);
		$this->_sender->send(self::URL, ['bad' => fopen('php://memory', 'r')]);
	}

	public function testTheTargetsOwnLimitsOverrideTheSenders()
	{
		$this->answer(new THttpClientResponse(500));
		$this->_sender->setMaxAttempts(5);
		$this->_sender->setRetryDelay(1000);

		$delivery = $this->_sender->send(
			[['url' => self::URL, 'maxAttempts' => 2, 'retryDelay' => 10]],
			['id' => 1]
		)[0];

		$this->assertSame(2, $delivery->getAttempts());
		$this->assertSame([10], $this->_sender->pauses);
	}

	public function testTheSignedDeliveryIdIsTheDeliveryIdOnEveryAttempt()
	{
		// A scheme left to itself mints a fresh id per call, and a receiver deduplicating on
		// it would count one retried delivery as several.
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$signature->setIdHeader('webhook-id');
		$signature->setPayloadFormat('{id}.{body}');
		$this->_sender->setSignature($signature);
		$this->_sender->setMaxAttempts(3);
		$this->answer(new THttpClientResponse(500), new THttpClientResponse(500), new THttpClientResponse(200));

		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertCount(3, $this->_client->requests);
		foreach ($this->_client->requests as $index => $request) {
			$this->assertSame($delivery->getID(), $request['headers']['webhook-id'], 'attempt ' . ($index + 1));
			$this->assertTrue($signature->verify($this->sent($index)));
		}
	}

	public function testATargetsOwnIdHeaderIsNotOverwritten()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$signature->setIdHeader('webhook-id');
		$this->answer(new THttpClientResponse(200));

		$this->_sender->send(
			[['url' => self::URL, 'secret' => 's3cret', 'headers' => ['webhook-id' => 'chosen-by-the-app']]],
			['id' => 1]
		);

		$this->assertSame('chosen-by-the-app', $this->_client->requests[0]['headers']['webhook-id']);
	}

	public function testAFormContentTypeNeedsSomethingItCanEncode()
	{
		$this->expectException(TInvalidDataValueException::class);
		$this->_sender->send([['url' => self::URL, 'contentType' => 'application/x-www-form-urlencoded']], 42);
	}

	public function testADeliveryRecordsHowLongItTook()
	{
		$this->answer(new THttpClientResponse(200));
		$delivery = $this->_sender->send(self::URL, ['id' => 1])[0];

		$this->assertGreaterThan(0.0, $delivery->getDuration());
	}

	public function testTheDefaultPauseActuallyWaits()
	{
		// TestWebhookSender overrides pause() everywhere else, so the real one is exercised
		// here rather than never.
		$sender = new TWebhookSender();
		$sender->setHttpClient($this->_client);
		$sender->setMaxAttempts(2);
		$sender->setRetryDelay(20);
		$this->answer(new THttpClientResponse(500), new THttpClientResponse(200));

		$started = microtime(true);
		$sender->send(self::URL, ['id' => 1]);

		$this->assertGreaterThanOrEqual(0.015, microtime(true) - $started);
	}

	public function testDefaults()
	{
		$sender = new TWebhookSender();

		$this->assertSame(10, $sender->getTimeout());
		$this->assertSame(3, $sender->getMaxAttempts());
		$this->assertSame(500, $sender->getRetryDelay());
		$this->assertSame(TWebhookSender::DEFAULT_RETRY_STATUS_CODES, $sender->getRetryStatusCodes());
		$this->assertSame(TWebhookSender::getDefaultUserAgent(), $sender->getUserAgent());
		$this->assertNull($sender->getSignature());
	}

	public function testTheDefaultTransportIsBuiltOnDemandAndDoesNotFollowRedirects()
	{
		// A 3xx from a webhook URL is a misconfiguration, and following one would post the
		// signed body somewhere the subscriber did not name.
		$sender = new TWebhookSender();
		$client = $sender->getHttpClient();

		$this->assertInstanceOf(THttpClient::class, $client);
		$this->assertFalse($client->getFollowRedirects());
		$this->assertSame($client, $sender->getHttpClient());
	}

	public function testTheDefaultUserAgentCarriesTheRunningVersion()
	{
		// Computed rather than written down, so a release cannot leave a stale number in a
		// header that receivers log.
		$this->assertSame(
			TWebhookSender::USER_AGENT_PRODUCT . '/' . TWebhookModule::getVersion(),
			TWebhookSender::getDefaultUserAgent()
		);
		$this->assertStringStartsWith(TWebhookSender::USER_AGENT_PRODUCT . '/', (new TWebhookSender())->getUserAgent());
	}

	public function testTheUserAgentGoesBackToTheDefaultWhenCleared()
	{
		$sender = new TWebhookSender();
		$sender->setUserAgent('MyApp/2.0');
		$this->assertSame('MyApp/2.0', $sender->getUserAgent());

		$sender->setUserAgent('');
		$this->assertSame(TWebhookSender::getDefaultUserAgent(), $sender->getUserAgent());

		$sender->setUserAgent('MyApp/2.0');
		$sender->setUserAgent(null);
		$this->assertSame(TWebhookSender::getDefaultUserAgent(), $sender->getUserAgent());
	}

	public function testMaxAttemptsIsAtLeastOne()
	{
		$sender = new TWebhookSender();
		$sender->setMaxAttempts(0);

		$this->assertSame(1, $sender->getMaxAttempts());
	}

	public function testARetryAfterPastTheIntegerRangeSaturatesRatherThanWrappingToZero()
	{
		// (int) of a float outside the range is platform-defined -- 0 on x86-64 -- which
		// would turn "wait forever" into "retry now".
		$sender = new TWebhookSender();

		$this->assertSame(PHP_INT_MAX, $sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => '9223372036854775807'])));
		$this->assertSame(PHP_INT_MAX, $sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => '1e30'])));
		$this->assertSame(4000000000000000000, $sender->parseRetryAfter(new THttpClientResponse(429, ['Retry-After' => '4000000000000000'])));
	}

	public function testATargetsOwnUserAgentIsNotSentTwiceInAnotherCase()
	{
		$this->answer(new THttpClientResponse(200));
		$this->_sender->send([['url' => self::URL, 'headers' => ['user-agent' => 'Mine/1']]], ['id' => 1]);

		$names = array_filter(
			array_keys($this->_client->requests[0]['headers']),
			static fn ($name) => strcasecmp($name, 'User-Agent') === 0
		);
		$this->assertSame(['user-agent'], array_values($names));
		$this->assertSame('Mine/1', $this->_client->requests[0]['headers']['user-agent']);
	}
}
