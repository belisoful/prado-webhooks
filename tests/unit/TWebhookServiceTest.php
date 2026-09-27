<?php

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\TFieldedWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookEndpoint;
use Belisoful\Prado\Web\Webhooks\TWebhookEventParameter;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Belisoful\Prado\Web\Webhooks\TWebhookService;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\Xml\TXmlDocument;

/**
 * Stands in for THttpResponse, which needs a running application to be useful.
 */
class TestWebhookResponse
{
	public int $statusCode = 200;
	public ?string $reason = null;
	public array $appendedHeaders = [];
	public ?string $contentType = null;
	public string $body = '';

	public function setStatusCode($value, $reason = null): void
	{
		$this->statusCode = (int) $value;
		$this->reason = $reason;
	}

	public function appendHeader($value): void
	{
		$this->appendedHeaders[] = $value;
	}

	public function setContentType($value): void
	{
		$this->contentType = $value;
	}

	public function write($value): void
	{
		$this->body .= $value;
	}
}

/**
 * The service with the request and response supplied rather than read from the environment,
 * so a delivery can be replayed from its bytes.
 */
class TestWebhookService extends TWebhookService
{
	public string $serviceParameter = '';
	public string $method = 'POST';
	public string $requestBody = '';
	public array $requestHeaders = [];
	public string $requestUrl = 'https://example.com/index.php';
	public array $requestParameters = [];
	public ?string $remoteAddress = '192.0.2.1';
	public int $bodyReads = 0;
	public TestWebhookResponse $response;

	public function __construct()
	{
		$this->response = new TestWebhookResponse();
		parent::__construct();
	}

	public function getResponse()
	{
		return $this->response;
	}

	protected function getServiceParameter(): string
	{
		return $this->serviceParameter;
	}

	protected function getRequestMethod(): string
	{
		return strtoupper($this->method);
	}

	protected function getRequestHeaders(): array
	{
		return $this->requestHeaders;
	}

	protected function readBody(): string
	{
		$this->bodyReads++;

		return $this->requestBody;
	}

	protected function getRequestUrl(): string
	{
		return $this->requestUrl;
	}

	protected function getRequestParameters(): array
	{
		return $this->requestParameters;
	}

	protected function getRemoteAddress(): ?string
	{
		return $this->remoteAddress;
	}
}

/**
 * Stands in for THttpRequest: the framework's view of the environment, as the service's
 * default readers see it. Only the methods the service calls exist.
 */
class TestFrameworkRequest
{
	public string $serviceParameter = 'github';
	public string $requestType = 'post';
	public array $headers = ['X-GitHub-Event' => 'push'];
	public string $baseUrl = 'https://example.com';
	public string $requestUri = '/index.php?webhook=github&page=1';
	public array $items = ['webhook' => 'github', 'page' => '1', 'nested' => ['a' => 'b']];
	public string $userHostAddress = '192.0.2.7';

	public function getServiceParameter()
	{
		return $this->serviceParameter;
	}

	public function getRequestType()
	{
		return $this->requestType;
	}

	public function getHeaders($case = null)
	{
		return $this->headers;
	}

	public function getBaseUrl()
	{
		return $this->baseUrl;
	}

	public function getRequestUri()
	{
		return $this->requestUri;
	}

	public function toArray()
	{
		return $this->items;
	}

	public function getUserHostAddress()
	{
		return $this->userHostAddress;
	}
}

/**
 * The service with only the framework's request and response replaced, so its own readers
 * of the environment -- the ones TestWebhookService overrides -- are what runs.
 */
class TestEnvironmentWebhookService extends TWebhookService
{
	public TestFrameworkRequest $request;
	public TestWebhookResponse $response;

	public function __construct()
	{
		$this->request = new TestFrameworkRequest();
		$this->response = new TestWebhookResponse();
		parent::__construct();
	}

	public function getRequest()
	{
		return $this->request;
	}

	public function getResponse()
	{
		return $this->response;
	}

	public function buildRequest(bool $withBody = true): TWebhookRequest
	{
		return $this->createWebhookRequest($withBody);
	}

	public function declaredBodySize(): ?int
	{
		return $this->getDeclaredBodySize();
	}
}

class TWebhookServiceTest extends PHPUnit\Framework\TestCase
{
	private TestWebhookService $_service;

	protected function setUp(): void
	{
		$this->_service = new TestWebhookService();
	}

	private function endpoint(string $id): TWebhookEndpoint
	{
		$endpoint = new TWebhookEndpoint();
		$endpoint->setID($id);
		$this->_service->addEndpoint($endpoint);

		return $endpoint;
	}

	private function xml(string $markup): TXmlDocument
	{
		$document = new TXmlDocument();
		$document->loadFromString($markup);

		return $document;
	}

	public function testTheConventionalServiceIdIsSingular()
	{
		// It is the URL's parameter name -- index.php?webhook=github -- and one delivery
		// reaches one endpoint, so the plural would be describing the configuration rather
		// than the request.
		$this->assertSame('webhook', TWebhookService::SERVICE_ID);
		$this->assertSame('endpoint', TWebhookService::ENDPOINT_TAG);
	}

	public function testAnEndpointIsReachedByItsId()
	{
		$github = $this->endpoint('github');
		$this->endpoint('stripe');
		$seen = [];
		$github->onWebhook[] = function ($sender, $param) use (&$seen) {
			$seen[] = $param;
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = '{"action":"opened"}';
		$this->_service->run();

		$this->assertCount(1, $seen);
		$this->assertSame(204, $this->_service->response->statusCode);
	}

	public function testAnUnknownIdIsFourOhFourAndReachesNoEndpoint()
	{
		$github = $this->endpoint('github');
		$seen = [];
		$github->onWebhook[] = function () use (&$seen) {
			$seen[] = true;
		};

		$this->_service->serviceParameter = 'gitlab';
		$this->_service->run();

		$this->assertSame(404, $this->_service->response->statusCode);
		$this->assertSame([], $seen);
	}

	public function testADisabledEndpointIsIndistinguishableFromAnAbsentOne()
	{
		// Deliberate: a caller must not be able to enumerate endpoints by their status.
		$this->endpoint('github')->setEnabled(false);

		$this->_service->serviceParameter = 'github';
		$this->_service->run();

		$this->assertSame(404, $this->_service->response->statusCode);
	}

	public function testTheOnlyEndpointAnswersABareUrl()
	{
		$this->endpoint('github');

		$this->_service->serviceParameter = '';
		$this->_service->requestBody = '{}';
		$this->_service->run();

		$this->assertSame(204, $this->_service->response->statusCode);
	}

	public function testWithSeveralEndpointsABareUrlNeedsADefault()
	{
		$this->endpoint('github');
		$this->endpoint('stripe');

		$this->_service->serviceParameter = '';
		$this->_service->run();
		$this->assertSame(404, $this->_service->response->statusCode);

		$this->_service->setDefaultEndpoint('stripe');
		$this->_service->requestBody = '{}';
		$this->_service->run();
		$this->assertSame(204, $this->_service->response->statusCode);
	}

	public function testTheServiceEventSeesEveryEndpointsDeliveries()
	{
		$this->endpoint('github');
		$this->endpoint('stripe');
		$seen = [];
		$this->_service->onWebhook[] = function ($sender, TWebhookEventParameter $param) use (&$seen) {
			$seen[] = $param->getEndpoint()->getID();
		};

		$this->_service->requestBody = '{}';
		foreach (['github', 'stripe'] as $id) {
			$this->_service->serviceParameter = $id;
			$this->_service->run();
		}

		$this->assertSame(['github', 'stripe'], $seen);
	}

	public function testTheServiceEventRunsAfterTheEndpointsAndMayStillChangeTheResponse()
	{
		$endpoint = $this->endpoint('github');
		$order = [];
		$endpoint->onWebhook[] = function ($sender, $param) use (&$order) {
			$order[] = 'endpoint';
			$param->setStatusCode(200);
		};
		$this->_service->onWebhook[] = function ($sender, $param) use (&$order) {
			$order[] = 'service';
			$param->setStatusCode(202);
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = '{}';
		$this->_service->run();

		$this->assertSame(['endpoint', 'service'], $order);
		$this->assertSame(202, $this->_service->response->statusCode);
	}

	public function testARefusedMethodAnswersWithAnAllowHeader()
	{
		$this->endpoint('github');

		$this->_service->serviceParameter = 'github';
		$this->_service->method = 'GET';
		$this->_service->run();

		$this->assertSame(405, $this->_service->response->statusCode);
		$this->assertSame(['Allow: POST'], $this->_service->response->appendedHeaders);
	}

	public function testAResponseBodyIsWrittenWithItsContentType()
	{
		$this->endpoint('github')->onWebhook[] = function ($sender, $param) {
			$param->setStatusCode(200);
			$param->setResponseBody(['ok' => true]);
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = '{}';
		$this->_service->run();

		$this->assertSame(200, $this->_service->response->statusCode);
		$this->assertSame('application/json', $this->_service->response->contentType);
		$this->assertSame('{"ok":true}', $this->_service->response->body);
	}

	public function testNoResponseBodyWritesNothing()
	{
		$this->endpoint('github');

		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = '{}';
		$this->_service->run();

		$this->assertSame('', $this->_service->response->body);
		$this->assertNull($this->_service->response->contentType);
	}

	public function testTheRawBodyAndHeadersReachTheVerifier()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$endpoint = $this->endpoint('github');
		$endpoint->setVerifier($signature);

		$body = '{"action":"opened"}';
		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = $body;
		$this->_service->requestHeaders = $signature->sign(new TWebhookRequest('POST', $body));
		$this->_service->run();

		$this->assertSame(204, $this->_service->response->statusCode);
	}

	public function testAForgedDeliveryIsRefused()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$this->endpoint('github')->setVerifier($signature);

		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = '{"action":"opened"}';
		$this->_service->requestHeaders = [THmacWebhookSignature::DEFAULT_HEADER => 'deadbeef'];
		$this->_service->run();

		$this->assertSame(401, $this->_service->response->statusCode);
	}

	public function testEndpointsAreBuiltFromTheConfiguration()
	{
		$this->_service->init($this->xml(
			'<service id="webhook">'
			. '<endpoint id="github" EventHeader="X-GitHub-Event">'
			. '<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"'
			. ' Secret="s3cret" Header="X-Hub-Signature-256" Prefix="sha256=" />'
			. '</endpoint>'
			. '<endpoint id="stripe" EventProperty="type" SuccessStatus="200" />'
			. '</service>'
		));

		$this->assertSame(['github', 'stripe'], array_keys($this->_service->getEndpoints()));

		$github = $this->_service->getEndpoint('github');
		$this->assertSame('github', $github->getID());
		$this->assertSame('X-GitHub-Event', $github->getEventHeader());
		$this->assertInstanceOf(THmacWebhookSignature::class, $github->getVerifier());

		$stripe = $this->_service->getEndpoint('stripe');
		$this->assertSame('type', $stripe->getEventProperty());
		$this->assertSame(200, $stripe->getSuccessStatus());
		$this->assertNull($stripe->getVerifier());
	}

	public function testAConfiguredEndpointAnswersEndToEnd()
	{
		$this->_service->init($this->xml(
			'<service id="webhook">'
			. '<endpoint id="github" EventHeader="X-GitHub-Event">'
			. '<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"'
			. ' Secret="s3cret" Header="X-Hub-Signature-256" Prefix="sha256=" />'
			. '</endpoint>'
			. '</service>'
		));
		$seen = [];
		$this->_service->getEndpoint('github')->onWebhook[] = function ($sender, $param) use (&$seen) {
			$seen[] = $param->getEvent();
		};

		$body = '{"action":"opened"}';
		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = $body;
		$this->_service->requestHeaders = [
			'X-GitHub-Event' => 'pull_request',
			'X-Hub-Signature-256' => 'sha256=' . hash_hmac('sha256', $body, 's3cret'),
		];
		$this->_service->run();

		$this->assertSame(['pull_request'], $seen);
		$this->assertSame(204, $this->_service->response->statusCode);
	}

	public function testEndpointsAreBuiltFromAPhpConfiguration()
	{
		// The other form an application configuration takes; both have to produce the same thing.
		$this->_service->init([
			'class' => TWebhookService::class,
			'endpoint' => [
				'github' => [
					'properties' => ['EventHeader' => 'X-GitHub-Event'],
					'signature' => [
						'class' => THmacWebhookSignature::class,
						'properties' => ['Secret' => 's3cret', 'Header' => 'X-Hub-Signature-256', 'Prefix' => 'sha256='],
					],
				],
				'stripe' => [],
			],
		]);

		$this->assertSame(['github', 'stripe'], array_keys($this->_service->getEndpoints()));

		$github = $this->_service->getEndpoint('github');
		$this->assertSame('X-GitHub-Event', $github->getEventHeader());
		$signature = $github->getVerifier();
		$this->assertInstanceOf(THmacWebhookSignature::class, $signature);
		$this->assertSame('s3cret', $signature->getSecret());
		$this->assertSame('sha256=', $signature->getPrefix());
		$this->assertNull($this->_service->getEndpoint('stripe')->getVerifier());
	}

	public function testAPhpConfiguredEndpointAnswersEndToEnd()
	{
		$this->_service->init([
			'endpoint' => [
				'stripe' => [
					'properties' => ['EventProperty' => 'type'],
					'signature' => [
						'class' => TFieldedWebhookSignature::class,
						'properties' => ['Secret' => 'whsec_x'],
					],
				],
			],
		]);
		$seen = [];
		$this->_service->getEndpoint('stripe')->onWebhook[] = function ($sender, $param) use (&$seen) {
			$seen[] = $param->getEvent();
		};

		$signature = new TFieldedWebhookSignature();
		$signature->setSecret('whsec_x');
		$body = '{"id":"evt_1","type":"invoice.paid"}';

		$this->_service->serviceParameter = 'stripe';
		$this->_service->requestBody = $body;
		$this->_service->requestHeaders = $signature->sign(new TWebhookRequest('POST', $body));
		$this->_service->run();

		$this->assertSame(['invoice.paid'], $seen);
		$this->assertSame(204, $this->_service->response->statusCode);
	}

	public function testAConfigurationWithNoWebhooksBuildsNoEndpoints()
	{
		$this->_service->init(['endpoint' => []]);
		$this->assertSame([], $this->_service->getEndpoints());

		$this->_service->init(null);
		$this->assertSame([], $this->_service->getEndpoints());
	}

	public function testAnEndpointClassOfItsOwnIsHonored()
	{
		$this->_service->init($this->xml(
			'<service id="webhook">'
			. '<endpoint id="github" class="Belisoful\Prado\Web\Webhooks\TWebhookEndpoint" RequireJson="false" />'
			. '</service>'
		));

		$this->assertFalse($this->_service->getEndpoint('github')->getRequireJson());
	}

	public function testAnEndpointWithoutAnIdIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		$this->_service->init($this->xml('<service id="webhook"><endpoint /></service>'));
	}

	public function testAnEndpointClassThatIsNotAnEndpointIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		$this->_service->init($this->xml(
			'<service id="webhook"><endpoint id="x" class="Prado\TComponent" /></service>'
		));
	}

	public function testTwoEndpointsCannotShareAnId()
	{
		$this->endpoint('github');

		$this->expectException(TConfigurationException::class);
		$this->endpoint('github');
	}

	public function testAnEndpointNeedsAnIdToBeAdded()
	{
		$this->expectException(TConfigurationException::class);
		$this->_service->addEndpoint(new TWebhookEndpoint());
	}

	public function testAnAbsentEndpointIsNull()
	{
		$this->assertNull($this->_service->getEndpoint('nothing'));
		$this->assertSame([], $this->_service->getEndpoints());
	}

	public function testTheDefaultEndpointClearsBackToNull()
	{
		$this->_service->setDefaultEndpoint('github');
		$this->assertSame('github', $this->_service->getDefaultEndpoint());

		$this->_service->setDefaultEndpoint('');
		$this->assertNull($this->_service->getDefaultEndpoint());
	}

	public function testTheServiceEventIsSilentForARefusedDelivery()
	{
		// The documented contract is "once per verified delivery"; a handler written to it
		// would otherwise act on a forged payload, and could overwrite the 401 with a 2xx.
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$this->endpoint('github')->setVerifier($signature);
		$accepted = [];
		$refused = [];
		$this->_service->onWebhook[] = function ($sender, TWebhookEventParameter $param) use (&$accepted) {
			$accepted[] = $param->getStatusCode();
		};
		$this->_service->onRefused[] = function ($sender, TWebhookEventParameter $param) use (&$refused) {
			$refused[] = [$param->getStatusCode(), $param->getPayloadDecoded(), $param->getAccepted()];
		};
		$this->_service->serviceParameter = 'github';

		$this->_service->requestBody = '{"action":"opened"}';
		$this->_service->requestHeaders = [THmacWebhookSignature::DEFAULT_HEADER => 'deadbeef'];
		$this->_service->run();
		$this->assertSame(401, $this->_service->response->statusCode);

		$this->_service->method = 'GET';
		$this->_service->run();
		$this->assertSame(405, $this->_service->response->statusCode);
		$this->_service->method = 'POST';

		$this->_service->getEndpoint('github')->setMaxBodySize(4);
		$this->_service->requestHeaders = $signature->sign(new TWebhookRequest('POST', '{"action":"opened"}'));
		$this->_service->run();
		$this->assertSame(413, $this->_service->response->statusCode);
		$this->_service->getEndpoint('github')->setMaxBodySize(0);

		$this->_service->requestBody = 'not json';
		$this->_service->requestHeaders = $signature->sign(new TWebhookRequest('POST', 'not json'));
		$this->_service->run();
		$this->assertSame(400, $this->_service->response->statusCode);

		$this->assertSame([], $accepted);
		$this->assertSame([[401, false, false], [405, false, false], [413, false, false], [400, true, false]], $refused);
	}

	public function testARefusalHandlerCannotTurnARefusalIntoASuccess()
	{
		$this->endpoint('github');
		$this->_service->onRefused[] = function ($sender, TWebhookEventParameter $param) {
			$param->setStatusCode(200);
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->method = 'GET';
		$this->_service->run();

		$this->assertSame(405, $this->_service->response->statusCode);
	}

	public function testARefusalHandlerMayChooseAnotherRefusal()
	{
		$this->endpoint('github');
		$this->_service->onRefused[] = function ($sender, TWebhookEventParameter $param) {
			$param->setStatusCode(429);
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->method = 'GET';
		$this->_service->run();

		$this->assertSame(429, $this->_service->response->statusCode);
	}

	public function testADeclaredOversizedBodyIsRefusedBeforeItIsRead()
	{
		$this->endpoint('github')->setMaxBodySize(10);
		$refused = [];
		$this->_service->onRefused[] = function ($sender, TWebhookEventParameter $param) use (&$refused) {
			$refused[] = $param->getStatusCode();
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->requestHeaders = ['Content-Length' => '11'];
		$this->_service->requestBody = str_repeat('x', 11);
		$this->_service->run();

		$this->assertSame(413, $this->_service->response->statusCode);
		$this->assertSame(0, $this->_service->bodyReads);
		$this->assertSame([413], $refused);
	}

	public function testADeclaredLengthWithinTheLimitIsReadAndAMisdeclaredOneIsCaughtByTheEndpoint()
	{
		$this->endpoint('github')->setMaxBodySize(10);

		$this->_service->serviceParameter = 'github';
		$this->_service->requestHeaders = ['content-length' => '2'];
		$this->_service->requestBody = '{}';
		$this->_service->run();
		$this->assertSame(204, $this->_service->response->statusCode);
		$this->assertSame(1, $this->_service->bodyReads);

		// A liar declares 2 and sends 11: the endpoint's own check still refuses it.
		$this->_service->requestBody = str_repeat('x', 11);
		$this->_service->run();
		$this->assertSame(413, $this->_service->response->statusCode);
	}

	public function testAContentLengthThatIsNotANumberIsIgnored()
	{
		$this->endpoint('github')->setMaxBodySize(10);

		$this->_service->serviceParameter = 'github';
		$this->_service->requestHeaders = ['Content-Length' => 'lots'];
		$this->_service->requestBody = '{}';
		$this->_service->run();

		$this->assertSame(204, $this->_service->response->statusCode);
	}

	public function testABodyOnTheDefaultStatusIsAnsweredAsTwoHundred()
	{
		// A 204 cannot carry a body; a handler that set one meant 200.
		$this->endpoint('github')->onWebhook[] = function ($sender, $param) {
			$param->setResponseBody('queued');
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = '{}';
		$this->_service->run();

		$this->assertSame(200, $this->_service->response->statusCode);
		$this->assertSame('text/plain', $this->_service->response->contentType);
		$this->assertSame('queued', $this->_service->response->body);
	}

	public function testAStatusTheFrameworkHasNoPhraseForIsSentWithOne()
	{
		$this->endpoint('github')->onWebhook[] = function ($sender, $param) {
			$param->setStatusCode(299);
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = '{}';
		$this->_service->run();

		$this->assertSame(299, $this->_service->response->statusCode);
		$this->assertSame(TWebhookService::STATUS_REASON, $this->_service->response->reason);
	}

	public function testAListShapedPhpEndpointConfigurationIsRefused()
	{
		// ['github'] is a list where a map was meant; it would build an open endpoint at ?webhook=0.
		$this->expectException(TConfigurationException::class);
		$this->_service->init(['endpoint' => ['github']]);
	}

	public function testAPhpEndpointThatIsNotAnArrayIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		$this->_service->init(['endpoint' => ['github' => null]]);
	}

	public function testAnEndpointWithAnUnknownChildIsRefusedAtBoot()
	{
		$this->expectException(TConfigurationException::class);
		$this->_service->init($this->xml(
			'<service id="webhook"><endpoint id="github">'
			. '<signatrue class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature" Secret="s" />'
			. '</endpoint></service>'
		));
	}

	public function testRequireVerifierIsHonoredFromTheConfiguration()
	{
		$this->_service->init($this->xml(
			'<service id="webhook"><endpoint id="github" RequireVerifier="true">'
			. '<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature" Secret="s" />'
			. '</endpoint></service>'
		));
		$this->assertTrue($this->_service->getEndpoint('github')->getRequireVerifier());

		$this->expectException(TConfigurationException::class);
		$this->_service->init($this->xml(
			'<service id="webhook"><endpoint id="stripe" RequireVerifier="true" /></service>'
		));
	}

	public function testASuccessStatusThatIsNotAStatusIsRefusedAtBoot()
	{
		$this->expectException(TConfigurationException::class);
		$this->_service->init($this->xml(
			'<service id="webhook"><endpoint id="github" SuccessStatus="ok" /></service>'
		));
	}

	public function testAHandlerSettingAnImpossibleStatusIsToldSo()
	{
		$this->endpoint('github')->onWebhook[] = function ($sender, $param) {
			$param->setStatusCode(0);
		};

		$this->_service->serviceParameter = 'github';
		$this->_service->requestBody = '{}';

		$this->expectException(TInvalidDataValueException::class);
		$this->_service->run();
	}

	public function testTheDefaultReadersAssembleTheRequestFromTheFramework()
	{
		$saved = $_POST;
		$_POST = ['From' => '+15005550006', 'count' => 2, 'nested' => ['a' => 'b']];
		try {
			$service = new TestEnvironmentWebhookService();
			$request = $service->buildRequest();

			$this->assertSame('POST', $request->getMethod());
			$this->assertSame('', $request->getBody(), 'php://input is empty on the command line');
			$this->assertSame('push', $request->getHeader('x-github-event'));
			$this->assertSame('https://example.com/index.php?webhook=github&page=1', $request->getUrl());
			// The posted fields alone, as strings, and only the scalars: the query string --
			// which the framework's merged view puts alongside them -- is not among them, and
			// a nested field has no serialization a scheme could sign.
			$this->assertSame(['From' => '+15005550006', 'count' => '2'], $request->getParameters());
			$this->assertSame(['webhook' => 'github', 'page' => '1'], $request->getQueryParameters());
			$this->assertSame('192.0.2.7', $request->getRemoteAddress());

			$service->request->userHostAddress = '';
			$this->assertNull($service->buildRequest()->getRemoteAddress());

			$_POST = [];
			$this->assertSame([], $service->buildRequest()->getParameters());
		} finally {
			$_POST = $saved;
		}
	}

	public function testThePostedFieldsAreVerifiedWithoutTheServiceParameter()
	{
		// Twilio signs the URL -- query string included -- followed by the sorted posted
		// fields, and nothing from the query string a second time. The framework's view of
		// the request merges in webhook=twilio, which Twilio never saw.
		$url = 'https://example.com/index.php?webhook=twilio';
		$secret = 'twilio-auth-token';
		$twilio = static function () use ($secret) {
			$signature = new THmacWebhookSignature();
			$signature->setSecret($secret);
			$signature->setHeader('X-Twilio-Signature');
			$signature->setAlgorithm('sha1');
			$signature->setEncoding('base64');
			$signature->setPayloadFormat('{url}{params}');

			return $signature;
		};
		$saved = $_POST;
		$_POST = ['From' => '+15005550006', 'CallSid' => 'CA123'];
		try {
			$service = new TestEnvironmentWebhookService();
			$service->request->serviceParameter = 'twilio';
			$service->request->requestUri = '/index.php?webhook=twilio';
			$service->request->items = ['webhook' => 'twilio', 'From' => '+15005550006', 'CallSid' => 'CA123'];
			$service->request->headers = [
				'X-Twilio-Signature' => base64_encode(hash_hmac('sha1', $url . 'CallSidCA123From+15005550006', $secret, true)),
			];
			$endpoint = new TWebhookEndpoint();
			$endpoint->setID('twilio');
			$endpoint->setRequireJson(false);
			$endpoint->setVerifier($twilio());
			$service->addEndpoint($endpoint);
			$accepted = 0;
			$endpoint->onWebhook[] = function () use (&$accepted) {
				$accepted++;
			};

			$this->assertSame(['From' => '+15005550006', 'CallSid' => 'CA123'], $service->buildRequest()->getParameters());

			$service->run();
			$this->assertSame(1, $accepted);
			$this->assertSame(204, $service->response->statusCode);

			// The signature the merged view would have matched is a forgery to a receiver
			// that sees only the posted fields.
			$service->response = new TestWebhookResponse();
			$service->request->headers = [
				'X-Twilio-Signature' => base64_encode(hash_hmac('sha1', $url . 'CallSidCA123From+15005550006webhooktwilio', $secret, true)),
			];
			$service->run();
			$this->assertSame(1, $accepted);
			$this->assertSame(401, $service->response->statusCode);
		} finally {
			$_POST = $saved;
		}
	}

	public function testContentHeadersCgiKeepsOutOfHttpAreRestored()
	{
		// php-fpm hands Content-Type and Content-Length to PHP without the HTTP_ prefix, so the
		// framework's header map lacks them; a scheme covering either would then fail there
		// and pass under Apache.
		$saved = [$_SERVER['CONTENT_TYPE'] ?? null, $_SERVER['CONTENT_LENGTH'] ?? null];
		$_SERVER['CONTENT_TYPE'] = 'application/json';
		$_SERVER['CONTENT_LENGTH'] = '17';
		try {
			$service = new TestEnvironmentWebhookService();
			$request = $service->buildRequest();
			$this->assertSame('application/json', $request->getHeader('Content-Type'));
			$this->assertSame('17', $request->getHeader('Content-Length'));
			$this->assertSame(17, $service->declaredBodySize());

			// One the server did put in the map is left alone rather than overwritten.
			$service->request->headers['content-type'] = 'text/plain';
			$request = $service->buildRequest();
			$this->assertSame('text/plain', $request->getHeader('Content-Type'));
			$this->assertCount(3, $request->getHeaders());
		} finally {
			foreach (['CONTENT_TYPE', 'CONTENT_LENGTH'] as $i => $key) {
				if ($saved[$i] === null) {
					unset($_SERVER[$key]);
				} else {
					$_SERVER[$key] = $saved[$i];
				}
			}
		}
	}

	public function testTheDeclaredBodySizeIsNullWhenAbsentOrNotANumber()
	{
		$service = new TestEnvironmentWebhookService();
		$this->assertNull($service->declaredBodySize());

		$service->request->headers['Content-Length'] = 'many';
		$this->assertNull($service->declaredBodySize());

		$service->request->headers['Content-Length'] = ' 42 ';
		$this->assertSame(42, $service->declaredBodySize());
	}

	public function testARequestBuiltWithoutABodyHasNone()
	{
		$service = new TestEnvironmentWebhookService();
		$this->assertSame('', $service->buildRequest(false)->getBody());
	}

	public function testTheDefaultReadersRunARequestEndToEnd()
	{
		$service = new TestEnvironmentWebhookService();
		$endpoint = new TWebhookEndpoint();
		$endpoint->setID('github');
		$endpoint->setRequireJson(false);
		$endpoint->setEventHeader('X-GitHub-Event');
		$service->addEndpoint($endpoint);
		$seen = [];
		$endpoint->onWebhook[] = function ($sender, TWebhookEventParameter $param) use (&$seen) {
			$seen[] = $param->getEvent();
		};

		$service->run();

		$this->assertSame(['push'], $seen);
		$this->assertSame(204, $service->response->statusCode);
	}
}
