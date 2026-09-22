<?php

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\TFieldedWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookEndpoint;
use Belisoful\Prado\Web\Webhooks\TWebhookEventParameter;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Belisoful\Prado\Web\Webhooks\TWebhookService;
use Prado\Exceptions\TConfigurationException;
use Prado\Xml\TXmlDocument;

/**
 * Stands in for THttpResponse, which needs a running application to be useful.
 */
class TestWebhookResponse
{
	public int $statusCode = 200;
	public array $appendedHeaders = [];
	public ?string $contentType = null;
	public string $body = '';

	public function setStatusCode($value): void
	{
		$this->statusCode = (int) $value;
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
}
