<?php

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\IWebhookVerifier;
use Belisoful\Prado\Web\Webhooks\TWebhookEndpoint;
use Belisoful\Prado\Web\Webhooks\TWebhookEventParameter;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\Xml\TXmlDocument;

/**
 * A verifier whose answer the test dictates, so an endpoint's behavior either side of
 * verification can be exercised without building a real signature for each case.
 */
class TestWebhookVerifier implements IWebhookVerifier
{
	public bool $answer = true;
	public ?string $sawBody = null;

	public function verify(TWebhookRequest $request): bool
	{
		$this->sawBody = $request->getBody();

		return $this->answer;
	}
}

class TWebhookEndpointTest extends PHPUnit\Framework\TestCase
{
	private const BODY = '{"action":"opened","repository":{"full_name":"belisoful/prado"}}';

	private TWebhookEndpoint $_endpoint;

	protected function setUp(): void
	{
		$this->_endpoint = new TWebhookEndpoint();
		$this->_endpoint->setID('github');
	}

	/** Hands the endpoint a delivery built from its pieces. */
	private function handle(string $method, string $body, array $headers = []): TWebhookEventParameter
	{
		return $this->_endpoint->handle(new TWebhookRequest($method, $body, $headers));
	}

	public function testAVerifiedDeliveryRaisesTheEventAndSucceeds()
	{
		$seen = [];
		$this->_endpoint->onWebhook[] = function ($sender, $param) use (&$seen) {
			$seen[] = [$sender, $param];
		};

		$param = $this->handle('POST', self::BODY, ['X-GitHub-Event' => 'push']);

		$this->assertCount(1, $seen);
		$this->assertSame($this->_endpoint, $seen[0][0]);
		$this->assertSame($param, $seen[0][1]);
		$this->assertSame(TWebhookEndpoint::DEFAULT_SUCCESS_STATUS, $param->getStatusCode());
		$this->assertTrue($param->getVerified());
	}

	public function testThePayloadIsDecodedAndSubscriptable()
	{
		$param = $this->handle('POST', self::BODY);

		$this->assertSame('opened', $param->getPayload()['action']);
		$this->assertSame('belisoful/prado', $param['repository']['full_name']);
		$this->assertSame(self::BODY, $param->getBody());
	}

	public function testAnUnacceptedMethodIsRefusedWithoutRaisingTheEvent()
	{
		$seen = [];
		$this->_endpoint->onWebhook[] = function () use (&$seen) {
			$seen[] = true;
		};

		$param = $this->handle('GET', '');

		$this->assertSame(405, $param->getStatusCode());
		$this->assertSame([], $seen);
		$this->assertFalse($param->getVerified());
	}

	public function testTheAllowValueListsTheAcceptedMethods()
	{
		$this->_endpoint->setMethods('POST, put');
		$this->assertSame(['POST', 'PUT'], $this->_endpoint->getMethods());
		$this->assertSame('POST, PUT', $this->_endpoint->getAllow());
		$this->assertSame(204, $this->handle('put', '{}')->getStatusCode());
	}

	public function testAnEmptyMethodListIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		$this->_endpoint->setMethods(' , ');
	}

	public function testAnOversizedBodyIsRefusedBeforeItIsVerified()
	{
		$verifier = new TestWebhookVerifier();
		$this->_endpoint->setVerifier($verifier);
		$this->_endpoint->setMaxBodySize(16);

		$param = $this->handle('POST', self::BODY);

		$this->assertSame(413, $param->getStatusCode());
		// The point of the ordering: an unauthenticated caller cannot make the endpoint hash
		// an arbitrarily large body.
		$this->assertNull($verifier->sawBody);
	}

	public function testAZeroMaxBodySizeAcceptsAnyBody()
	{
		$this->_endpoint->setMaxBodySize(0);
		$this->assertSame(204, $this->handle('POST', json_encode([str_repeat('x', 4096)]))->getStatusCode());
	}

	public function testAFailedVerificationIsRefusedWithoutRaisingTheEvent()
	{
		$verifier = new TestWebhookVerifier();
		$verifier->answer = false;
		$this->_endpoint->setVerifier($verifier);
		$seen = [];
		$this->_endpoint->onWebhook[] = function () use (&$seen) {
			$seen[] = true;
		};

		$param = $this->handle('POST', self::BODY);

		$this->assertSame(401, $param->getStatusCode());
		$this->assertFalse($param->getVerified());
		$this->assertSame([], $seen);
	}

	public function testTheVerifierSeesTheRawBody()
	{
		// Not the re-encoded payload: whitespace and key order are part of what was signed.
		$verifier = new TestWebhookVerifier();
		$this->_endpoint->setVerifier($verifier);
		$body = "{\n\t\"action\" : \"opened\"\n}";

		$this->handle('POST', $body);

		$this->assertSame($body, $verifier->sawBody);
	}

	public function testARealSignatureVerifies()
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret('s3cret');
		$signature->setHeader('X-Hub-Signature-256');
		$signature->setPrefix('sha256=');
		$this->_endpoint->setVerifier($signature);

		$signed = $signature->sign(new TWebhookRequest('POST', self::BODY));
		$accepted = $this->handle('POST', self::BODY, $signed);
		$refused = $this->handle('POST', self::BODY, ['X-Hub-Signature-256' => 'sha256=00']);

		$this->assertSame(204, $accepted->getStatusCode());
		$this->assertSame(401, $refused->getStatusCode());
	}

	public function testABodyThatIsNotJsonIsRefusedByDefault()
	{
		$param = $this->handle('POST', 'RecordType=Bounce&Email=x%40y.z');

		$this->assertSame(400, $param->getStatusCode());
		// It was authentic; it just was not JSON.
		$this->assertTrue($param->getVerified());
	}

	public function testABodyThatIsNotJsonIsAllowedWhenTheEndpointSaysSo()
	{
		$this->_endpoint->setRequireJson(false);
		$seen = [];
		$this->_endpoint->onWebhook[] = function ($sender, $param) use (&$seen) {
			$seen[] = $param;
		};

		$param = $this->handle('POST', 'RecordType=Bounce');

		$this->assertSame(204, $param->getStatusCode());
		$this->assertCount(1, $seen);
		$this->assertNull($param->getPayload());
		$this->assertSame('RecordType=Bounce', $param->getBody());
	}

	public function testAHandlerDecidesTheResponse()
	{
		$this->_endpoint->onWebhook[] = function ($sender, $param) {
			$param->setStatusCode(202);
			$param->setResponseBody(['queued' => true]);
		};

		$param = $this->handle('POST', self::BODY);

		$this->assertSame(202, $param->getStatusCode());
		$this->assertSame('{"queued":true}', $param->getResponseBody());
		$this->assertSame('application/json', $param->getResponseContentType());
	}

	public function testTheSuccessStatusIsConfigurable()
	{
		$this->_endpoint->setSuccessStatus(200);
		$this->assertSame(200, $this->handle('POST', '{}')->getStatusCode());
	}

	public function testTheEventNameComesFromAHeader()
	{
		$this->_endpoint->setEventHeader('X-GitHub-Event');
		$param = $this->handle('POST', self::BODY, ['x-github-event' => 'pull_request']);

		$this->assertSame('pull_request', $param->getEvent());
	}

	public function testTheEventNameComesFromThePayload()
	{
		$this->_endpoint->setEventProperty('type');
		$param = $this->handle('POST', '{"type":"invoice.paid"}');

		$this->assertSame('invoice.paid', $param->getEvent());
	}

	public function testTheEventNameIsNullWhenTheEndpointNamesNoSource()
	{
		$this->assertNull($this->handle('POST', '{"type":"invoice.paid"}')->getEvent());
	}

	public function testTheHeaderWinsOverThePayloadProperty()
	{
		$this->_endpoint->setEventHeader('X-Event');
		$this->_endpoint->setEventProperty('type');
		$param = $this->handle('POST', '{"type":"from.payload"}', ['X-Event' => 'from.header']);

		$this->assertSame('from.header', $param->getEvent());
	}

	public function testThePayloadPropertyIsUsedWhenTheHeaderIsAbsent()
	{
		$this->_endpoint->setEventHeader('X-Event');
		$this->_endpoint->setEventProperty('type');
		$param = $this->handle('POST', '{"type":"from.payload"}');

		$this->assertSame('from.payload', $param->getEvent());
	}

	public function testAnEventPropertyThatIsNotScalarIsNotAnEventName()
	{
		$this->_endpoint->setEventProperty('type');
		$this->assertNull($this->handle('POST', '{"type":{"nested":1}}')->getEvent());
	}

	public function testHeadersAreReadableWithoutRegardToCase()
	{
		$param = $this->handle('POST', '{}', ['X-GitHub-Delivery' => 'abc']);

		$this->assertSame('abc', $param->getHeader('x-github-delivery'));
		$this->assertNull($param->getHeader('X-Absent'));
	}

	public function testTheParameterReportsTheEndpointAndMethod()
	{
		$param = $this->handle('post', '{}');

		$this->assertSame($this->_endpoint, $param->getEndpoint());
		$this->assertSame('POST', $param->getMethod());
	}

	public function testTheParameterCarriesTheRequestTheVerifierSaw()
	{
		$request = new TWebhookRequest('POST', self::BODY, ['X-Event' => 'push'], 'https://example.com/index.php?webhook=github');
		$param = $this->_endpoint->handle($request);

		$this->assertSame($request, $param->getRequest());
		$this->assertSame('https://example.com/index.php?webhook=github', $param->getRequest()->getUrl());
	}

	public function testTheParameterCarriesTheHeadersItWasGiven()
	{
		$headers = ['X-GitHub-Event' => 'push', 'X-GitHub-Delivery' => 'abc'];
		$param = $this->handle('POST', '{}', $headers);

		$this->assertSame($headers, $param->getHeaders());
	}

	public function testTheResponseContentTypeIsSettable()
	{
		$this->_endpoint->onWebhook[] = function ($sender, $param) {
			$param->setResponseContentType('text/plain');
			$param->setResponseBody('ok');
		};

		$param = $this->handle('POST', '{}');

		$this->assertSame('text/plain', $param->getResponseContentType());
		$this->assertSame('ok', $param->getResponseBody());
	}

	public function testAResponseBodyClearsBackToNull()
	{
		$this->_endpoint->onWebhook[] = function ($sender, $param) {
			$param->setResponseBody('ok');
			$param->setResponseBody(null);
		};

		$this->assertNull($this->handle('POST', '{}')->getResponseBody());
	}

	public function testAVerifierIsBuiltFromTheSignatureChild()
	{
		$xml = new TXmlDocument();
		$xml->loadFromString(
			'<endpoint id="github">'
			. '<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"'
			. ' Secret="s3cret" Header="X-Hub-Signature-256" Prefix="sha256=" />'
			. '</endpoint>'
		);
		$this->_endpoint->init($xml);

		$verifier = $this->_endpoint->getVerifier();
		$this->assertInstanceOf(THmacWebhookSignature::class, $verifier);
		$this->assertSame('s3cret', $verifier->getSecret());
		$this->assertSame('X-Hub-Signature-256', $verifier->getHeader());
		$this->assertSame('sha256=', $verifier->getPrefix());
	}

	public function testASignatureChildThatCannotVerifyIsRefused()
	{
		$xml = new TXmlDocument();
		$xml->loadFromString('<endpoint id="x"><signature class="Prado\TComponent" /></endpoint>');

		$this->expectException(TConfigurationException::class);
		$this->_endpoint->init($xml);
	}

	public function testASignatureChildWithoutAClassIsRefused()
	{
		$xml = new TXmlDocument();
		$xml->loadFromString('<endpoint id="x"><signature Secret="s3cret" /></endpoint>');

		$this->expectException(TConfigurationException::class);
		$this->_endpoint->init($xml);
	}

	public function testNoSignatureChildLeavesTheEndpointUnverified()
	{
		$xml = new TXmlDocument();
		$xml->loadFromString('<endpoint id="x" />');
		$this->_endpoint->init($xml);

		$this->assertNull($this->_endpoint->getVerifier());
		$this->assertSame(204, $this->handle('POST', '{}')->getStatusCode());
	}

	public function testDefaults()
	{
		$endpoint = new TWebhookEndpoint();
		$this->assertTrue($endpoint->getEnabled());
		$this->assertNull($endpoint->getVerifier());
		$this->assertSame(['POST'], $endpoint->getMethods());
		$this->assertNull($endpoint->getEventHeader());
		$this->assertNull($endpoint->getEventProperty());
		$this->assertSame(TWebhookEndpoint::DEFAULT_MAX_BODY_SIZE, $endpoint->getMaxBodySize());
		$this->assertTrue($endpoint->getRequireJson());
		$this->assertSame(TWebhookEndpoint::DEFAULT_SUCCESS_STATUS, $endpoint->getSuccessStatus());
	}
}
