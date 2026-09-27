<?php

/**
 * TWebhookService class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\Exceptions\TConfigurationException;
use Prado\TPropertyValue;
use Prado\TService;
use Prado\Web\THttpHeaderName;

/**
 * TWebhookService class.
 *
 * The inbound half of the package: a PRADO service that receives webhook deliveries and
 * routes each to the {@see \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint} its URL names.
 *
 * ```xml
 * <services>
 *		<service id="webhook" class="Belisoful\Prado\Web\Webhooks\TWebhookService">
 *			<endpoint id="github" EventHeader="X-GitHub-Event">
 *				<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *					Secret="..." Header="X-Hub-Signature-256" Prefix="sha256=" />
 *			</endpoint>
 *			<endpoint id="mail" RequireJson="true">
 *				<signature class="Belisoful\Prado\Web\Webhooks\Signature\TTokenWebhookSignature"
 *					Token="..." Prefix="Basic " />
 *			</endpoint>
 *		</service>
 * </services>
 * ```
 *
 * The service id is the URL's first parameter and the endpoint id its value, so the
 * configuration above gives the provider `index.php?webhook=github`. An id that names no
 * endpoint, or names a disabled one, gets a 404 and nothing else: a caller cannot use the
 * service to learn which endpoints exist.
 *
 * {@see onWebhook} is raised for every endpoint's accepted deliveries -- and only those; a
 * request the endpoint refused reaches {@see onRefused} instead, with its payload
 * undecoded. That is where a single module can watch the lot:
 *
 * ```php
 * $this->getApplication()->onInitComplete[] = function () {
 *		// Null on any request another service is handling, and the nullsafe operator is
 *		// not allowed on the left of an assignment, so this is a plain check.
 *		if (($service = TWebhookService::getInstance()) !== null) {
 *			$service->onWebhook[] = [$this, 'anyWebhook'];
 *			$service->onRefused[] = [$this, 'countRefusal'];
 *		}
 * };
 * ```
 *
 * A delivery is answered inside the request that carried it, and providers time out in
 * seconds, so a handler that has real work to do should record the payload and return.
 * The outbound half of this package -- {@see \Belisoful\Prado\Web\Webhooks\TWebhookModule}
 * and {@see \Belisoful\Prado\Web\Webhooks\TWebhookSender} -- is the other direction and is
 * configured separately.
 *
 * Two things about the environment are worth knowing. The URL a scheme is shown is
 * assembled from what PHP saw, so behind a proxy that terminates TLS it begins `http://`
 * and a scheme that signs the URL will refuse; override {@see getRequestUrl} to put the
 * public URL back, from a header that only a trusted hop can have set. And the framework
 * picks the service from the query string and the posted form together, so a
 * form-encoded provider whose body carries a field named like another service's id --
 * `page`, say -- is routed to that service instead; such a provider needs a URL whose
 * service parameter comes first, or an endpoint that does not share a name with a field.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 * @method void dyWebhook(TWebhookEventParameter $param)
 * @method void dyRefused(TWebhookEventParameter $param)
 */
class TWebhookService extends TService
{
	use TWebhookConfigurationTrait;

	/** @var string the conventional service id, and so the URL parameter name. */
	public const SERVICE_ID = 'webhook';

	/** @var string the configuration element each endpoint is declared in. */
	public const ENDPOINT_TAG = 'endpoint';

	/** @var string the reason phrase sent with a status the framework has no phrase for. */
	public const STATUS_REASON = 'Webhook';

	/** @var array<string, \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint> id => endpoint */
	private array $_endpoints = [];

	/** @var null|string the endpoint a request with no service parameter reaches */
	private ?string $_defaultEndpoint = null;

	/**
	 * Configures the service and every `endpoint` child of it.
	 * @param mixed $config the service configuration.
	 * @throws \Prado\Exceptions\TConfigurationException when an endpoint has no id, is
	 *   declared twice, or names a class that is not a
	 *   {@see \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint}.
	 */
	public function init($config): void
	{
		foreach ($this->childConfigurations($config, self::ENDPOINT_TAG) as $id => $endpointConfig) {
			/** @var \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint $endpoint */
			$endpoint = $this->createConfigured($endpointConfig, TWebhookEndpoint::class, TWebhookEndpoint::class);
			$endpoint->setID($id);
			$endpoint->init($endpointConfig);
			$this->addEndpoint($endpoint);
		}
		parent::init($config);
	}

	/**
	 * Receives one delivery and answers it.
	 *
	 * A body the request declares to be larger than the endpoint accepts is refused before
	 * it is read, so an unauthenticated caller cannot make the service buffer it either.
	 *
	 * @throws \Prado\Exceptions\TConfigurationException when the endpoint's verifier is not
	 *   configured.
	 */
	public function run(): void
	{
		$id = $this->getServiceParameter();
		$endpoint = $id === null ? null : $this->resolveEndpoint($id);
		if ($endpoint === null) {
			$this->getResponse()->setStatusCode(404);

			return;
		}

		$declared = $this->getDeclaredBodySize();
		if ($declared !== null && $endpoint->getMaxBodySize() > 0 && $declared > $endpoint->getMaxBodySize()) {
			$param = new TWebhookEventParameter($endpoint, $this->createWebhookRequest(false));
			$param->setStatusCode(413);
		} else {
			$param = $endpoint->handle($this->createWebhookRequest());
		}

		if ($param->getAccepted()) {
			$this->onWebhook($param);
		} else {
			$this->onRefused($param);
		}
		$this->writeResponse($param);
	}

	/**
	 * Finds the endpoint a service parameter names.
	 *
	 * An empty parameter falls back to {@see getDefaultEndpoint DefaultEndpoint}, and then,
	 * when a service carries exactly one endpoint, to that endpoint -- so a single-provider
	 * application can use a bare `index.php?webhooks` URL without naming anything twice.
	 *
	 * @param string $id the service parameter.
	 * @return null|\Belisoful\Prado\Web\Webhooks\TWebhookEndpoint the endpoint, or null when
	 *   there is no enabled endpoint by that name.
	 */
	protected function resolveEndpoint(string $id): ?TWebhookEndpoint
	{
		if ($id === '') {
			$id = $this->_defaultEndpoint ?? '';
		}
		if ($id === '' && count($this->_endpoints) === 1) {
			$id = (string) array_key_first($this->_endpoints);
		}
		$endpoint = $this->_endpoints[$id] ?? null;

		return ($endpoint !== null && $endpoint->getEnabled()) ? $endpoint : null;
	}

	/**
	 * Writes the response an endpoint decided on.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookEventParameter $param the handled request.
	 */
	protected function writeResponse(TWebhookEventParameter $param): void
	{
		$response = $this->getResponse();
		$status = $param->getStatusCode();
		$body = $param->getResponseBody();
		if ($body !== null && $status === 204) {
			// A 204 cannot carry a body; a handler that set one on the default status
			// meant 200.
			$status = 200;
		}
		// The reason is only used for a code outside the framework's table, where the
		// framework would otherwise throw -- and an error page to a provider is a 500.
		$response->setStatusCode($status, self::STATUS_REASON);

		if ($status === 405) {
			$response->appendHeader(THttpHeaderName::Allow . ': ' . $param->getEndpoint()->getAllow());
		}
		if ($body !== null) {
			$response->setContentType($param->getResponseContentType());
			$response->write($body);
		}
	}

	/**
	 * Returns the raw HTTP request body.
	 *
	 * Reads `php://input` rather than anything PHP has already parsed, because every
	 * signature scheme hashes the bytes as sent: `$_POST` has been through urldecoding and
	 * a JSON body never reaches it at all. Override this in a subclass to feed a synthetic
	 * body to a test. A `multipart/form-data` request is the one kind PHP consumes before
	 * anything can read the stream; such a body reads as empty here and is refused.
	 *
	 * @return string the raw request body, or an empty string when the stream cannot be read.
	 */
	protected function readBody(): string
	{
		return (string) file_get_contents('php://input');
	}

	/**
	 * @return null|int the body size the request declares in `Content-Length`, or null
	 *   when it declares none or something that is not a size.
	 * @since 0.1.0
	 */
	protected function getDeclaredBodySize(): ?int
	{
		foreach ($this->getRequestHeaders() as $name => $value) {
			if (strcasecmp((string) $name, THttpHeaderName::ContentLength) === 0) {
				$value = is_array($value) ? reset($value) : $value;
				$value = trim((string) $value);

				return ctype_digit($value) ? (int) $value : null;
			}
		}

		return null;
	}

	/**
	 * Assembles the request a verifier is given.
	 *
	 * The URL, the parameters, and the address are collected even though most schemes want
	 * none of them, because the ones that do -- a signature over the URL, a token in the
	 * query string, an address allow list -- cannot be configured into an endpoint whose
	 * request never carried them.
	 *
	 * @param bool $withBody whether to read the body; false leaves it empty, for a request
	 *   refused before it is worth reading.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookRequest the request as received.
	 */
	protected function createWebhookRequest(bool $withBody = true): TWebhookRequest
	{
		return new TWebhookRequest(
			$this->getRequestMethod(),
			$withBody ? $this->readBody() : '',
			$this->getRequestHeaders(),
			$this->getRequestUrl(),
			$this->getRequestParameters(),
			$this->getRemoteAddress()
		);
	}

	/**
	 * Returns the service parameter, which names the endpoint the request is for.
	 *
	 * The framework hands the parameter over as it was parsed, so `?webhook[]=x` arrives as
	 * an array. Casting that would warn, and the warning would be a 500 anyone can cause;
	 * it reads as null here, which no endpoint matches.
	 *
	 * @return null|string the service parameter, or null when it is not a single value.
	 */
	protected function getServiceParameter(): ?string
	{
		$value = $this->getRequest()->getServiceParameter();

		return is_scalar($value) ? (string) $value : null;
	}

	/**
	 * @return string the HTTP method of the request, upper case.
	 */
	protected function getRequestMethod(): string
	{
		return strtoupper((string) $this->getRequest()->getRequestType());
	}

	/**
	 * Returns the request headers.
	 *
	 * Outside Apache the framework builds these from `$_SERVER`'s `HTTP_*` entries, and
	 * CGI puts `Content-Type` and `Content-Length` elsewhere -- so a scheme that covers
	 * either would verify under Apache and fail under php-fpm. They are put back here.
	 *
	 * @return array<string, string> the request headers.
	 */
	protected function getRequestHeaders(): array
	{
		$headers = $this->getRequest()->getHeaders();
		foreach (['CONTENT_TYPE' => THttpHeaderName::ContentType, 'CONTENT_LENGTH' => THttpHeaderName::ContentLength] as $key => $name) {
			if (!isset($_SERVER[$key]) || $_SERVER[$key] === '') {
				continue;
			}
			foreach (array_keys($headers) as $present) {
				if (strcasecmp((string) $present, $name) === 0) {
					continue 2;
				}
			}
			$headers[$name] = (string) $_SERVER[$key];
		}

		return $headers;
	}

	/**
	 * Returns the URL a scheme that signs the URL is shown. It is assembled from what PHP
	 * saw, so behind a proxy that terminates TLS or rewrites the host it is not the URL the
	 * provider signed; override this to build the public one from a header only a trusted
	 * hop can set.
	 * @return string the absolute URL of the request.
	 */
	protected function getRequestUrl(): string
	{
		$request = $this->getRequest();

		return $request->getBaseUrl() . $request->getRequestUri();
	}

	/**
	 * @return array<string, string> the request parameters, query string and posted form
	 *   together, as the framework parsed them.
	 */
	protected function getRequestParameters(): array
	{
		$parameters = [];
		foreach ($this->getRequest()->toArray() as $name => $value) {
			if (is_scalar($value)) {
				$parameters[(string) $name] = (string) $value;
			}
		}

		return $parameters;
	}

	/**
	 * @return null|string the address the request came from, or null when it is not known.
	 */
	protected function getRemoteAddress(): ?string
	{
		$address = (string) $this->getRequest()->getUserHostAddress();

		return $address === '' ? null : $address;
	}

	/**
	 * Raises the `OnWebhook` event, once per accepted delivery to any endpoint.
	 *
	 * The endpoint's own {@see TWebhookEndpoint::onWebhook} has already run, so a handler
	 * here sees whatever it decided and may still change the response. A refused delivery
	 * never reaches this event; it raises {@see onRefused}.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookEventParameter $param the request and response.
	 */
	public function onWebhook(TWebhookEventParameter $param): void
	{
		$this->raiseEvent('onWebhook', $this, $param);
	}

	/**
	 * Raises the `OnRefused` event, once per delivery an endpoint refused: the wrong
	 * method, too large, unsigned or forged, or not JSON where JSON was required.
	 *
	 * The parameter carries the status the provider will see and the request as received,
	 * with its body undecoded; a handler that reads the payload decodes it. This is where
	 * an application counts forgeries, rate limits, or alerts -- and a handler here must not
	 * turn a refusal into a success, so the status may be changed only to another refusal.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookEventParameter $param the request and response.
	 * @since 0.1.0
	 */
	public function onRefused(TWebhookEventParameter $param): void
	{
		$status = $param->getStatusCode();
		$this->raiseEvent('onRefused', $this, $param);
		if ($param->getStatusCode() < 400) {
			$param->setStatusCode($status);
		}
	}

	/**
	 * @return array<string, \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint> every configured
	 *   endpoint, keyed by id.
	 */
	public function getEndpoints(): array
	{
		return $this->_endpoints;
	}

	/**
	 * @param string $id the endpoint id.
	 * @return null|\Belisoful\Prado\Web\Webhooks\TWebhookEndpoint the endpoint, or null when
	 *   no endpoint has that id.
	 */
	public function getEndpoint(string $id): ?TWebhookEndpoint
	{
		return $this->_endpoints[$id] ?? null;
	}

	/**
	 * Adds an endpoint, which is how one is registered from PHP rather than configuration.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint $endpoint the endpoint, which
	 *   must carry an id.
	 * @throws \Prado\Exceptions\TConfigurationException when the endpoint has no id, or
	 *   another endpoint already answers at that id.
	 */
	public function addEndpoint(TWebhookEndpoint $endpoint): void
	{
		$id = (string) $endpoint->getID();
		if ($id === '') {
			throw new TConfigurationException('webhooks_endpoint_id_required', static::class);
		}
		if (isset($this->_endpoints[$id])) {
			throw new TConfigurationException('webhooks_endpoint_duplicate', $id);
		}
		$this->_endpoints[$id] = $endpoint;
	}

	/**
	 * @return null|string the endpoint a request with no service parameter reaches.
	 */
	public function getDefaultEndpoint(): ?string
	{
		return $this->_defaultEndpoint;
	}

	/**
	 * @param mixed $value the id of the endpoint a request with no service parameter reaches.
	 */
	public function setDefaultEndpoint($value): void
	{
		$id = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_defaultEndpoint = $id === '' ? null : $id;
	}
}
