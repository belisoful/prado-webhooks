<?php

/**
 * TWebhookEndpoint class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Belisoful\Prado\Web\Webhooks\Signature\IWebhookVerifier;
use Prado\Exceptions\TConfigurationException;
use Prado\TApplicationComponent;
use Prado\TPropertyValue;
use Prado\Xml\TXmlElement;

/**
 * TWebhookEndpoint class.
 *
 * One inbound webhook URL: the provider that may post to it, how a request from that
 * provider is authenticated, and the event raised once it is. A
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookService} holds one of these per provider and
 * routes to them by id.
 *
 * ```xml
 * <service id="webhook" class="Belisoful\Prado\Web\Webhooks\TWebhookService">
 *		<endpoint id="github" EventHeader="X-GitHub-Event">
 *			<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *				Secret="..." Header="X-Hub-Signature-256" Prefix="sha256=" />
 *		</endpoint>
 *		<endpoint id="payments" EventProperty="type">
 *			<signature class="Belisoful\Prado\Web\Webhooks\Signature\TFieldedWebhookSignature"
 *				Secret="whsec_..." Header="Stripe-Signature" />
 *		</endpoint>
 * </service>
 * ```
 *
 * Both endpoints above answer at `index.php?webhook=<id>`; point the provider's dashboard
 * at that URL. Handlers attach from a module, once the service exists:
 *
 * ```php
 * $this->getApplication()->onInitComplete[] = function () {
 *		$endpoint = TWebhookService::getInstance()?->getEndpoint('github');
 *		if ($endpoint !== null) {
 *			$endpoint->onWebhook[] = [$this, 'github'];
 *		}
 * };
 * ```
 *
 * {@see handle} is the whole of the endpoint's behavior and takes the request apart from
 * its pieces rather than from the environment, so a delivery can be replayed in a test
 * with nothing more than the bytes and headers the provider sent.
 *
 * The checks run in the order that leaks least: the method, then the size, then the
 * signature, and only then anything that reads the payload. Nothing that depends on the
 * body's *content* happens before the signature has been verified; the body is not even
 * decoded until then.
 *
 * An endpoint with no `signature` child accepts every request that reaches it. That is
 * deliberate, for a URL something in front of the application already guards, but it is
 * also what a misspelled child element would silently produce -- so an unknown child is
 * refused at configuration time, and {@see setRequireVerifier RequireVerifier} makes the
 * absence of a verifier a configuration error rather than an open door.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 * @method void dyWebhook(TWebhookEventParameter $param)
 */
class TWebhookEndpoint extends TApplicationComponent
{
	use TWebhookConfigurationTrait;

	/** @var int the status a handled request answers with when nothing sets another. */
	public const DEFAULT_SUCCESS_STATUS = 204;

	/** @var int the largest body accepted by default, in bytes. */
	public const DEFAULT_MAX_BODY_SIZE = 1048576;

	/** @var string the one child element an endpoint is configured with. */
	public const SIGNATURE_TAG = 'signature';

	/** @var string[] the keys a PHP endpoint configuration may carry besides its children. */
	protected const CONFIGURATION_KEYS = ['class', 'properties', 'id'];

	/** @var null|string the id this endpoint answers at */
	private ?string $_id = null;

	/** @var bool whether the endpoint accepts requests */
	private bool $_enabled = true;

	/** @var null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookVerifier how a request is authenticated */
	private ?IWebhookVerifier $_verifier = null;

	/** @var bool whether an endpoint without a verifier is a configuration error */
	private bool $_requireVerifier = false;

	/** @var string[] the HTTP methods the endpoint accepts, upper case */
	private array $_methods = ['POST'];

	/** @var null|string the header naming the event, for providers that use one */
	private ?string $_eventHeader = null;

	/** @var null|string the payload property naming the event, for providers that use one */
	private ?string $_eventProperty = null;

	/** @var int the largest body accepted, in bytes; 0 accepts any */
	private int $_maxBodySize = self::DEFAULT_MAX_BODY_SIZE;

	/** @var bool whether a body that is not JSON is rejected */
	private bool $_requireJson = true;

	/** @var int the status a handled request answers with */
	private int $_successStatus = self::DEFAULT_SUCCESS_STATUS;

	/**
	 * Configures the endpoint, including its `signature` child.
	 * @param mixed $config the endpoint's configuration.
	 * @throws \Prado\Exceptions\TConfigurationException when the signature names no class, or
	 *   names one that does not verify.
	 */
	public function init($config): void
	{
		$this->assertKnownChildren($config);
		if (($signature = $this->childConfiguration($config, self::SIGNATURE_TAG)) !== null) {
			/** @var \Belisoful\Prado\Web\Webhooks\Signature\IWebhookVerifier $verifier */
			$verifier = $this->createConfigured($signature, IWebhookVerifier::class);
			$this->setVerifier($verifier);
		}
		if ($this->_requireVerifier && $this->_verifier === null) {
			throw new TConfigurationException('webhooks_verifier_required', (string) $this->_id, static::class);
		}
	}

	/**
	 * Refuses a configuration carrying a child this endpoint does not read.
	 *
	 * The only child is `signature`, and a `signatrue` would otherwise be ignored -- which
	 * leaves an endpoint that accepts everything and reports it verified. Fail at boot
	 * instead.
	 *
	 * @param mixed $config the endpoint's configuration.
	 * @throws \Prado\Exceptions\TConfigurationException when an unknown child is present.
	 */
	protected function assertKnownChildren(mixed $config): void
	{
		$unknown = [];
		if ($config instanceof TXmlElement) {
			foreach ($config->getElements() as $element) {
				if ($element->getTagName() !== self::SIGNATURE_TAG) {
					$unknown[] = $element->getTagName();
				}
			}
		} elseif (is_array($config)) {
			foreach (array_keys($config) as $key) {
				if ($key !== self::SIGNATURE_TAG && !in_array($key, static::CONFIGURATION_KEYS, true)) {
					$unknown[] = (string) $key;
				}
			}
		}
		if ($unknown !== []) {
			throw new TConfigurationException(
				'webhooks_child_unknown',
				implode(', ', $unknown),
				static::class,
				self::SIGNATURE_TAG
			);
		}
	}

	/**
	 * Handles one delivery: checks it, raises {@see onWebhook} when it is genuine, and
	 * returns the parameter carrying the response to send.
	 *
	 * The returned parameter always carries a status, so a caller writes the response the
	 * same way whether the request was accepted or refused. Nothing here throws over a bad
	 * request: a provider that is told 400 stops, while a provider that is shown an error
	 * page learns about the application and, because that page is a 500, keeps retrying.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when the verifier is not configured.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookEventParameter the request, and the
	 *   response to answer it with.
	 */
	public function handle(TWebhookRequest $request): TWebhookEventParameter
	{
		if ($this->_requireVerifier && $this->_verifier === null) {
			throw new TConfigurationException('webhooks_verifier_required', (string) $this->_id, static::class);
		}
		$param = new TWebhookEventParameter($this, $request);

		if (!in_array($request->getMethod(), $this->_methods, true)) {
			$param->setStatusCode(405);

			return $param;
		}
		if ($this->_maxBodySize > 0 && strlen($request->getBody()) > $this->_maxBodySize) {
			$param->setStatusCode(413);

			return $param;
		}
		if ($this->_verifier !== null && !$this->_verifier->verify($request)) {
			$param->setStatusCode(401);

			return $param;
		}
		$param->setVerified(true);

		// The first thing that reads the body's content, and it runs only now.
		$param->decodePayload();
		if ($this->_requireJson && !$param->getPayloadIsJson()) {
			$param->setStatusCode(400);

			return $param;
		}

		// Set before raising, so a handler can answer with something else.
		$param->setAccepted(true);
		$param->setStatusCode($this->_successStatus);
		$this->onWebhook($param);

		return $param;
	}

	/**
	 * Raises the `OnWebhook` event, once per verified delivery.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookEventParameter $param the request and response.
	 */
	public function onWebhook(TWebhookEventParameter $param): void
	{
		$this->raiseEvent('onWebhook', $this, $param);
	}

	/**
	 * @return null|string the id this endpoint answers at, which is the service parameter of
	 *   its URL.
	 */
	public function getID(): ?string
	{
		return $this->_id;
	}

	/**
	 * @param mixed $value the id this endpoint answers at.
	 */
	public function setID($value): void
	{
		$this->_id = TPropertyValue::ensureString($value);
	}

	/**
	 * @return bool whether the endpoint accepts requests. Defaults to true.
	 */
	public function getEnabled(): bool
	{
		return $this->_enabled;
	}

	/**
	 * @param mixed $value whether the endpoint accepts requests. A disabled endpoint answers
	 *   404, the same as an id that was never configured.
	 */
	public function setEnabled($value): void
	{
		$this->_enabled = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookVerifier how a request is
	 *   authenticated, or null when it is not.
	 */
	public function getVerifier(): ?IWebhookVerifier
	{
		return $this->_verifier;
	}

	/**
	 * Sets how a request is authenticated. An endpoint with no verifier accepts anything
	 * that reaches its URL, which is only ever right when something in front of the
	 * application has already authenticated the request.
	 * @param null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookVerifier $value the verifier.
	 */
	public function setVerifier(?IWebhookVerifier $value): void
	{
		$this->_verifier = $value;
	}

	/**
	 * @return bool whether an endpoint with no verifier is a configuration error. Defaults
	 *   to false.
	 * @since 0.1.0
	 */
	public function getRequireVerifier(): bool
	{
		return $this->_requireVerifier;
	}

	/**
	 * Makes the absence of a verifier a configuration error, so that an endpoint whose
	 * `signature` child went missing fails at boot -- or, if it was registered from PHP,
	 * on its first request -- rather than accepting everything.
	 * @param mixed $value whether a verifier is required.
	 * @since 0.1.0
	 */
	public function setRequireVerifier($value): void
	{
		$this->_requireVerifier = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return string[] the HTTP methods the endpoint accepts. Defaults to `['POST']`.
	 */
	public function getMethods(): array
	{
		return $this->_methods;
	}

	/**
	 * @param mixed $value the accepted methods, as an array or a comma separated list.
	 * @throws \Prado\Exceptions\TConfigurationException when $value names no method.
	 */
	public function setMethods($value): void
	{
		$methods = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$methods = array_values(array_filter(array_map(
			static fn ($method) => strtoupper(trim((string) $method)),
			$methods
		), static fn ($method) => $method !== ''));
		if ($methods === []) {
			throw new TConfigurationException('webhooks_methods_required', static::class);
		}
		$this->_methods = $methods;
	}

	/**
	 * @return string the value of an `Allow` header for this endpoint.
	 */
	public function getAllow(): string
	{
		return implode(', ', $this->_methods);
	}

	/**
	 * @return null|string the header naming the event, or null when the provider uses none.
	 */
	public function getEventHeader(): ?string
	{
		return $this->_eventHeader;
	}

	/**
	 * @param mixed $value the header naming the event, such as `X-GitHub-Event`.
	 */
	public function setEventHeader($value): void
	{
		$header = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_eventHeader = $header === '' ? null : $header;
	}

	/**
	 * @return null|string the payload property naming the event, or null when the provider
	 *   uses none.
	 */
	public function getEventProperty(): ?string
	{
		return $this->_eventProperty;
	}

	/**
	 * @param mixed $value the payload property naming the event, such as Stripe's `type` or
	 *   PayPal's `event_type`.
	 */
	public function setEventProperty($value): void
	{
		$property = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_eventProperty = $property === '' ? null : $property;
	}

	/**
	 * @return int the largest body accepted, in bytes. Defaults to
	 *   {@see DEFAULT_MAX_BODY_SIZE}.
	 */
	public function getMaxBodySize(): int
	{
		return $this->_maxBodySize;
	}

	/**
	 * Bounds the work an unauthenticated caller can cause: the size is checked before the
	 * body is hashed, so an oversized request costs a `strlen` rather than an HMAC.
	 * @param mixed $value the limit in bytes; 0 or less accepts any body.
	 */
	public function setMaxBodySize($value): void
	{
		$this->_maxBodySize = TPropertyValue::ensureInteger($value);
	}

	/**
	 * @return bool whether a body that is not JSON is rejected. Defaults to true.
	 */
	public function getRequireJson(): bool
	{
		return $this->_requireJson;
	}

	/**
	 * @param mixed $value whether a body that is not JSON is rejected with a 400. Set it
	 *   false for a provider that posts a form or some other encoding, and read
	 *   {@see TWebhookEventParameter::getBody Body} in the handler.
	 */
	public function setRequireJson($value): void
	{
		$this->_requireJson = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return int the status a handled request answers with. Defaults to
	 *   {@see DEFAULT_SUCCESS_STATUS}.
	 */
	public function getSuccessStatus(): int
	{
		return $this->_successStatus;
	}

	/**
	 * @param mixed $value the status a handled request answers with, before any handler
	 *   changes it; 100 to 599.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is not a status code.
	 *   A `SuccessStatus="ok"` would otherwise coerce to 0 and become an error page on
	 *   every accepted delivery.
	 */
	public function setSuccessStatus($value): void
	{
		$status = TPropertyValue::ensureInteger($value);
		if ($status < 100 || $status > 599) {
			throw new TConfigurationException('webhooks_status_invalid', (string) $value);
		}
		$this->_successStatus = $status;
	}
}
