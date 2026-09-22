<?php

/**
 * TWebhookEventParameter class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\TEventParameter;
use Prado\TPropertyValue;
use Prado\Web\TMediaType;

/**
 * TWebhookEventParameter class.
 *
 * One inbound webhook request, as handlers of
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint::onWebhook onWebhook} see it, and
 * the response they may shape on the way back out.
 *
 * The decoded payload is the {@see \Prado\TEventParameter} parameter, so a handler can
 * subscript the event parameter directly:
 *
 * ```php
 * public function githubPush(TWebhookEndpoint $sender, TWebhookEventParameter $param): void
 * {
 *		if ($param->getEvent() !== 'push') {
 *			return;
 *		}
 *		$this->deploy($param['repository']['full_name'], $param['after']);
 *		$param->setResponseBody('queued');
 * }
 * ```
 *
 * {@see getBody Body} holds the bytes as received; {@see getPayload Payload} holds them
 * decoded, or null when the body was not JSON. Signature verification runs against the raw
 * body, never the decoded copy, so the two are kept separate here as well.
 *
 * A handler that leaves the response alone answers with the endpoint's
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint::getSuccessStatus SuccessStatus} and
 * an empty body. Providers read the status to decide whether to redeliver, so a handler
 * that fails should say so with {@see setStatusCode} rather than by throwing -- an
 * uncaught exception reaches the provider as a PRADO error page, which is both a 500 and
 * an information leak.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TWebhookEventParameter extends TEventParameter
{
	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint the endpoint that received the request */
	private TWebhookEndpoint $_endpoint;

	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookRequest the request as received */
	private TWebhookRequest $_request;

	/** @var bool whether the signature was verified, or no verifier was configured */
	private bool $_verified = false;

	/** @var int the HTTP status to answer with */
	private int $_statusCode = TWebhookEndpoint::DEFAULT_SUCCESS_STATUS;

	/** @var null|string the response body, or null for an empty response */
	private ?string $_responseBody = null;

	/** @var string the media type of the response body */
	private string $_responseContentType = TMediaType::JSON;

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint $endpoint the receiving endpoint.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 */
	public function __construct(TWebhookEndpoint $endpoint, TWebhookRequest $request)
	{
		$this->_endpoint = $endpoint;
		$this->_request = $request;

		// The decoded payload is the event parameter itself, which is what gives handlers
		// array access to it. A body that is not JSON decodes to null rather than failing:
		// whether that is acceptable is the endpoint's RequireJson decision, not this one.
		parent::__construct(json_decode($request->getBody(), true));
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookRequest the request as received, which
	 *   is what the endpoint's verifier was given.
	 */
	public function getRequest(): TWebhookRequest
	{
		return $this->_request;
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint the endpoint that received the request.
	 */
	public function getEndpoint(): TWebhookEndpoint
	{
		return $this->_endpoint;
	}

	/**
	 * @return string the HTTP method of the request, upper case.
	 */
	public function getMethod(): string
	{
		return $this->_request->getMethod();
	}

	/**
	 * @return string the raw request body, byte for byte as received.
	 */
	public function getBody(): string
	{
		return $this->_request->getBody();
	}

	/**
	 * @return array<string, string> the request headers, in whatever case the server gave them.
	 */
	public function getHeaders(): array
	{
		return $this->_request->getHeaders();
	}

	/**
	 * Reads one request header without regard to the case of its name.
	 * @param string $name the header name.
	 * @return null|string the header value, or null when the header is absent.
	 */
	public function getHeader(string $name): ?string
	{
		return $this->_request->getHeader($name);
	}

	/**
	 * @return mixed the decoded JSON payload, or null when the body was not JSON.
	 */
	public function getPayload(): mixed
	{
		return $this->getParameter();
	}

	/**
	 * Returns the provider's name for what happened, from wherever the endpoint says the
	 * provider puts it: a header, for GitHub (`X-GitHub-Event`) and Postmark; a property of
	 * the payload, for Stripe (`type`) and PayPal (`event_type`).
	 * @return null|string the event name, or null when the endpoint names no source for it or
	 *   this request carries none.
	 */
	public function getEvent(): ?string
	{
		$header = $this->_endpoint->getEventHeader();
		if ($header !== null && ($value = $this->getHeader($header)) !== null) {
			return $value;
		}
		$property = $this->_endpoint->getEventProperty();
		$payload = $this->getParameter();
		if ($property !== null && is_array($payload) && is_scalar($payload[$property] ?? null)) {
			return (string) $payload[$property];
		}

		return null;
	}

	/**
	 * @return bool whether the request was authenticated. False until the endpoint has
	 *   verified it, and never true for a request whose signature did not check out, so a
	 *   handler reached through some other path can still tell.
	 */
	public function getVerified(): bool
	{
		return $this->_verified;
	}

	/**
	 * @param mixed $value whether the request was authenticated.
	 */
	public function setVerified($value): void
	{
		$this->_verified = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return int the HTTP status to answer with.
	 */
	public function getStatusCode(): int
	{
		return $this->_statusCode;
	}

	/**
	 * Sets the status the provider will see. Most providers treat any 2xx as delivered and
	 * retry on 5xx, so a handler that could not do its work should answer 500 to be sent the
	 * same webhook again, and 4xx to be left alone.
	 * @param mixed $value the HTTP status code.
	 */
	public function setStatusCode($value): void
	{
		$this->_statusCode = TPropertyValue::ensureInteger($value);
	}

	/**
	 * @return null|string the response body, or null for an empty response.
	 */
	public function getResponseBody(): ?string
	{
		return $this->_responseBody;
	}

	/**
	 * @param mixed $value the response body; an array or object is encoded as JSON.
	 */
	public function setResponseBody($value): void
	{
		if ($value === null) {
			$this->_responseBody = null;
		} elseif (is_array($value) || is_object($value)) {
			$this->_responseBody = (string) json_encode($value);
		} else {
			$this->_responseBody = TPropertyValue::ensureString($value);
		}
	}

	/**
	 * @return string the media type of the response body. Defaults to `application/json`.
	 */
	public function getResponseContentType(): string
	{
		return $this->_responseContentType;
	}

	/**
	 * @param mixed $value the media type of the response body.
	 */
	public function setResponseContentType($value): void
	{
		$this->_responseContentType = TPropertyValue::ensureString($value);
	}
}
