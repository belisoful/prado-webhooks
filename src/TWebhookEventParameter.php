<?php

/**
 * TWebhookEventParameter class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\Exceptions\TInvalidDataValueException;
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
 * body, never the decoded copy, so the two are kept separate here as well. The body is
 * decoded the first time the payload is read, not when the parameter is built, so a
 * delivery the endpoint refuses -- wrong method, too large, unsigned -- is never parsed at
 * all; {@see getPayloadDecoded PayloadDecoded} says whether it has been.
 *
 * A handler that leaves the response alone answers with the endpoint's
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint::getSuccessStatus SuccessStatus} and
 * an empty body. Providers read the status to decide whether to redeliver, so a handler
 * that fails should say so with {@see setStatusCode} rather than by throwing -- an
 * uncaught exception reaches the provider as a PRADO error page, which is both a 500 and
 * an information leak. A body set on the default 204 is answered as a 200, because a 204
 * cannot carry one; a string body goes out as `text/plain` and an array as
 * `application/json` unless {@see setResponseContentType ResponseContentType} says
 * otherwise.
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

	/** @var bool whether the endpoint accepted the delivery and raised its event */
	private bool $_accepted = false;

	/** @var bool whether the body has been decoded into the parameter */
	private bool $_decoded = false;

	/** @var bool whether the body decoded as JSON; meaningless until decoded */
	private bool $_payloadIsJson = false;

	/** @var int the HTTP status to answer with */
	private int $_statusCode = TWebhookEndpoint::DEFAULT_SUCCESS_STATUS;

	/** @var null|string the response body, or null for an empty response */
	private ?string $_responseBody = null;

	/** @var bool whether the response body was encoded from an array or object */
	private bool $_responseBodyEncoded = false;

	/** @var null|string the media type of the response body, or null to derive it */
	private ?string $_responseContentType = null;

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint $endpoint the receiving endpoint.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 */
	public function __construct(TWebhookEndpoint $endpoint, TWebhookRequest $request)
	{
		$this->_endpoint = $endpoint;
		$this->_request = $request;

		// The decoded payload becomes the event parameter itself, which is what gives
		// handlers array access to it -- but not yet. Decoding waits for the first read, so
		// the method, size and signature checks cost an attacker nothing more than they say.
		parent::__construct(null);
		// The parent constructor goes through setParameter, which would count as decoded.
		$this->_decoded = false;
		$this->_payloadIsJson = false;
	}

	/**
	 * Decodes the body into the parameter, once.
	 *
	 * The endpoint calls this after the signature has been verified, and every read of the
	 * payload calls it too, so a handler reached by some other path still sees the decoded
	 * body. A body that is not JSON decodes to null rather than failing: whether that is
	 * acceptable is the endpoint's `RequireJson` decision, not this one.
	 *
	 * @since 0.2.0
	 */
	public function decodePayload(): void
	{
		if ($this->_decoded) {
			return;
		}
		$this->_decoded = true;
		$decoded = json_decode($this->_request->getBody(), true);
		$this->_payloadIsJson = json_last_error() === JSON_ERROR_NONE;
		parent::setParameter($decoded);
		$this->resetParameterChanged();
	}

	/**
	 * @return bool whether the body has been decoded yet. False for a refused delivery,
	 *   which is the point: nothing parses a request the endpoint did not accept.
	 * @since 0.2.0
	 */
	public function getPayloadDecoded(): bool
	{
		return $this->_decoded;
	}

	/**
	 * @return bool whether the body is well-formed JSON. Decodes it if nothing has yet. A
	 *   body holding the literal `null` is JSON; an empty or malformed one is not.
	 * @since 0.2.0
	 */
	public function getPayloadIsJson(): bool
	{
		$this->decodePayload();

		return $this->_payloadIsJson;
	}

	/**
	 * @return mixed the decoded payload, decoding it first if nothing has yet.
	 */
	public function getParameter(): mixed
	{
		$this->decodePayload();

		return parent::getParameter();
	}

	/**
	 * Replaces the payload. A value set here is what handlers see from then on; the body is
	 * not decoded over it.
	 * @param mixed $value the payload.
	 */
	public function setParameter(mixed $value)
	{
		$this->_decoded = true;
		$this->_payloadIsJson = true;
		parent::setParameter($value);
	}

	/**
	 * @return bool whether the decoded payload is an array.
	 */
	public function getParameterIsArray(): bool
	{
		$this->decodePayload();

		return parent::getParameterIsArray();
	}

	/**
	 * @param mixed $offset the payload key.
	 * @return bool whether the decoded payload has that key.
	 */
	public function offsetExists($offset): bool
	{
		$this->decodePayload();

		return parent::offsetExists($offset);
	}

	/**
	 * @param mixed $offset the payload key.
	 * @return mixed the value at that key, or null.
	 */
	public function offsetGet($offset): mixed
	{
		$this->decodePayload();

		return parent::offsetGet($offset);
	}

	/**
	 * @param mixed $offset the payload key.
	 * @param mixed $item the value to set.
	 */
	public function offsetSet($offset, $item): void
	{
		$this->decodePayload();
		parent::offsetSet($offset, $item);
	}

	/**
	 * @param mixed $offset the payload key.
	 */
	public function offsetUnset($offset): void
	{
		$this->decodePayload();
		parent::offsetUnset($offset);
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
	 * @return bool whether the endpoint accepted the delivery: every check passed and its
	 *   `onWebhook` was raised. False for a refused one, whatever status a handler set since.
	 * @since 0.2.0
	 */
	public function getAccepted(): bool
	{
		return $this->_accepted;
	}

	/**
	 * @param mixed $value whether the endpoint accepted the delivery.
	 * @since 0.2.0
	 */
	public function setAccepted($value): void
	{
		$this->_accepted = TPropertyValue::ensureBoolean($value);
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
	 * @param mixed $value the HTTP status code, 100 to 599.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value is not a status code.
	 *   Refused here rather than at write time, where it would become an error page.
	 */
	public function setStatusCode($value): void
	{
		$status = TPropertyValue::ensureInteger($value);
		if ($status < 100 || $status > 599) {
			throw new TInvalidDataValueException('webhooks_status_invalid', (string) $value);
		}
		$this->_statusCode = $status;
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
	 * @throws \Prado\Exceptions\TInvalidDataValueException when an array or object cannot
	 *   be encoded, rather than answering with an empty body and a success.
	 */
	public function setResponseBody($value): void
	{
		if ($value === null) {
			$this->_responseBody = null;
			$this->_responseBodyEncoded = false;
		} elseif (is_array($value) || is_object($value)) {
			$encoded = json_encode($value);
			if ($encoded === false) {
				throw new TInvalidDataValueException('webhooks_response_invalid', json_last_error_msg());
			}
			$this->_responseBody = $encoded;
			$this->_responseBodyEncoded = true;
		} else {
			$this->_responseBody = TPropertyValue::ensureString($value);
			$this->_responseBodyEncoded = false;
		}
	}

	/**
	 * @return string the media type of the response body. Unless set, `text/plain` for a
	 *   string body and `application/json` for an encoded one or none.
	 */
	public function getResponseContentType(): string
	{
		if ($this->_responseContentType !== null) {
			return $this->_responseContentType;
		}

		return ($this->_responseBody === null || $this->_responseBodyEncoded) ? TMediaType::JSON : TMediaType::PLAIN;
	}

	/**
	 * @param mixed $value the media type of the response body; empty or null goes back to
	 *   deriving it from the body.
	 */
	public function setResponseContentType($value): void
	{
		$type = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_responseContentType = $type === '' ? null : $type;
	}
}
