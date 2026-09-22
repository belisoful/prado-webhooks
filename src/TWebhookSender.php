<?php

/**
 * TWebhookSender class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner;
use Belisoful\Prado\Web\Webhooks\Signature\TWebhookSignature;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\IO\HttpClient\THttpClient;
use Prado\IO\HttpClient\THttpClientException;
use Prado\TApplicationComponent;
use Prado\TPropertyValue;
use Prado\Web\THttpHeaderName;
use Prado\Web\TMediaType;

/**
 * TWebhookSender class.
 *
 * The outbound half of the package: posts one payload to every target an application hands
 * it, signs each delivery, retries the failures that are worth retrying, and returns a
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookDelivery} per target.
 *
 * ```php
 * $deliveries = $sender->send($rows, ['invoice' => $invoice->toArray()], 'invoice.paid');
 * ```
 *
 * **Which failures are retried.** A 2xx is delivered and a 4xx is refused: the receiver
 * understood the request and will not like it any better the second time, so retrying it
 * only costs both ends. What is retried is everything that might be transient -- a
 * transport failure, and the statuses in {@see getRetryStatusCodes RetryStatusCodes}, which
 * are the transient 5xx -- 500, 502, 503 and 504 -- plus 408, 425 and 429. A 501 or a 505 is
 * a refusal rather than a hiccup, so neither is in the list. The delay doubles each time from
 * {@see getRetryDelay RetryDelay}, and a `Retry-After` on the response overrides it,
 * because a receiver that says when to come back has told you something the backoff is
 * only guessing at.
 *
 * **Deliveries happen inside the request.** The sender posts when it is called, so a target
 * that is slow to answer is time the user's own request spends waiting: keep
 * {@see getTimeout Timeout} and {@see getMaxAttempts MaxAttempts} small enough that their
 * product is a delay a page can afford. Every delivery is announced through
 * {@see onSending}, {@see onDelivered}, and {@see onFailed}, and a handler of the first may
 * cancel a delivery outright, so an application that outgrows sending inline can record
 * the deliveries and drain them elsewhere without this class changing.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 * @method void dySending(TWebhookDelivery $delivery)
 * @method void dyDelivered(TWebhookDelivery $delivery)
 * @method void dyFailed(TWebhookDelivery $delivery)
 */
class TWebhookSender extends TApplicationComponent
{
	/** @var string the product the default User-Agent names, before its version. */
	public const USER_AGENT_PRODUCT = 'PRADO-Webhooks';

	/** @var int[] the statuses worth trying again, by default. */
	public const DEFAULT_RETRY_STATUS_CODES = [408, 425, 429, 500, 502, 503, 504];

	/** @var int the longest a `Retry-After` is honored for, in milliseconds. */
	public const MAX_RETRY_AFTER = 60000;

	/** @var null|\Prado\IO\HttpClient\THttpClient the transport deliveries go over */
	private ?THttpClient $_httpClient = null;

	/** @var int the per-request timeout in seconds */
	private int $_timeout = 10;

	/** @var int how many times a delivery is attempted */
	private int $_maxAttempts = 3;

	/** @var int the first retry delay in milliseconds */
	private int $_retryDelay = 500;

	/** @var int[] the statuses worth trying again */
	private array $_retryStatusCodes = self::DEFAULT_RETRY_STATUS_CODES;

	/** @var null|string the User-Agent deliveries carry; null takes the default */
	private ?string $_userAgent = null;

	/** @var null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner the signer a target without one uses */
	private ?IWebhookSigner $_signature = null;

	/**
	 * Delivers one payload to every target that wants it.
	 *
	 * Targets are whatever the application keeps them as -- see
	 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookTarget::ensure} for the shorthands -- and
	 * a single target need not be wrapped in an array. Targets that are disabled, or that
	 * subscribe to other events, are skipped and produce no delivery.
	 *
	 * @param mixed $targets the targets, or one target.
	 * @param mixed $payload the payload, encoded per the target's content type.
	 * @param null|string $event the event name, sent as a header and matched against each
	 *   target's subscription.
	 * @throws \Prado\Exceptions\TConfigurationException when a target cannot be built.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the payload cannot be encoded.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookDelivery[] one delivery per target that
	 *   wanted the event, in the order the targets were given.
	 */
	public function send(mixed $targets, mixed $payload, ?string $event = null): array
	{
		if ($targets instanceof TWebhookTarget || is_string($targets) || !is_iterable($targets)) {
			$targets = [$targets];
		}

		$deliveries = [];
		foreach ($targets as $spec) {
			$target = TWebhookTarget::ensure($spec);
			if (!$target->getEnabled() || !$target->acceptsEvent($event)) {
				continue;
			}
			$deliveries[] = $this->deliver($target, $payload, $event);
		}

		return $deliveries;
	}

	/**
	 * Delivers one payload to one target, retrying as the policy allows.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookTarget $target where to deliver.
	 * @param mixed $payload the payload.
	 * @param null|string $event the event name, when it has one.
	 * @param null|string $id the id the receiver is shown; one is minted when it is not
	 *   given. A queued delivery passes the id it was stored under, so every attempt the
	 *   queue makes over the following hours carries the same one.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the payload cannot be encoded.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookDelivery the delivery, attempted or cancelled.
	 */
	public function deliver(TWebhookTarget $target, mixed $payload, ?string $event = null, ?string $id = null): TWebhookDelivery
	{
		$id ??= $this->newDeliveryId();
		$body = $this->encodePayload($payload, $target->getContentType());
		$delivery = new TWebhookDelivery($target, $id, $payload, $body, $event);
		$delivery->setHeaders(
			$target->buildHeaders($event, $id) + [THttpHeaderName::UserAgent => $this->getUserAgent()]
		);

		$this->onSending($delivery);
		if ($delivery->getCancel()) {
			return $delivery;
		}

		$client = $this->getHttpClient();
		$client->setTimeout($target->getTimeout() ?: $this->_timeout);
		$attempts = $target->getMaxAttempts() ?: $this->_maxAttempts;
		$delay = $target->getRetryDelay() ?: $this->_retryDelay;
		$started = microtime(true);

		for ($attempt = 1; $attempt <= $attempts; $attempt++) {
			$delivery->setAttempts($attempt);
			$wait = $delay * (2 ** ($attempt - 1));

			try {
				// Signed per attempt, not once: a timestamped scheme signs the moment it is
				// sent, and a signature made before a backoff would be stale by the time the
				// retry arrives.
				$response = $client->download(
					$target->getMethod(),
					$target->getUrl(),
					$this->signHeaders($target, $delivery),
					$delivery->getBody()
				);
				$delivery->setResponse($response);
				if ($response->isSuccess() || !$this->isRetryable($response->getStatusCode())) {
					break;
				}
				$wait = $this->retryAfter($response) ?? $wait;
			} catch (THttpClientException $e) {
				$delivery->setError($e->getMessage());
			}

			if ($attempt < $attempts) {
				$this->pause((int) $wait);
			}
		}

		$delivery->setDuration(microtime(true) - $started);
		if ($delivery->getSuccessful()) {
			$this->onDelivered($delivery);
		} else {
			$this->onFailed($delivery);
		}

		return $delivery;
	}

	/**
	 * Adds the signature headers to a delivery's own.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookTarget $target the target being delivered to.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookDelivery $delivery the delivery.
	 * @throws \Prado\Exceptions\TConfigurationException when the signer is not configured.
	 * @return array<string, string> the headers to send.
	 */
	protected function signHeaders(TWebhookTarget $target, TWebhookDelivery $delivery): array
	{
		$signer = $target->getSignature() ?? $this->_signature;
		$headers = $delivery->getHeaders();
		if ($signer === null) {
			return $headers;
		}

		// A scheme that signs a delivery id is given this delivery's own, so the id a
		// receiver deduplicates on is the same on every attempt. Left to itself the scheme
		// would mint a fresh one per attempt, and a retried delivery would look like a new
		// one. Anything already in the headers wins, so a target can still set its own.
		if ($signer instanceof TWebhookSignature && ($idName = $signer->getIdName()) !== null) {
			$headers += [$idName => $delivery->getID()];
		}

		// The signer is shown the whole outbound request, not just the body, because the
		// scheme on the other end may be one that signs the URL or the method.
		$request = new TWebhookRequest($target->getMethod(), $delivery->getBody(), $headers, $target->getUrl());

		return array_merge($headers, $signer->sign($request));
	}

	/**
	 * Encodes a payload for the wire.
	 *
	 * A string is sent as it is, on the assumption that an application handing over bytes
	 * has its reasons; anything else is encoded as the content type asks.
	 *
	 * @param mixed $payload the payload.
	 * @param string $contentType the target's content type.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the payload cannot be encoded.
	 * @return string the request body.
	 */
	protected function encodePayload(mixed $payload, string $contentType): string
	{
		if (is_string($payload)) {
			return $payload;
		}
		if (str_starts_with(strtolower($contentType), TMediaType::FORM)) {
			if (!is_array($payload) && !is_object($payload)) {
				throw new TInvalidDataValueException('webhooks_payload_invalid', get_debug_type($payload));
			}

			return http_build_query($payload);
		}

		$body = json_encode($payload);
		if ($body === false) {
			throw new TInvalidDataValueException('webhooks_payload_invalid', json_last_error_msg());
		}

		return $body;
	}

	/**
	 * @param int $statusCode the status the target answered with.
	 * @return bool whether the delivery is worth attempting again.
	 */
	protected function isRetryable(int $statusCode): bool
	{
		return in_array($statusCode, $this->_retryStatusCodes, true);
	}

	/**
	 * Reads a `Retry-After` as a delay, when the response gives one this package can use.
	 *
	 * Only the delta-seconds form is honored. The HTTP-date form is legal but rare from the
	 * services that send it, and a date pointing hours out is not something to hold a
	 * request open for.
	 *
	 * @param \Prado\IO\HttpClient\THttpClientResponse $response the response.
	 * @return null|int the delay in milliseconds, capped at {@see MAX_RETRY_AFTER}, or null
	 *   when the header is absent or not a number of seconds.
	 */
	protected function retryAfter(\Prado\IO\HttpClient\THttpClientResponse $response): ?int
	{
		$header = $response->getHeader(THttpHeaderName::RetryAfter);
		if ($header === null || !is_numeric(trim($header))) {
			return null;
		}

		return min((int) ((float) trim($header) * 1000), self::MAX_RETRY_AFTER);
	}

	/**
	 * Waits between attempts. Overriding this is how a test runs the retry policy without
	 * spending the wall clock on it.
	 * @param int $milliseconds how long to wait.
	 */
	protected function pause(int $milliseconds): void
	{
		if ($milliseconds > 0) {
			usleep($milliseconds * 1000);
		}
	}

	/**
	 * @return string a new delivery id, unique enough for a receiver to deduplicate on.
	 */
	protected function newDeliveryId(): string
	{
		return bin2hex(random_bytes(16));
	}

	/**
	 * Raises the `OnSending` event, once per delivery, before the first attempt.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookDelivery $delivery the delivery, still editable.
	 */
	public function onSending(TWebhookDelivery $delivery): void
	{
		$this->raiseEvent('onSending', $this, $delivery);
	}

	/**
	 * Raises the `OnDelivered` event, once per delivery the target accepted.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookDelivery $delivery the delivery.
	 */
	public function onDelivered(TWebhookDelivery $delivery): void
	{
		$this->raiseEvent('onDelivered', $this, $delivery);
	}

	/**
	 * Raises the `OnFailed` event, once per delivery that ran out of attempts.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookDelivery $delivery the delivery, whose
	 *   {@see TWebhookDelivery::getStatusText StatusText} says how it ended.
	 */
	public function onFailed(TWebhookDelivery $delivery): void
	{
		$this->raiseEvent('onFailed', $this, $delivery);
	}

	/**
	 * @return \Prado\IO\HttpClient\THttpClient the transport deliveries go over. Created by
	 *   {@see \Prado\IO\HttpClient\THttpClient::create} on first use, which is cURL where
	 *   the extension is loaded and PHP streams otherwise.
	 */
	public function getHttpClient(): THttpClient
	{
		if ($this->_httpClient === null) {
			$this->_httpClient = THttpClient::create();
			$this->_httpClient->setFollowRedirects(false);
		}

		return $this->_httpClient;
	}

	/**
	 * Sets the transport, which is how a test delivers without a network and how an
	 * application substitutes a client of its own.
	 * @param null|\Prado\IO\HttpClient\THttpClient $value the transport, or null to build the
	 *   default again on next use.
	 */
	public function setHttpClient(?THttpClient $value): void
	{
		$this->_httpClient = $value;
	}

	/**
	 * @return int the per-request timeout in seconds. Defaults to 10.
	 */
	public function getTimeout(): int
	{
		return $this->_timeout;
	}

	/**
	 * @param mixed $value the timeout in seconds. This bounds one attempt, so the worst case
	 *   for a target is roughly this times {@see getMaxAttempts MaxAttempts}.
	 */
	public function setTimeout($value): void
	{
		$this->_timeout = max(1, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int how many times a delivery is attempted. Defaults to 3.
	 */
	public function getMaxAttempts(): int
	{
		return $this->_maxAttempts;
	}

	/**
	 * @param mixed $value the attempt count, including the first; 1 disables retrying.
	 */
	public function setMaxAttempts($value): void
	{
		$this->_maxAttempts = max(1, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int the first retry delay in milliseconds. Defaults to 500.
	 */
	public function getRetryDelay(): int
	{
		return $this->_retryDelay;
	}

	/**
	 * @param mixed $value the first retry delay in milliseconds; it doubles on each further
	 *   attempt.
	 */
	public function setRetryDelay($value): void
	{
		$this->_retryDelay = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int[] the statuses worth trying again. Defaults to
	 *   {@see DEFAULT_RETRY_STATUS_CODES}.
	 */
	public function getRetryStatusCodes(): array
	{
		return $this->_retryStatusCodes;
	}

	/**
	 * @param mixed $value the statuses, as an array or a comma separated list.
	 */
	public function setRetryStatusCodes($value): void
	{
		$codes = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$this->_retryStatusCodes = array_values(array_filter(array_map(
			static fn ($code) => (int) trim((string) $code),
			$codes
		)));
	}

	/**
	 * @return string the User-Agent deliveries carry. Defaults to
	 *   {@see getDefaultUserAgent}.
	 */
	public function getUserAgent(): string
	{
		return $this->_userAgent ?? self::getDefaultUserAgent();
	}

	/**
	 * @param mixed $value the User-Agent, which is what a receiver's logs will show this
	 *   application as. An empty value goes back to the default rather than sending no
	 *   product at all.
	 */
	public function setUserAgent($value): void
	{
		$agent = TPropertyValue::ensureString($value ?? '');
		$this->_userAgent = $agent === '' ? null : $agent;
	}

	/**
	 * The default User-Agent: the product, then the version this package is running at.
	 *
	 * Computed rather than written down, so a release does not leave a stale number in a
	 * header that receivers log. See {@see TWebhookModule::getVersion}.
	 *
	 * @return string the default User-Agent.
	 */
	public static function getDefaultUserAgent(): string
	{
		return self::USER_AGENT_PRODUCT . '/' . TWebhookModule::getVersion();
	}

	/**
	 * @return null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner the signer used for
	 *   targets that carry none of their own.
	 */
	public function getSignature(): ?IWebhookSigner
	{
		return $this->_signature;
	}

	/**
	 * Sets the signer for targets that carry none. Useful when every subscriber shares one
	 * secret; a per-subscriber secret belongs on the target instead, so that one subscriber
	 * cannot forge a delivery to another.
	 * @param null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner $value the signer.
	 */
	public function setSignature(?IWebhookSigner $value): void
	{
		$this->_signature = $value;
	}
}
