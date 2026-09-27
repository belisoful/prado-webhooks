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
use Throwable;

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
 * {@see getRetryDelay RetryDelay} up to {@see getMaxRetryDelay MaxRetryDelay}, and a
 * `Retry-After` on the response overrides it, because a receiver that says when to come
 * back has told you something the backoff is only guessing at. The same ceiling applies to
 * what a `Retry-After` asks for: a date hours out is not something to hold a request open
 * for.
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

	/** @var int the longest wait between attempts, and the longest a `Retry-After` is honored for, in milliseconds. */
	public const MAX_RETRY_AFTER = 60000;

	/** @var int the highest power of two the backoff reaches before the ceiling alone bounds it. */
	private const MAX_BACKOFF_EXPONENT = 30;

	/** @var null|\Prado\IO\HttpClient\THttpClient the transport deliveries go over */
	private ?THttpClient $_httpClient = null;

	/** @var int the per-request timeout in seconds */
	private int $_timeout = 10;

	/** @var int how many times a delivery is attempted */
	private int $_maxAttempts = 3;

	/** @var int the first retry delay in milliseconds */
	private int $_retryDelay = 500;

	/** @var int the longest wait between attempts, in milliseconds */
	private int $_maxRetryDelay = self::MAX_RETRY_AFTER;

	/** @var bool whether a throwing delivery event handler is recorded rather than propagated */
	private bool $_containHandlerErrors = false;

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

		// Every target is built before any is delivered to. Built one at a time inside the
		// loop, a bad specification at position N would throw after 1..N-1 had already been
		// sent -- and their delivery records would be lost with the exception.
		$built = [];
		foreach ($targets as $spec) {
			$target = TWebhookTarget::ensure($spec);
			if ($target->getEnabled() && $target->acceptsEvent($event)) {
				$built[] = $target;
			}
		}

		$deliveries = [];
		foreach ($built as $target) {
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
		// Set on every delivery rather than once when the client is built, so a client an
		// application substituted cannot follow a 3xx to somewhere the subscriber did not name.
		$client->setFollowRedirects(false);
		$attempts = $target->getMaxAttempts() ?: $this->_maxAttempts;
		$delay = $target->getRetryDelay() ?: $this->_retryDelay;
		$started = microtime(true);

		for ($attempt = 1; $attempt <= $attempts; $attempt++) {
			$delivery->setAttempts($attempt);
			$wait = $this->backoff($delay, $attempt);

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
		$this->raiseDeliveryEvents($delivery);

		return $delivery;
	}

	/**
	 * Raises {@see onDelivered} or {@see onFailed}, whichever the delivery earned.
	 *
	 * By the time this runs the request has been made and answered, so what a handler does
	 * cannot change whether the receiver has the delivery. With
	 * {@see getContainHandlerErrors ContainHandlerErrors} on, a handler that throws is
	 * recorded on the delivery as its {@see TWebhookDelivery::getHandlerError HandlerError}
	 * rather than propagated -- which is what a queue drain needs, so that an accepted
	 * delivery is not mistaken for a failed attempt and sent again. Off, which is the
	 * default, the exception propagates as it always has.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookDelivery $delivery the delivery, attempted.
	 * @throws \Throwable what a handler threw, unless errors are being contained.
	 * @since 0.1.0
	 */
	protected function raiseDeliveryEvents(TWebhookDelivery $delivery): void
	{
		try {
			if ($delivery->getSuccessful()) {
				$this->onDelivered($delivery);
			} else {
				$this->onFailed($delivery);
			}
		} catch (Throwable $e) {
			if (!$this->_containHandlerErrors) {
				throw $e;
			}
			$delivery->setHandlerError($e->getMessage());
		}
	}

	/**
	 * The wait before the next attempt, doubling from $delay and never above
	 * {@see getMaxRetryDelay MaxRetryDelay}.
	 *
	 * The exponent is capped before it is raised, not after: `2 ** 63` is already past what an
	 * integer holds, and PHP answers with a float that a cast turns into 0 -- at which point a
	 * retry that should have waited a minute waits nothing at all.
	 *
	 * @param int $delay the first retry delay in milliseconds.
	 * @param int $attempt the attempt just made, from 1.
	 * @return int how long to wait, in milliseconds.
	 * @since 0.1.0
	 */
	protected function backoff(int $delay, int $attempt): int
	{
		$exponent = min(max(0, $attempt - 1), self::MAX_BACKOFF_EXPONENT);

		return (int) min(max(0, $delay) * (2 ** $exponent), $this->_maxRetryDelay);
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
		// one. Anything already in the headers wins, so a target can still set its own. A
		// TFieldedWebhookSignature packs its id into the signature value rather than a
		// header, and reads it from here under the same IdName -- so a fielded scheme with
		// an IdField needs an IdName as well, or its packed id is minted per attempt.
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
	 * @param \Prado\IO\HttpClient\THttpClientResponse $response the response.
	 * @return null|int the delay in milliseconds, capped at {@see getMaxRetryDelay
	 *   MaxRetryDelay}, or null when the header is absent or unreadable.
	 */
	protected function retryAfter(\Prado\IO\HttpClient\THttpClientResponse $response): ?int
	{
		$delay = $this->parseRetryAfter($response);

		return $delay === null ? null : min($delay, $this->_maxRetryDelay);
	}

	/**
	 * Reads what a response's `Retry-After` asks for, before any ceiling is applied.
	 *
	 * Both forms of RFC 9110 §10.2.3 are read: a number of seconds, and an HTTP-date, which
	 * becomes the time from now until then. A date already past, or a negative number, is
	 * a request to come back now rather than a wait of less than nothing. The cap is the
	 * caller's, because it differs by caller: a request being held open has
	 * {@see getMaxRetryDelay MaxRetryDelay}, and a queue spreading attempts over hours has
	 * its own.
	 *
	 * @param \Prado\IO\HttpClient\THttpClientResponse $response the response.
	 * @return null|int the delay in milliseconds, at least 0, or null when the header is
	 *   absent or neither a number nor a date.
	 * @since 0.1.0
	 */
	public function parseRetryAfter(\Prado\IO\HttpClient\THttpClientResponse $response): ?int
	{
		$header = $response->getHeader(THttpHeaderName::RetryAfter);
		if ($header === null || trim($header) === '') {
			return null;
		}
		$header = trim($header);
		if (is_numeric($header)) {
			return max(0, (int) ((float) $header * 1000));
		}
		$at = strtotime($header);
		if ($at === false) {
			return null;
		}

		return max(0, $at - time()) * 1000;
	}

	/**
	 * Waits between attempts. Overriding this is how a test runs the retry policy without
	 * spending the wall clock on it.
	 *
	 * The wait is taken a second at a time: `usleep` is only required to work for arguments
	 * under a second, and some platforms honor nothing above it.
	 *
	 * @param int $milliseconds how long to wait.
	 */
	protected function pause(int $milliseconds): void
	{
		$remaining = $milliseconds;
		while ($remaining > 0) {
			$chunk = min($remaining, 1000);
			usleep($chunk * 1000);
			$remaining -= $chunk;
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
	 *
	 * Whatever the client's own `FollowRedirects` says, deliveries do not follow redirects:
	 * {@see deliver} turns it off on every delivery, because following a 3xx would post the
	 * signed body somewhere the subscriber did not name.
	 *
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
	 * @return int the longest wait between attempts, in milliseconds. Defaults to
	 *   {@see MAX_RETRY_AFTER}.
	 * @since 0.1.0
	 */
	public function getMaxRetryDelay(): int
	{
		return $this->_maxRetryDelay;
	}

	/**
	 * Sets the ceiling on the wait between attempts, which bounds both the doubling backoff
	 * and what a `Retry-After` is honored for. Deliveries happen inside a request, so this
	 * is the longest a page ever waits for one target between two attempts.
	 * @param mixed $value the ceiling in milliseconds; at least 1.
	 * @since 0.1.0
	 */
	public function setMaxRetryDelay($value): void
	{
		$this->_maxRetryDelay = max(1, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return bool whether a delivery event handler that throws is recorded on the delivery
	 *   rather than propagated. Defaults to false.
	 * @since 0.1.0
	 */
	public function getContainHandlerErrors(): bool
	{
		return $this->_containHandlerErrors;
	}

	/**
	 * Sets whether an exception from an {@see onDelivered} or {@see onFailed} handler is
	 * contained. On, the delivery carries it as its
	 * {@see TWebhookDelivery::getHandlerError HandlerError} and {@see deliver} returns
	 * normally; off, it propagates. {@see TWebhookModule::drain} turns this on for the
	 * length of a run, because the request has already been made by the time a handler runs,
	 * and an accepted delivery that looked like a failed attempt would be sent again.
	 * @param mixed $value whether to contain handler errors.
	 * @since 0.1.0
	 */
	public function setContainHandlerErrors($value): void
	{
		$this->_containHandlerErrors = TPropertyValue::ensureBoolean($value);
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
