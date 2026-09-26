<?php

/**
 * TWebhookTarget class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner;
use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidOperationException;
use Prado\TApplicationComponent;
use Prado\TPropertyValue;
use Prado\Web\THttpHeaderName;
use Prado\Web\TMediaType;

/**
 * TWebhookTarget class.
 *
 * One outbound webhook subscription: where to post, how to sign it, and which events it
 * wants. This package deliberately does not store or own these -- which URLs a user has
 * subscribed, and for what, belongs to the application -- so
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookSender::send} takes whatever list the
 * application hands it and {@see ensure} turns each item into a target.
 *
 * The shorthand forms cost an application nothing to produce from its own tables:
 *
 * ```php
 * $module->send('https://example.com/hooks/prado', $payload);
 *
 * $module->send([
 *		['url' => $row['url'], 'secret' => $row['secret'], 'events' => ['invoice.paid']],
 *		['url' => $other['url'], 'secret' => $other['secret']],
 * ], $payload, 'invoice.paid');
 * ```
 *
 * `secret` is shorthand for an {@see \Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature}
 * keyed with it; every other key sets the property of the same name. A target built by
 * hand, or configured in XML, can use any signer instead.
 *
 * {@see getData Data} carries whatever the application needs to recognize the target
 * again -- a subscription id, a row -- back to it in the delivery events; nothing in this
 * package reads it.
 *
 * ## Refusing URLs
 *
 * {@see setUrl Url} accepts any absolute `http` or `https` URL, and a subscriber choosing the
 * URL chooses where the application posts: an internal address, a metadata service, the
 * application itself. An application that lets users subscribe should install a
 * {@see setUrlValidator UrlValidator}, one callable for the whole process, and every target
 * built afterwards is checked against it. One that refuses the private, loopback and
 * link-local ranges when the host is written as an address:
 *
 * ```php
 * TWebhookTarget::setUrlValidator(static function (string $url): bool {
 *		$host = trim((string) parse_url($url, PHP_URL_HOST), '[]');
 *		if (filter_var($host, FILTER_VALIDATE_IP) === false) {
 *			return true;   // a name: resolve it here and check what it resolves to, or refuse names
 *		}
 *		// Refuses 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16,
 *		// ::1, fc00::/7 and fe80::/10, among others.
 *		return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
 * });
 * ```
 *
 * This package resolves no names itself: which resolver to trust, and what to do about a
 * name that resolves to a private address only on the second lookup, are the application's
 * decisions.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TWebhookTarget extends TApplicationComponent
{
	/** @var string the header naming the event, by default. */
	public const DEFAULT_EVENT_HEADER = 'X-Webhook-Event';

	/** @var string the header carrying the delivery id, by default. */
	public const DEFAULT_DELIVERY_HEADER = 'X-Webhook-Delivery';

	/** @var null|callable the application's say over which URLs may be targets */
	private static $_urlValidator;

	/** @var string where the delivery is posted */
	private string $_url = '';

	/** @var string the HTTP method used to deliver */
	private string $_method = 'POST';

	/** @var string the media type the payload is encoded as */
	private string $_contentType = TMediaType::JSON;

	/** @var array<string, string> headers added to every delivery */
	private array $_headers = [];

	/** @var null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner how deliveries are signed */
	private ?IWebhookSigner $_signature = null;

	/** @var null|string[] the events this target wants, or null for every event */
	private ?array $_events = null;

	/** @var string the header naming the event */
	private string $_eventHeader = self::DEFAULT_EVENT_HEADER;

	/** @var string the header carrying the delivery id */
	private string $_deliveryHeader = self::DEFAULT_DELIVERY_HEADER;

	/** @var int the per-request timeout in seconds; 0 takes the sender's */
	private int $_timeout = 0;

	/** @var int how many times a delivery is attempted; 0 takes the sender's */
	private int $_maxAttempts = 0;

	/** @var int the first retry delay in milliseconds; 0 takes the sender's */
	private int $_retryDelay = 0;

	/** @var bool whether the target receives deliveries */
	private bool $_enabled = true;

	/** @var mixed whatever the application wants carried alongside the target */
	private mixed $_data = null;

	/**
	 * Turns one item of an application's webhook list into a target.
	 * @param mixed $spec a target, a URL, or an array of properties, in which `secret` is
	 *   shorthand for an HMAC signature keyed with it.
	 * @throws \Prado\Exceptions\TConfigurationException when $spec is none of those, names no
	 *   usable URL -- a built target included -- or names a property this class does not have.
	 * @return self the target $spec describes.
	 */
	public static function ensure(mixed $spec): self
	{
		if ($spec instanceof self) {
			if ($spec->getUrl() === '') {
				throw new TConfigurationException('webhooks_target_url_required', $spec::class);
			}

			return $spec;
		}

		$target = new self();
		if (is_string($spec)) {
			$target->setUrl($spec);

			return $target;
		}
		if (!is_array($spec)) {
			throw new TConfigurationException('webhooks_target_invalid', get_debug_type($spec));
		}
		foreach ($spec as $name => $value) {
			if (strcasecmp((string) $name, 'secret') === 0) {
				$signature = new THmacWebhookSignature();
				$signature->setSecret($value);
				$target->setSignature($signature);
			} else {
				try {
					$target->setSubproperty((string) $name, $value);
				} catch (TInvalidOperationException $e) {
					// TComponent's own message names a class and a property; a subscription row
					// with a misspelled key deserves one that says what the keys are.
					throw new TConfigurationException('webhooks_target_property_unknown', (string) $name, static::class);
				}
			}
		}
		if ($target->getUrl() === '') {
			throw new TConfigurationException('webhooks_target_url_required', static::class);
		}

		return $target;
	}

	/**
	 * Returns this target as a specification {@see ensure} rebuilds it from.
	 *
	 * Everything but the signer, which is an object holding a key and so is not a thing to
	 * write down. A target that carries one cannot be queued as it stands: queue the secret
	 * in the specification, or queue a reference and put the built target back in an
	 * `onDequeue` handler. See {@see \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem}.
	 *
	 * @return array<string, mixed> the specification.
	 */
	public function toSpec(): array
	{
		return array_filter([
			'url' => $this->_url,
			'method' => $this->_method,
			'contentType' => $this->_contentType,
			'headers' => $this->_headers,
			'events' => $this->_events,
			'eventHeader' => $this->_eventHeader,
			'deliveryHeader' => $this->_deliveryHeader,
			'timeout' => $this->_timeout,
			'maxAttempts' => $this->_maxAttempts,
			'retryDelay' => $this->_retryDelay,
			'enabled' => $this->_enabled,
			'data' => $this->_data,
		], static fn ($value) => $value !== null);
	}

	/**
	 * Whether this target wants an event.
	 *
	 * A target with no {@see getEvents Events} filter wants everything. A target that has
	 * one wants only what it listed, and wants nothing at all from an unnamed send: a
	 * payload with no event cannot be shown to match a subscription, and delivering it
	 * anyway would send a subscriber something it never asked for.
	 *
	 * @param null|string $event the event being sent.
	 * @return bool whether the target receives it.
	 */
	public function acceptsEvent(?string $event): bool
	{
		if ($this->_events === null) {
			return true;
		}

		return $event !== null && in_array($event, $this->_events, true);
	}

	/**
	 * Builds the headers of a delivery, before it is signed.
	 * @param null|string $event the event being sent, when it has a name.
	 * @param string $deliveryId the id identifying this delivery to the receiver.
	 * @return array<string, string> the request headers.
	 */
	public function buildHeaders(?string $event, string $deliveryId): array
	{
		$headers = [THttpHeaderName::ContentType => $this->_contentType];
		if ($event !== null && $this->_eventHeader !== '') {
			$headers[$this->_eventHeader] = $event;
		}
		if ($this->_deliveryHeader !== '') {
			$headers[$this->_deliveryHeader] = $deliveryId;
		}

		// The target's own headers win, so an application can override anything above --
		// however it spells the name. Header names are case-insensitive, and a target's
		// `content-type` alongside the default `Content-Type` would send both.
		foreach ($this->_headers as $name => $value) {
			foreach (array_keys($headers) as $existing) {
				if (strcasecmp((string) $existing, (string) $name) === 0) {
					unset($headers[$existing]);
				}
			}
			$headers[$name] = $value;
		}

		return $headers;
	}

	/**
	 * @return string where the delivery is posted.
	 */
	public function getUrl(): string
	{
		return $this->_url;
	}

	/**
	 * @param mixed $value an absolute `http` or `https` URL.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is not one, or the
	 *   {@see setUrlValidator UrlValidator} refuses it. A relative URL, or a scheme this
	 *   package cannot post to, is a configuration mistake rather than a delivery that
	 *   should be attempted and fail.
	 */
	public function setUrl($value): void
	{
		$url = trim(TPropertyValue::ensureString($value));
		$scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
		if (parse_url($url, PHP_URL_HOST) === null || !in_array($scheme, ['http', 'https'], true)) {
			throw new TConfigurationException('webhooks_target_url_invalid', $url);
		}
		if (self::$_urlValidator !== null && !(self::$_urlValidator)($url)) {
			throw new TConfigurationException('webhooks_target_url_refused', $url);
		}
		$this->_url = $url;
	}

	/**
	 * @return null|callable the application's say over which URLs may be targets, or null
	 *   when any absolute `http` or `https` URL may.
	 * @since 0.2.0
	 */
	public static function getUrlValidator(): ?callable
	{
		return self::$_urlValidator;
	}

	/**
	 * Installs a check every target URL has to pass, for the whole process.
	 *
	 * It is given the URL as a string, after it has been found to be an absolute `http` or
	 * `https` URL, and returns whether the target may be built; false makes {@see setUrl}
	 * throw. The class docblock has one that refuses private and link-local addresses.
	 * There is one for all targets rather than one per target because the point is that a
	 * subscriber cannot choose to be exempt.
	 *
	 * @param null|callable $validator the check, taking the URL and returning bool, or null
	 *   to accept any absolute `http` or `https` URL again.
	 * @since 0.2.0
	 */
	public static function setUrlValidator(?callable $validator): void
	{
		self::$_urlValidator = $validator;
	}

	/**
	 * @return string the HTTP method used to deliver. Defaults to `POST`.
	 */
	public function getMethod(): string
	{
		return $this->_method;
	}

	/**
	 * @param mixed $value the HTTP method used to deliver.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is empty.
	 */
	public function setMethod($value): void
	{
		$method = strtoupper(trim(TPropertyValue::ensureString($value)));
		if ($method === '') {
			throw new TConfigurationException('webhooks_target_method_required', static::class);
		}
		$this->_method = $method;
	}

	/**
	 * @return string the media type the payload is encoded as. Defaults to `application/json`.
	 */
	public function getContentType(): string
	{
		return $this->_contentType;
	}

	/**
	 * @param mixed $value the media type; `application/x-www-form-urlencoded` encodes an
	 *   array payload as a form instead of as JSON.
	 */
	public function setContentType($value): void
	{
		$this->_contentType = TPropertyValue::ensureString($value);
	}

	/**
	 * @return array<string, string> headers added to every delivery.
	 */
	public function getHeaders(): array
	{
		return $this->_headers;
	}

	/**
	 * @param mixed $value headers keyed by name, or a string of `Name: value` lines.
	 */
	public function setHeaders($value): void
	{
		if (!is_array($value)) {
			$parsed = [];
			foreach (preg_split('/\R/', TPropertyValue::ensureString($value)) ?: [] as $line) {
				$parts = explode(':', $line, 2);
				if (count($parts) === 2 && trim($parts[0]) !== '') {
					$parsed[trim($parts[0])] = trim($parts[1]);
				}
			}
			$value = $parsed;
		}
		$headers = [];
		foreach ($value as $name => $header) {
			$headers[(string) $name] = (string) $header;
		}
		$this->_headers = $headers;
	}

	/**
	 * @return null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner how deliveries are
	 *   signed, or null to take the sender's default.
	 */
	public function getSignature(): ?IWebhookSigner
	{
		return $this->_signature;
	}

	/**
	 * @param null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner $value the signer.
	 */
	public function setSignature(?IWebhookSigner $value): void
	{
		$this->_signature = $value;
	}

	/**
	 * @return null|string[] the events this target wants, or null for every event.
	 */
	public function getEvents(): ?array
	{
		return $this->_events;
	}

	/**
	 * @param mixed $value the events wanted, as an array or a comma separated list; null or
	 *   an empty value subscribes to everything.
	 */
	public function setEvents($value): void
	{
		if ($value === null || $value === '') {
			$this->_events = null;

			return;
		}
		$events = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$events = array_values(array_filter(array_map(
			static fn ($event) => trim((string) $event),
			$events
		), static fn ($event) => $event !== ''));
		$this->_events = $events === [] ? null : $events;
	}

	/**
	 * @return string the header naming the event. Defaults to {@see DEFAULT_EVENT_HEADER}.
	 */
	public function getEventHeader(): string
	{
		return $this->_eventHeader;
	}

	/**
	 * @param mixed $value the header naming the event, or an empty value to send none.
	 */
	public function setEventHeader($value): void
	{
		$this->_eventHeader = trim(TPropertyValue::ensureString($value ?? ''));
	}

	/**
	 * @return string the header carrying the delivery id. Defaults to
	 *   {@see DEFAULT_DELIVERY_HEADER}.
	 */
	public function getDeliveryHeader(): string
	{
		return $this->_deliveryHeader;
	}

	/**
	 * Names the header carrying the delivery id. The id is constant across the retries of
	 * one delivery, which is what lets a receiver recognize a repeat and process it once.
	 * @param mixed $value the header name, or an empty value to send none.
	 */
	public function setDeliveryHeader($value): void
	{
		$this->_deliveryHeader = trim(TPropertyValue::ensureString($value ?? ''));
	}

	/**
	 * @return int the per-request timeout in seconds, or 0 to take the sender's.
	 */
	public function getTimeout(): int
	{
		return $this->_timeout;
	}

	/**
	 * @param mixed $value the timeout in seconds; 0 takes the sender's.
	 */
	public function setTimeout($value): void
	{
		$this->_timeout = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int how many times a delivery is attempted, or 0 to take the sender's.
	 */
	public function getMaxAttempts(): int
	{
		return $this->_maxAttempts;
	}

	/**
	 * @param mixed $value the attempt count; 0 takes the sender's.
	 */
	public function setMaxAttempts($value): void
	{
		$this->_maxAttempts = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int the first retry delay in milliseconds, or 0 to take the sender's.
	 */
	public function getRetryDelay(): int
	{
		return $this->_retryDelay;
	}

	/**
	 * @param mixed $value the first retry delay in milliseconds; 0 takes the sender's.
	 */
	public function setRetryDelay($value): void
	{
		$this->_retryDelay = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return bool whether the target receives deliveries. Defaults to true.
	 */
	public function getEnabled(): bool
	{
		return $this->_enabled;
	}

	/**
	 * @param mixed $value whether the target receives deliveries. A disabled target is
	 *   skipped silently and produces no delivery record.
	 */
	public function setEnabled($value): void
	{
		$this->_enabled = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return mixed whatever the application attached to the target.
	 */
	public function getData(): mixed
	{
		return $this->_data;
	}

	/**
	 * @param mixed $value anything the application wants handed back to it in the delivery
	 *   events, such as the id of the subscription this target came from.
	 */
	public function setData($value): void
	{
		$this->_data = $value;
	}
}
