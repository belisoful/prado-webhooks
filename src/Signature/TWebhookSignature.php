<?php

/**
 * TWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookEncoding;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Belisoful\Prado\Web\Webhooks\TWebhookSource;
use Prado\Exceptions\TConfigurationException;
use Prado\TApplicationComponent;
use Prado\TPropertyValue;

/**
 * TWebhookSignature class.
 *
 * What every signature scheme in this package has in common: where in the request its
 * values are found, how its bytes are rendered as text, what counts as a recent timestamp,
 * and -- the part that does most of the generalizing -- what exactly gets signed.
 *
 * ## The payload template
 *
 * Providers disagree less about cryptography than about what they run it over.
 * {@see setPayloadFormat PayloadFormat} is that choice, written as a template:
 *
 * | Token | Expands to |
 * | --- | --- |
 * | `{body}` | the raw request body, byte for byte |
 * | `{method}` | the HTTP method, upper case |
 * | `{url}` | the absolute request URL |
 * | `{timestamp}` | the timestamp this signature is bound to |
 * | `{id}` | the delivery id this signature is bound to |
 * | `{crc32}` | the CRC32 of the body, as a decimal string |
 * | `{header:Name}` | one request header |
 * | `{param:name}` | one posted form field |
 * | `{query:name}` | one query string parameter |
 * | `{const:NAME}` | one entry of {@see setConstants Constants} |
 * | `{params}` | every posted form field, sorted by name, as name and value concatenated |
 *
 * A form field is a scalar entry of the posted body as PHP parses it -- `$_POST` on the
 * receiving side, the encoded payload on the sending side. The query string is not among
 * them: every inbound URL carries `?webhook=<id>`, which no provider signed, so it is
 * reached only through `{url}`, `{query:name}` and `Source="query"`.
 *
 * Which makes the schemes in the wild configuration rather than code:
 *
 * ```
 * {body}                     GitHub, Shopify, Patreon, Adyen, Xero, Zoom, DocuSign
 * {timestamp}.{body}         Stripe-shaped, and this package's own default
 * {id}.{timestamp}.{body}    Standard Webhooks (Svix)
 * {url}{body}                Square
 * {url}{params}              Twilio
 * {param:timestamp}{param:token}   Mailgun
 * ```
 *
 * ## Freshness
 *
 * A scheme that names a {@see setTimestampName TimestampName} is timestamped. Put
 * `{timestamp}` in the template as well and the timestamp is *inside* the hash, so a
 * captured request cannot be replayed under a new one; {@see setTolerance Tolerance} then
 * bounds how old a delivery may be. A timestamp that is read but not signed is worth
 * little: an attacker rewrites it freely.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
abstract class TWebhookSignature extends TApplicationComponent
{
	/** @var string the default header carrying a signature, when a scheme names no other. */
	public const DEFAULT_HEADER = 'X-Webhook-Signature';

	/** @var string the default header carrying a signature timestamp. */
	public const DEFAULT_TIMESTAMP_HEADER = 'X-Webhook-Timestamp';

	/** @var string the default header carrying a delivery id. */
	public const DEFAULT_ID_HEADER = 'X-Webhook-Delivery';

	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookSource where this scheme's values are found */
	private TWebhookSource $_source = TWebhookSource::Header;

	/** @var string the header, query parameter, or request parameter carrying the signature */
	private string $_name = self::DEFAULT_HEADER;

	/** @var string the literal text preceding the signature */
	private string $_prefix = '';

	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookEncoding how the signature is rendered as text */
	private TWebhookEncoding $_encoding = TWebhookEncoding::Hex;

	/** @var string what separates several signatures in one value; empty when there is one */
	private string $_separator = '';

	/** @var null|string where the signature timestamp is found, when the scheme has one */
	private ?string $_timestampName = null;

	/** @var null|string where the delivery id is found, when the scheme signs one */
	private ?string $_idName = null;

	/** @var int how many seconds either side of now a timestamp may fall; 0 accepts any */
	private int $_tolerance = 300;

	/** @var string the template of what is signed */
	private string $_payloadFormat = '{body}';

	/** @var array<string, string> values the template reaches through `{const:NAME}` */
	private array $_constants = [];

	/** @var null|string where a digest of the body is presented, when the scheme binds one */
	private ?string $_bodyHashName = null;

	/** @var null|\Belisoful\Prado\Web\Webhooks\TWebhookSource where that digest lives, when not with the signature */
	private ?TWebhookSource $_bodyHashSource = null;

	/** @var string the digest algorithm of the body hash */
	private string $_bodyHashAlgorithm = 'sha256';

	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookEncoding how that digest is rendered */
	private TWebhookEncoding $_bodyHashEncoding = TWebhookEncoding::Hex;

	/**
	 * Expands {@see getPayloadFormat PayloadFormat} against a request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param array<string, string> $bound the values `{timestamp}` and `{id}` stand for.
	 * @throws \Prado\Exceptions\TConfigurationException when the template uses a token this
	 *   package does not define.
	 * @return string the bytes to sign or verify.
	 */
	protected function expandPayload(TWebhookRequest $request, array $bound = []): string
	{
		return (string) preg_replace_callback(
			'/\{([a-z0-9]+)(?::([^}]*))?\}/i',
			function (array $match) use ($request, $bound): string {
				$token = strtolower($match[1]);
				$argument = $match[2] ?? null;

				return match ($token) {
					'body' => $request->getBody(),
					'method' => $request->getMethod(),
					'url' => $request->getUrl(),
					'timestamp' => $bound['timestamp'] ?? '',
					'id' => $bound['id'] ?? '',
					'crc32' => (string) crc32($request->getBody()),
					'header' => $request->getHeader((string) $argument) ?? '',
					'param' => $request->getParameterValue((string) $argument) ?? '',
					'query' => (string) ($request->getQueryParameters()[(string) $argument] ?? ''),
					'const' => $this->_constants[(string) $argument] ?? '',
					'params' => $this->concatenateParameters($request),
					default => throw new TConfigurationException('webhooks_payload_token_unknown', $match[0], static::class),
				};
			},
			$this->_payloadFormat
		);
	}

	/**
	 * Every posted form field, sorted by name, as name immediately followed by value.
	 *
	 * This is the serialization Twilio-shaped schemes append to the URL. Sorting is by
	 * name, ascending, which is what makes the result independent of the order the fields
	 * arrived in. The query string is not part of it; a Twilio-shaped scheme covers that
	 * through `{url}`.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return string the concatenated parameters.
	 */
	protected function concatenateParameters(TWebhookRequest $request): string
	{
		$parameters = $request->getParameters();
		ksort($parameters, SORT_STRING);
		$concatenated = '';
		foreach ($parameters as $name => $value) {
			$concatenated .= $name . (is_scalar($value) ? (string) $value : '');
		}

		return $concatenated;
	}

	/**
	 * Reads one of this scheme's values from wherever {@see getSource Source} says it lives.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param string $name the header or parameter name.
	 * @return null|string the value, or null when it is absent.
	 */
	protected function readValue(TWebhookRequest $request, string $name): ?string
	{
		return $this->readValueFrom($request, $this->_source, $name);
	}

	/**
	 * Reads a value from a named part of the request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookSource $source where to look.
	 * @param string $name the header or parameter name.
	 * @return null|string the value, or null when it is absent.
	 */
	protected function readValueFrom(TWebhookRequest $request, TWebhookSource $source, string $name): ?string
	{
		return match ($source) {
			TWebhookSource::Header => $request->getHeader($name),
			TWebhookSource::Query => $request->getQueryParameters()[$name] ?? null,
			TWebhookSource::Parameter => $request->getParameterValue($name),
		};
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return string the digest of the body, as a bound body hash should carry it.
	 */
	protected function bodyDigest(TWebhookRequest $request): string
	{
		return $this->_bodyHashEncoding->encode(hash($this->_bodyHashAlgorithm, $request->getBody(), true));
	}

	/**
	 * Whether the body matches the digest the request presents for it.
	 *
	 * A scheme that does not sign `{body}` is not bound to the body at all unless something
	 * else ties the two together. Providers that sign only the URL solve it by putting a
	 * digest of the body in the URL, which the signature then covers; this is the check that
	 * makes that digest mean something, and without it the signature would pass for any body.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return bool true when no body hash is configured, otherwise whether it matches.
	 */
	protected function bodyHashHolds(TWebhookRequest $request): bool
	{
		if ($this->_bodyHashName === null) {
			return true;
		}
		$presented = $this->readValueFrom(
			$request,
			$this->_bodyHashSource ?? $this->_source,
			$this->_bodyHashName
		);

		return $presented !== null && hash_equals($this->bodyDigest($request), $presented);
	}

	/**
	 * Reads the signatures a request presents.
	 *
	 * More than one is normal during a secret rotation: a provider that supports overlapping
	 * secrets sends one signature per active secret, separated by
	 * {@see getSeparator Separator}.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return string[] every presented signature, prefixes included.
	 */
	protected function presentedSignatures(TWebhookRequest $request): array
	{
		$value = $this->readValue($request, $this->_name);
		if ($value === null || $value === '') {
			return [];
		}
		if ($this->_separator === '') {
			return [$value];
		}

		return array_values(array_filter(array_map('trim', explode($this->_separator, $value)), static fn ($v) => $v !== ''));
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|string the timestamp the request presents, or null when the scheme is not
	 *   timestamped or the request carries none.
	 */
	protected function presentedTimestamp(TWebhookRequest $request): ?string
	{
		return $this->_timestampName === null ? null : $this->readValue($request, $this->_timestampName);
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|string the delivery id the request presents, or null when the scheme does
	 *   not sign one or the request carries none.
	 */
	protected function presentedId(TWebhookRequest $request): ?string
	{
		return $this->_idName === null ? null : $this->readValue($request, $this->_idName);
	}

	/**
	 * Whether a presented timestamp falls inside {@see getTolerance Tolerance} of now.
	 * @param null|string $timestamp the timestamp, as Unix seconds.
	 * @return bool whether the timestamp is numeric and recent enough.
	 */
	protected function isFresh(?string $timestamp): bool
	{
		if ($timestamp === null || !is_numeric($timestamp)) {
			return false;
		}
		if ($this->_tolerance <= 0) {
			return true;
		}

		return abs(time() - (int) $timestamp) <= $this->_tolerance;
	}

	/**
	 * Compares a computed signature against every one a request presented, in constant time.
	 *
	 * Every candidate is compared even after one matches, so neither the number of active
	 * secrets nor which of them matched is observable in the response time.
	 *
	 * @param string $expected the signature this scheme computed.
	 * @param string[] $presented the signatures the request carried.
	 * @return bool whether any of them matched.
	 */
	protected function matchesAny(string $expected, array $presented): bool
	{
		$matched = false;
		foreach ($presented as $candidate) {
			$matched = hash_equals($expected, $candidate) || $matched;
		}

		return $matched;
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookSource where this scheme's values are
	 *   found. Defaults to the request headers.
	 */
	public function getSource(): TWebhookSource
	{
		return $this->_source;
	}

	/**
	 * @param mixed $value a source, or its name: `header`, `query`, or `parameter`.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no source.
	 */
	public function setSource($value): void
	{
		$this->_source = TWebhookSource::ensure($value);
	}

	/**
	 * @return string the header, query parameter, or request parameter carrying the
	 *   signature. Defaults to {@see DEFAULT_HEADER}.
	 */
	public function getName(): string
	{
		return $this->_name;
	}

	/**
	 * @param mixed $value where the signature is found, within {@see getSource Source}.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is empty.
	 */
	public function setName($value): void
	{
		$name = trim(TPropertyValue::ensureString($value));
		if ($name === '') {
			throw new TConfigurationException('webhooks_name_required', static::class);
		}
		$this->_name = $name;
	}

	/**
	 * @return null|string the header carrying the signature, or null when this scheme does
	 *   not read headers.
	 */
	public function getHeader(): ?string
	{
		return $this->_source === TWebhookSource::Header ? $this->_name : null;
	}

	/**
	 * Names the header carrying the signature. Shorthand for setting
	 * {@see setSource Source} to `header` and {@see setName Name} together, because a
	 * header is what all but a handful of providers use.
	 * @param mixed $value the header name.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is empty.
	 */
	public function setHeader($value): void
	{
		$this->setSource(TWebhookSource::Header);
		$this->setName($value);
	}

	/**
	 * @return string the literal text preceding the signature, such as `sha256=`. Defaults to
	 *   an empty string.
	 */
	public function getPrefix(): string
	{
		return $this->_prefix;
	}

	/**
	 * @param mixed $value the literal text preceding the signature.
	 */
	public function setPrefix($value): void
	{
		$this->_prefix = TPropertyValue::ensureString($value);
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookEncoding how the signature is rendered as
	 *   text. Defaults to {@see \Belisoful\Prado\Web\Webhooks\TWebhookEncoding::Hex}.
	 */
	public function getEncoding(): TWebhookEncoding
	{
		return $this->_encoding;
	}

	/**
	 * @param mixed $value an encoding, or its name.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no encoding.
	 */
	public function setEncoding($value): void
	{
		$this->_encoding = TWebhookEncoding::ensure($value);
	}

	/**
	 * @return string what separates several signatures in one value. Defaults to an empty
	 *   string, meaning the value holds exactly one.
	 */
	public function getSeparator(): string
	{
		return $this->_separator;
	}

	/**
	 * Sets what separates several signatures in one value, for providers that send one per
	 * active secret through a rotation.
	 * @param mixed $value the separator, or an empty string for a single signature.
	 */
	public function setSeparator($value): void
	{
		$this->_separator = TPropertyValue::ensureString($value);
	}

	/**
	 * @return null|string where the signature timestamp is found, or null when the scheme is
	 *   not timestamped. Defaults to null.
	 */
	public function getTimestampName(): ?string
	{
		return $this->_timestampName;
	}

	/**
	 * Names where the signature timestamp is found, making the scheme timestamped. Put
	 * `{timestamp}` in {@see setPayloadFormat PayloadFormat} as well, or the timestamp is
	 * checked but not signed, and an attacker can rewrite it.
	 * @param mixed $value the header or parameter name, or an empty value for an
	 *   untimestamped scheme.
	 */
	public function setTimestampName($value): void
	{
		$name = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_timestampName = $name === '' ? null : $name;
	}

	/**
	 * @return null|string the header carrying the signature timestamp, or null.
	 */
	public function getTimestampHeader(): ?string
	{
		return $this->_source === TWebhookSource::Header ? $this->_timestampName : null;
	}

	/**
	 * An alias of {@see setTimestampName}, for configurations that read better naming the
	 * header.
	 * @param mixed $value the header name.
	 */
	public function setTimestampHeader($value): void
	{
		$this->setTimestampName($value);
	}

	/**
	 * @return null|string where the delivery id is found, or null when the scheme does not
	 *   sign one. Defaults to null.
	 */
	public function getIdName(): ?string
	{
		return $this->_idName;
	}

	/**
	 * Names where the delivery id is found, for schemes that bind a signature to one
	 * delivery as well as to one moment.
	 * @param mixed $value the header or parameter name, or an empty value for none.
	 */
	public function setIdName($value): void
	{
		$name = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_idName = $name === '' ? null : $name;
	}

	/**
	 * @return null|string the header carrying the delivery id, or null.
	 */
	public function getIdHeader(): ?string
	{
		return $this->_source === TWebhookSource::Header ? $this->_idName : null;
	}

	/**
	 * An alias of {@see setIdName}.
	 * @param mixed $value the header name.
	 */
	public function setIdHeader($value): void
	{
		$this->setIdName($value);
	}

	/**
	 * @return int how many seconds either side of now a timestamp may fall. Defaults to 300.
	 */
	public function getTolerance(): int
	{
		return $this->_tolerance;
	}

	/**
	 * @param mixed $value the tolerance in seconds; 0 or less accepts any timestamp.
	 */
	public function setTolerance($value): void
	{
		$this->_tolerance = TPropertyValue::ensureInteger($value);
	}

	/**
	 * @return string the template of what is signed. Defaults to `{body}`.
	 */
	public function getPayloadFormat(): string
	{
		return $this->_payloadFormat;
	}

	/**
	 * Sets what is signed, as a template. See the class docblock for the tokens and for the
	 * templates that reproduce the schemes in common use.
	 * @param mixed $value the template.
	 * @throws \Prado\Exceptions\TConfigurationException when $value contains no token at all,
	 *   which would sign a constant and authenticate nothing.
	 */
	public function setPayloadFormat($value): void
	{
		$format = TPropertyValue::ensureString($value);
		if (!preg_match('/\{[a-z0-9]+(?::[^}]*)?\}/i', $format)) {
			throw new TConfigurationException('webhooks_payload_format_invalid', $format);
		}
		$this->_payloadFormat = $format;
	}

	/**
	 * @return array<string, string> values the template reaches through `{const:NAME}`.
	 */
	public function getConstants(): array
	{
		return $this->_constants;
	}

	/**
	 * Sets the values `{const:NAME}` stands for: the parts of a signed payload that come
	 * from the application's own configuration rather than from the request, such as the
	 * provider-assigned id of the webhook subscription itself.
	 * @param mixed $value the values, keyed by name, or a string of `NAME=value` lines.
	 */
	public function setConstants($value): void
	{
		if (!is_array($value)) {
			$parsed = [];
			foreach (preg_split('/[\r\n,]+/', TPropertyValue::ensureString($value)) ?: [] as $line) {
				$parts = explode('=', $line, 2);
				if (count($parts) === 2 && trim($parts[0]) !== '') {
					$parsed[trim($parts[0])] = trim($parts[1]);
				}
			}
			$value = $parsed;
		}
		$constants = [];
		foreach ($value as $name => $constant) {
			$constants[(string) $name] = (string) $constant;
		}
		$this->_constants = $constants;
	}

	/**
	 * @return null|string where a digest of the body is presented, or null when the scheme
	 *   binds none. Defaults to null.
	 */
	public function getBodyHashName(): ?string
	{
		return $this->_bodyHashName;
	}

	/**
	 * Names where the request presents a digest of its own body, and requires it to match.
	 *
	 * Set it for a provider whose signed payload does not include `{body}` but whose URL or
	 * parameters carry a digest of it -- the signature then covers the digest, and this
	 * check ties the digest to the bytes actually received.
	 *
	 * @param mixed $value the header or parameter name, or an empty value for none.
	 */
	public function setBodyHashName($value): void
	{
		$name = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_bodyHashName = $name === '' ? null : $name;
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookSource where the body digest lives.
	 *   Defaults to wherever the signature lives.
	 */
	public function getBodyHashSource(): TWebhookSource
	{
		return $this->_bodyHashSource ?? $this->_source;
	}

	/**
	 * Sets where the body digest lives, for the providers that put it somewhere other than
	 * the signature -- a digest in the query string under a signature in a header.
	 * @param mixed $value a source, or its name; an empty value follows {@see getSource Source}.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no source.
	 */
	public function setBodyHashSource($value): void
	{
		$this->_bodyHashSource = ($value === null || $value === '') ? null : TWebhookSource::ensure($value);
	}

	/**
	 * @return string the digest algorithm of the body hash. Defaults to `sha256`.
	 */
	public function getBodyHashAlgorithm(): string
	{
		return $this->_bodyHashAlgorithm;
	}

	/**
	 * @param mixed $value a hash algorithm {@see hash_algos} lists.
	 * @throws \Prado\Exceptions\TConfigurationException when PHP does not offer $value.
	 */
	public function setBodyHashAlgorithm($value): void
	{
		$algorithm = strtolower(trim(TPropertyValue::ensureString($value)));
		if (!in_array($algorithm, hash_algos(), true)) {
			throw new TConfigurationException('webhooks_algorithm_unsupported', $algorithm, static::class);
		}
		$this->_bodyHashAlgorithm = $algorithm;
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookEncoding how the body digest is
	 *   rendered. Defaults to {@see \Belisoful\Prado\Web\Webhooks\TWebhookEncoding::Hex}.
	 */
	public function getBodyHashEncoding(): TWebhookEncoding
	{
		return $this->_bodyHashEncoding;
	}

	/**
	 * @param mixed $value an encoding, or its name.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no encoding.
	 */
	public function setBodyHashEncoding($value): void
	{
		$this->_bodyHashEncoding = TWebhookEncoding::ensure($value);
	}
}
