<?php

/**
 * TFieldedWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\TPropertyValue;

/**
 * TFieldedWebhookSignature class.
 *
 * The same keyed hash as {@see THmacWebhookSignature}, but with the timestamp, the id, and
 * the signature packed into one value as named fields rather than spread across headers:
 *
 * ```
 * X-Signature: t=1492774577,v1=5257a869e7ec...,v1=<a second, during a rotation>
 * ```
 *
 * ```xml
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TFieldedWebhookSignature"
 *		Secret="..." Header="Stripe-Signature" />
 * ```
 *
 * The defaults are the packing this shape is usually seen in: fields separated by commas,
 * name and value by an equals sign, the timestamp in `t`, the signature in `v1`, and
 * `{timestamp}.{body}` hashed. Anything laid out differently is a property away.
 *
 * A repeated signature field is how overlapping secrets work: a provider mid-rotation sends
 * one per active secret, and verification accepts the request when any of them matches.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TFieldedWebhookSignature extends THmacWebhookSignature
{
	/** @var string what separates one field from the next. */
	public const DEFAULT_FIELD_SEPARATOR = ',';

	/** @var string what separates a field's name from its value. */
	public const DEFAULT_VALUE_SEPARATOR = '=';

	/** @var string the field the timestamp is packed into. */
	public const DEFAULT_TIMESTAMP_FIELD = 't';

	/** @var string the field the signature is packed into. */
	public const DEFAULT_SIGNATURE_FIELD = 'v1';

	/** @var string what separates one field from the next */
	private string $_fieldSeparator = self::DEFAULT_FIELD_SEPARATOR;

	/** @var string what separates a field's name from its value */
	private string $_valueSeparator = self::DEFAULT_VALUE_SEPARATOR;

	/** @var string the field the timestamp is packed into */
	private string $_timestampField = self::DEFAULT_TIMESTAMP_FIELD;

	/** @var string the field the signature is packed into */
	private string $_signatureField = self::DEFAULT_SIGNATURE_FIELD;

	/** @var null|string the field the delivery id is packed into, when the scheme has one */
	private ?string $_idField = null;

	/**
	 * Defaults the payload template to `{timestamp}.{body}`: this packing exists to carry
	 * a timestamp, so a scheme using it is timestamped.
	 */
	public function __construct()
	{
		parent::__construct();
		// The packing exists to carry a timestamp, so this shape is timestamped by default.
		$this->setPayloadFormat('{timestamp}.{body}');
	}

	/**
	 * Splits the packed value into its fields. A field may repeat, so every value is kept
	 * rather than the last one winning.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return array<string, string[]> field name => every value given for it, in order.
	 */
	protected function parseFields(TWebhookRequest $request): array
	{
		$value = $this->readValue($request, $this->getName());
		if ($value === null || $value === '') {
			return [];
		}
		$fields = [];
		foreach (explode($this->_fieldSeparator, $value) as $pair) {
			$parts = explode($this->_valueSeparator, trim($pair), 2);
			if (count($parts) !== 2) {
				continue;
			}
			$fields[trim($parts[0])][] = trim($parts[1]);
		}

		return $fields;
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return string[] every signature packed into the value.
	 */
	protected function presentedSignatures(TWebhookRequest $request): array
	{
		return $this->parseFields($request)[$this->_signatureField] ?? [];
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|string the timestamp packed into the value, or null when it carries none.
	 */
	protected function presentedTimestamp(TWebhookRequest $request): ?string
	{
		return $this->parseFields($request)[$this->_timestampField][0] ?? null;
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|string the delivery id packed into the value, or null.
	 */
	protected function presentedId(TWebhookRequest $request): ?string
	{
		if ($this->_idField === null) {
			return null;
		}

		return $this->parseFields($request)[$this->_idField][0] ?? null;
	}

	/**
	 * Verifies the packed value. The timestamp is always checked here, because a packing
	 * that carries one carries it for that purpose.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when the scheme is not configured.
	 * @return bool whether a packed signature matches and the timestamp is recent.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		$presented = $this->presentedSignatures($request);
		if ($presented === [] || !$this->bodyHashHolds($request)) {
			return false;
		}
		$timestamp = $this->presentedTimestamp($request);
		if (!$this->isFresh($timestamp)) {
			return false;
		}

		$bound = ['timestamp' => (string) $timestamp, 'id' => (string) $this->presentedId($request)];

		return $this->matchesAny($this->computeSignature($request, $bound), $presented);
	}

	/**
	 * Signs an outbound request, packing the fields into one header.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request about to be made.
	 * @throws \Prado\Exceptions\TConfigurationException when the scheme is not configured.
	 * @return array<string, string> the one packed header.
	 */
	public function sign(TWebhookRequest $request): array
	{
		$bound = ['timestamp' => (string) time(), 'id' => ''];
		$fields = [$this->_timestampField . $this->_valueSeparator . $bound['timestamp']];

		if ($this->_idField !== null) {
			// Minted per call, because the id is packed into the value being written and so
			// cannot be read back out of the request the way a header-borne one can.
			$bound['id'] = bin2hex(random_bytes(16));
			$fields[] = $this->_idField . $this->_valueSeparator . $bound['id'];
		}
		$fields[] = $this->_signatureField . $this->_valueSeparator . $this->computeSignature($request, $bound);

		return [$this->getName() => implode($this->_fieldSeparator, $fields)];
	}

	/**
	 * @return string what separates one field from the next. Defaults to
	 *   {@see DEFAULT_FIELD_SEPARATOR}.
	 */
	public function getFieldSeparator(): string
	{
		return $this->_fieldSeparator;
	}

	/**
	 * @param mixed $value the field separator.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is empty, which would
	 *   leave the fields unsplittable.
	 */
	public function setFieldSeparator($value): void
	{
		$separator = TPropertyValue::ensureString($value);
		if ($separator === '') {
			throw new TConfigurationException('webhooks_separator_required', 'FieldSeparator', static::class);
		}
		$this->_fieldSeparator = $separator;
	}

	/**
	 * @return string what separates a field's name from its value. Defaults to
	 *   {@see DEFAULT_VALUE_SEPARATOR}.
	 */
	public function getValueSeparator(): string
	{
		return $this->_valueSeparator;
	}

	/**
	 * @param mixed $value the name/value separator.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is empty.
	 */
	public function setValueSeparator($value): void
	{
		$separator = TPropertyValue::ensureString($value);
		if ($separator === '') {
			throw new TConfigurationException('webhooks_separator_required', 'ValueSeparator', static::class);
		}
		$this->_valueSeparator = $separator;
	}

	/**
	 * @return string the field the timestamp is packed into. Defaults to
	 *   {@see DEFAULT_TIMESTAMP_FIELD}.
	 */
	public function getTimestampField(): string
	{
		return $this->_timestampField;
	}

	/**
	 * @param mixed $value the timestamp field name.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is empty.
	 */
	public function setTimestampField($value): void
	{
		$field = trim(TPropertyValue::ensureString($value));
		if ($field === '') {
			throw new TConfigurationException('webhooks_field_required', 'TimestampField', static::class);
		}
		$this->_timestampField = $field;
	}

	/**
	 * @return string the field the signature is packed into. Defaults to
	 *   {@see DEFAULT_SIGNATURE_FIELD}.
	 */
	public function getSignatureField(): string
	{
		return $this->_signatureField;
	}

	/**
	 * Names the field the signature is packed into, which doubles as the scheme version a
	 * provider stamps on it. A value packed under any other field name is ignored, so
	 * raising this is how an application stops accepting a retired version.
	 * @param mixed $value the signature field name.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is empty.
	 */
	public function setSignatureField($value): void
	{
		$field = trim(TPropertyValue::ensureString($value));
		if ($field === '') {
			throw new TConfigurationException('webhooks_field_required', 'SignatureField', static::class);
		}
		$this->_signatureField = $field;
	}

	/**
	 * @return null|string the field the delivery id is packed into, or null when the scheme
	 *   packs none. Defaults to null. Unlike a delivery id in a header, one packed here is
	 *   minted per call, so a retry of the same delivery carries a new id.
	 */
	public function getIdField(): ?string
	{
		return $this->_idField;
	}

	/**
	 * @param mixed $value the id field name, or an empty value for none.
	 */
	public function setIdField($value): void
	{
		$field = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_idField = $field === '' ? null : $field;
	}
}
