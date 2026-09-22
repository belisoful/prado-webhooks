<?php

/**
 * TWebhookSecretTrait class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookEncoding;
use Prado\Exceptions\TConfigurationException;
use Prado\TPropertyValue;

/**
 * TWebhookSecretTrait trait.
 *
 * The shared secret of a symmetric scheme, and the two things providers do to it before it
 * becomes a key.
 *
 * Most hand the secret over as the key itself. Some prefix it with a marker that is not
 * part of the key -- Stripe's `whsec_` is, awkwardly, part of the key, while Standard
 * Webhooks strips the same prefix and base64 decodes the rest. Getting either wrong
 * produces a scheme that fails every verification for no visible reason, so both are
 * properties rather than assumptions.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
trait TWebhookSecretTrait
{
	/** @var string the shared secret, as the provider shows it */
	private string $_secret = '';

	/** @var string a marker stripped from the secret before it is decoded */
	private string $_secretPrefix = '';

	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookEncoding how the secret is encoded */
	private TWebhookEncoding $_secretEncoding = TWebhookEncoding::Raw;

	/**
	 * Returns the bytes the scheme keys its MAC with.
	 * @throws \Prado\Exceptions\TConfigurationException when no secret is set, or the secret
	 *   is not valid in {@see getSecretEncoding SecretEncoding}.
	 * @return string the key.
	 */
	protected function getSecretKey(): string
	{
		if ($this->_secret === '') {
			throw new TConfigurationException('webhooks_secret_required', static::class);
		}
		$secret = $this->_secret;
		if ($this->_secretPrefix !== '' && str_starts_with($secret, $this->_secretPrefix)) {
			$secret = substr($secret, strlen($this->_secretPrefix));
		}
		$key = $this->_secretEncoding->decode($secret);
		if ($key === false || $key === '') {
			throw new TConfigurationException('webhooks_secret_invalid', $this->_secretEncoding->value, static::class);
		}

		return $key;
	}

	/**
	 * @return string the shared secret, as the provider shows it.
	 */
	public function getSecret(): string
	{
		return $this->_secret;
	}

	/**
	 * @param mixed $value the shared secret.
	 */
	public function setSecret($value): void
	{
		$this->_secret = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string a marker stripped from the secret before it is decoded. Defaults to an
	 *   empty string, which strips nothing.
	 */
	public function getSecretPrefix(): string
	{
		return $this->_secretPrefix;
	}

	/**
	 * Sets a marker that is part of how the provider displays the secret but not part of the
	 * key, such as the `whsec_` of a Standard Webhooks secret. Stripping happens before
	 * decoding, and a secret that does not start with the marker is left alone.
	 * @param mixed $value the marker, or an empty string to strip nothing.
	 */
	public function setSecretPrefix($value): void
	{
		$this->_secretPrefix = TPropertyValue::ensureString($value);
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookEncoding how the secret is encoded.
	 *   Defaults to {@see \Belisoful\Prado\Web\Webhooks\TWebhookEncoding::Raw}, the secret
	 *   being the key.
	 */
	public function getSecretEncoding(): TWebhookEncoding
	{
		return $this->_secretEncoding;
	}

	/**
	 * @param mixed $value an encoding, or its name; `base64` for a provider whose displayed
	 *   secret encodes the key rather than being it.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no encoding.
	 */
	public function setSecretEncoding($value): void
	{
		$this->_secretEncoding = TWebhookEncoding::ensure($value);
	}
}
