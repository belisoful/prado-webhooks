<?php

/**
 * TWebhookEncoding class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\Exceptions\TInvalidDataValueException;

/**
 * TWebhookEncoding enum.
 *
 * How raw bytes -- a message authentication code, a signature, a decoded secret -- are
 * rendered as text. Providers differ only in this detail: GitHub and Stripe send lowercase
 * hex, Shopify and Twilio send base64, JWT-based schemes use base64url, and the same bytes
 * sit underneath all of them.
 *
 * ```php
 * TWebhookEncoding::Hex->encode(hash_hmac('sha256', $body, $secret, true));
 * ```
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
enum TWebhookEncoding: string
{
	/** The bytes as they are, with no transformation. */
	case Raw = 'raw';

	/** Lowercase hexadecimal, as GitHub, Stripe, and Patreon send. */
	case Hex = 'hex';

	/** Standard base64 with padding, as Shopify, Twilio, and Adyen send. */
	case Base64 = 'base64';

	/** URL-safe base64 without padding, as JWT and Standard Webhooks use. */
	case Base64Url = 'base64url';

	/**
	 * Renders raw bytes as text.
	 * @param string $raw the bytes.
	 * @return string the bytes in this encoding.
	 */
	public function encode(string $raw): string
	{
		return match ($this) {
			self::Raw => $raw,
			self::Hex => bin2hex($raw),
			self::Base64 => base64_encode($raw),
			self::Base64Url => rtrim(strtr(base64_encode($raw), '+/', '-_'), '='),
		};
	}

	/**
	 * Reads text back to the bytes it encodes.
	 *
	 * Used where a scheme has to decode rather than re-encode: an asymmetric signature is
	 * decoded before it is checked, and a base64 secret is decoded before it is keyed. It
	 * returns false rather than throwing on malformed input, because that input is usually
	 * something an attacker supplied.
	 *
	 * @param string $encoded the text.
	 * @return false|string the bytes, or false when $encoded is not valid in this encoding.
	 */
	public function decode(string $encoded): false|string
	{
		return match ($this) {
			self::Raw => $encoded,
			self::Hex => ctype_xdigit($encoded) && strlen($encoded) % 2 === 0 ? hex2bin($encoded) : false,
			self::Base64 => base64_decode($encoded, true),
			self::Base64Url => base64_decode(str_pad(strtr($encoded, '-_', '+/'), (int) (ceil(strlen($encoded) / 4) * 4), '='), true),
		};
	}

	/**
	 * Coerces a property value to an encoding, so `Encoding="base64"` works in a
	 * configuration file as well as the enum case does in PHP.
	 * @param mixed $value an encoding, or its name in any case.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no encoding.
	 * @return self the encoding $value names.
	 */
	public static function ensure(mixed $value): self
	{
		if ($value instanceof self) {
			return $value;
		}
		$encoding = self::tryFrom(strtolower(trim((string) $value)));
		if ($encoding === null) {
			throw new TInvalidDataValueException('webhooks_encoding_invalid', (string) $value);
		}

		return $encoding;
	}
}
