<?php

/**
 * TWebhookPadding class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\Exceptions\TInvalidDataValueException;

/**
 * TWebhookPadding enum.
 *
 * How an RSA signature is padded. The two are not interchangeable and not detectable from
 * the signature: a PSS signature checked as PKCS#1 v1.5 simply fails, which looks exactly
 * like a wrong key.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
enum TWebhookPadding: string
{
	/** RSASSA-PKCS1-v1_5, what most providers send and what OpenSSL does by default. */
	case Pkcs1 = 'pkcs1';

	/** RSASSA-PSS, the padding RFC 9421 recommends and newer providers use. */
	case Pss = 'pss';

	/**
	 * Coerces a property value to a padding, so `Padding="pss"` works in a configuration
	 * file as well as the enum case does in PHP.
	 * @param mixed $value a padding, or its name in any case.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no padding.
	 * @return self the padding $value names.
	 */
	public static function ensure(mixed $value): self
	{
		if ($value instanceof self) {
			return $value;
		}
		$padding = self::tryFrom(strtolower(trim((string) $value)));
		if ($padding === null) {
			throw new TInvalidDataValueException('webhooks_padding_invalid', (string) $value);
		}

		return $padding;
	}
}
