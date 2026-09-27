<?php

/**
 * TWebhookSource class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\Exceptions\TInvalidDataValueException;

/**
 * TWebhookSource enum.
 *
 * Where in a request a scheme's values are found. Nearly every provider uses headers, but
 * not all of them: some put a token in the query string of the URL they were given, and
 * Mailgun-shaped schemes put the timestamp, the nonce, and the signature itself in the
 * posted form body.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
enum TWebhookSource: string
{
	/** An HTTP header, matched without regard to case. */
	case Header = 'header';

	/** A query string parameter of the request URL. */
	case Query = 'query';

	/**
	 * A field of the posted form body: a scalar entry of `$_POST`, which PHP fills for a
	 * form-encoded body and leaves empty for JSON. The query string is {@see Query}, not
	 * here, so a scheme that signs the posted fields does not also sign `?webhook=<id>`.
	 */
	case Parameter = 'parameter';

	/**
	 * Coerces a property value to a source, so `Source="query"` works in a configuration
	 * file as well as the enum case does in PHP.
	 * @param mixed $value a source, or its name in any case.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no source.
	 * @return self the source $value names.
	 */
	public static function ensure(mixed $value): self
	{
		if ($value instanceof self) {
			return $value;
		}
		$source = self::tryFrom(strtolower(trim((string) $value)));
		if ($source === null) {
			throw new TInvalidDataValueException('webhooks_source_invalid', (string) $value);
		}

		return $source;
	}
}
