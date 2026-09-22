<?php

/**
 * TWebhookKeyTrait class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

/**
 * TWebhookKeyTrait trait.
 *
 * Accepts a key as PEM text or as a path to a file holding it, so a configuration can name
 * a file rather than inlining key material into the application configuration.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
trait TWebhookKeyTrait
{
	/**
	 * @param string $key the configured value: PEM text, or a path to a file holding it.
	 * @return string the PEM text.
	 */
	protected function readKeyMaterial(string $key): string
	{
		if (!str_contains($key, '-----BEGIN') && is_file($key)) {
			return (string) file_get_contents($key);
		}

		return $key;
	}
}
