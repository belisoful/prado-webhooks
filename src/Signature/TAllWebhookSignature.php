<?php

/**
 * TAllWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

/**
 * TAllWebhookSignature class.
 *
 * Requires a delivery to satisfy **every** one of its children. Layering independent checks
 * is what this is for: an address allow list under a keyed signature leaves an attacker
 * needing both the provider's network position and its secret.
 *
 * ```xml
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TAllWebhookSignature">
 *		<signature class="Belisoful\Prado\Web\Webhooks\Signature\TIpWebhookVerifier"
 *			Addresses="192.0.2.0/24" />
 *		<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *			Secret="..." Header="X-Signature" />
 * </signature>
 * ```
 *
 * A child that can only verify -- an address list has no outbound form -- contributes
 * nothing when signing, and the remaining children still sign.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TAllWebhookSignature extends TCompositeWebhookSignature
{
	/**
	 * @param bool[] $results what each child answered.
	 * @return bool whether every child accepted the request.
	 */
	protected function combine(array $results): bool
	{
		return $results !== [] && !in_array(false, $results, true);
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner[] every child that can sign.
	 */
	protected function signingChildren(): array
	{
		return array_values(array_filter(
			$this->getSignatures(),
			static fn ($signature) => $signature instanceof IWebhookSigner
		));
	}
}
