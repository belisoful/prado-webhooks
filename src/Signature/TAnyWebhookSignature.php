<?php

/**
 * TAnyWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

/**
 * TAnyWebhookSignature class.
 *
 * Accepts a delivery that satisfies **any** of its children. A secret rotation is the usual
 * reason: configure the new secret alongside the old one, wait for the provider to finish
 * switching over, then drop the old child.
 *
 * ```xml
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TAnyWebhookSignature">
 *		<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *			Secret="the-new-one" Header="X-Signature" />
 *		<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *			Secret="the-old-one" Header="X-Signature" />
 * </signature>
 * ```
 *
 * Each child weakens the endpoint by exactly what that child accepts, so this is a place to
 * pass through rather than to settle in: an old secret left configured is an old secret
 * still working.
 *
 * Signing uses the first child that can sign -- the one an application would want a
 * receiver to be checking against.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TAnyWebhookSignature extends TCompositeWebhookSignature
{
	/**
	 * @param bool[] $results what each child answered.
	 * @return bool whether any child accepted the request.
	 */
	protected function combine(array $results): bool
	{
		return in_array(true, $results, true);
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner[] the first child that
	 *   can sign, if there is one.
	 */
	protected function signingChildren(): array
	{
		foreach ($this->getSignatures() as $signature) {
			if ($signature instanceof IWebhookSigner) {
				return [$signature];
			}
		}

		return [];
	}
}
