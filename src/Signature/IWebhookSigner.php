<?php

/**
 * IWebhookSigner interface file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookRequest;

/**
 * IWebhookSigner interface.
 *
 * Produces the headers that prove an outbound webhook came from this application.
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookSender} calls {@see sign} once per attempt,
 * with the request it is about to make, and merges the returned headers into it.
 *
 * Signing and verifying are the same scheme read in opposite directions, so the classes in
 * this namespace implement both this interface and {@see IWebhookVerifier}: what one PRADO
 * application signs, another verifies with an identically configured object. A scheme that
 * cannot be run in reverse -- an address allow list, a verify-only public key -- implements
 * {@see IWebhookVerifier} alone.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
interface IWebhookSigner
{
	/**
	 * Returns the signature headers for an outbound request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request about to be
	 *   made, carrying the encoded body and the headers already set on it.
	 * @throws \Prado\Exceptions\TConfigurationException when the signer is not configured.
	 * @return array<string, string> headers to merge into the request, keyed by name.
	 */
	public function sign(TWebhookRequest $request): array;
}
