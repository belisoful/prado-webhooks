<?php

/**
 * IWebhookVerifier interface file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookRequest;

/**
 * IWebhookVerifier interface.
 *
 * Decides whether an inbound request really came from the provider that claims to have sent
 * it. A {@see \Belisoful\Prado\Web\Webhooks\TWebhookEndpoint} calls {@see verify} with the
 * whole request, because schemes differ in what they authenticate: the body, the body and a
 * timestamp, the URL and the sorted form parameters, or nothing but a credential.
 *
 * Implementations return false rather than throwing for anything an attacker controls: a
 * missing header, a malformed signature, a stale timestamp, a key that will not parse. They
 * throw only when the *configuration* is unusable, such as a verifier with no secret --
 * quietly answering false there would turn an unreachable endpoint into what looks like a
 * stream of forged requests.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
interface IWebhookVerifier
{
	/**
	 * Verifies an inbound webhook request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received,
	 *   whose body is the bytes the provider sent.
	 * @throws \Prado\Exceptions\TConfigurationException when the verifier is not configured.
	 * @return bool whether the request is authentic.
	 */
	public function verify(TWebhookRequest $request): bool;
}
