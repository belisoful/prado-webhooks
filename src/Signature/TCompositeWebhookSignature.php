<?php

/**
 * TCompositeWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookConfigurationTrait;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\TApplicationComponent;

/**
 * TCompositeWebhookSignature class.
 *
 * Several schemes on one endpoint, configured as children:
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
 * {@see TAnyWebhookSignature} accepts a delivery that satisfies one child, which is how a
 * secret is rotated without an outage: add the new one, wait out the provider's rollout,
 * remove the old one. {@see TAllWebhookSignature} requires every child, which is how an
 * address allow list is layered under a signature so that an attacker needs both.
 *
 * Every child is evaluated even once the answer is settled, so how many schemes matched,
 * and which, stays out of the response time.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
abstract class TCompositeWebhookSignature extends TApplicationComponent implements IWebhookVerifier, IWebhookSigner
{
	use TWebhookConfigurationTrait;

	/** @var object[] the schemes this one is made of */
	private array $_signatures = [];

	/**
	 * Builds the `signature` children.
	 * @param mixed $config this component's configuration.
	 * @throws \Prado\Exceptions\TConfigurationException when a child names no class, or names
	 *   one that neither verifies nor signs.
	 */
	public function init($config): void
	{
		foreach ($this->childConfigurationList($config, 'signature') as $child) {
			$this->addSignature($this->createConfigured($child, [IWebhookVerifier::class, IWebhookSigner::class]));
		}
	}

	/**
	 * Verifies a request against the children.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when there are no children, or a
	 *   child is not configured.
	 * @return bool whether the request satisfies this composite.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		if ($this->_signatures === []) {
			throw new TConfigurationException('webhooks_signatures_required', static::class);
		}

		$results = [];
		foreach ($this->_signatures as $signature) {
			$results[] = $signature instanceof IWebhookVerifier && $signature->verify($request);
		}

		return $this->combine($results);
	}

	/**
	 * @param bool[] $results what each child answered, in order.
	 * @return bool whether the composite accepts the request.
	 */
	abstract protected function combine(array $results): bool;

	/**
	 * Signs an outbound request with the children that can sign.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request about to be made.
	 * @throws \Prado\Exceptions\TConfigurationException when no child can sign.
	 * @return array<string, string> the merged signature headers.
	 */
	public function sign(TWebhookRequest $request): array
	{
		$headers = [];
		foreach ($this->signingChildren() as $signer) {
			$headers = array_merge($headers, $signer->sign($request));
		}
		if ($headers === []) {
			throw new TConfigurationException('webhooks_signers_required', static::class);
		}

		return $headers;
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner[] the children that sign
	 *   an outbound request.
	 */
	abstract protected function signingChildren(): array;

	/**
	 * @return object[] the schemes this one is made of.
	 */
	public function getSignatures(): array
	{
		return $this->_signatures;
	}

	/**
	 * Adds a scheme, which is how one is registered from PHP rather than configuration.
	 * @param object $signature an {@see IWebhookVerifier}, an {@see IWebhookSigner}, or both.
	 * @throws \Prado\Exceptions\TConfigurationException when $signature is neither.
	 */
	public function addSignature(object $signature): void
	{
		if (!($signature instanceof IWebhookVerifier) && !($signature instanceof IWebhookSigner)) {
			throw new TConfigurationException('webhooks_component_invalid', $signature::class, IWebhookVerifier::class);
		}
		$this->_signatures[] = $signature;
	}
}
