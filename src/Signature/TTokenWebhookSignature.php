<?php

/**
 * TTokenWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\TPropertyValue;
use Prado\Web\THttpHeaderName;

/**
 * TTokenWebhookSignature class.
 *
 * A shared secret presented as it is, for the providers that sign nothing. Some offer HTTP
 * Basic authentication on the webhook URL and no signature at all; some send an API key in
 * a header of their own; some put a token in the query string of the URL you registered.
 * All three are this class.
 *
 * ```xml
 * <!-- Basic credentials set on the webhook in the provider's dashboard -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TTokenWebhookSignature"
 *		Token="aGVsbG86d29ybGQ=" Prefix="Basic " />
 *
 * <!-- an API key in a header of the provider's own -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TTokenWebhookSignature"
 *		Token="..." Header="X-Api-Key" Prefix="" />
 *
 * <!-- a token in the query string of the registered URL -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TTokenWebhookSignature"
 *		Token="..." Source="query" Name="key" Prefix="" />
 * ```
 *
 * A token is strictly weaker than a signature: it travels with every request and
 * authenticates none of it, so anything that can read one request can forge any request.
 * A token in a query string is weaker still, because URLs end up in logs, proxies, and
 * referrers. Prefer a keyed scheme where the provider offers one, require TLS where it does
 * not, and treat the token as the password it is.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TTokenWebhookSignature extends TWebhookSignature implements IWebhookVerifier, IWebhookSigner
{
	/** @var string the prefix a bearer token carries, including its trailing space. */
	public const BEARER_PREFIX = 'Bearer ';

	/** @var string the shared secret */
	private string $_token = '';

	/**
	 * Defaults to a bearer token in the `Authorization` header, which is where most
	 * providers that use one put it.
	 */
	public function __construct()
	{
		parent::__construct();
		$this->setName(THttpHeaderName::Authorization);
		$this->setPrefix(self::BEARER_PREFIX);
	}

	/**
	 * Compares the presented value against the configured token, in constant time.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received,
	 *   whose body this scheme does not authenticate.
	 * @throws \Prado\Exceptions\TConfigurationException when no token is set.
	 * @return bool whether the request presents the token.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		$presented = $this->readValue($request, $this->getName());
		if ($presented === null || !$this->bodyHashHolds($request)) {
			return false;
		}

		return hash_equals($this->presentedValue(), $presented);
	}

	/**
	 * Returns the token header for an outbound request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request about to be
	 *   made, which this scheme does not authenticate.
	 * @throws \Prado\Exceptions\TConfigurationException when no token is set, or the token
	 *   belongs somewhere this package cannot put it.
	 * @return array<string, string> the token header.
	 */
	public function sign(TWebhookRequest $request): array
	{
		if ($this->getHeader() === null) {
			// A signer returns headers; a token that lives in the URL has to be part of the
			// target's URL instead, and silently dropping it would send an unauthenticated
			// delivery that looks signed.
			throw new TConfigurationException('webhooks_sign_source_unsupported', $this->getSource()->value, static::class);
		}

		return [$this->getName() => $this->presentedValue()];
	}

	/**
	 * @throws \Prado\Exceptions\TConfigurationException when no token is set.
	 * @return string the full value a request should present, prefix included.
	 */
	protected function presentedValue(): string
	{
		if ($this->_token === '') {
			throw new TConfigurationException('webhooks_token_required', static::class);
		}

		return $this->getPrefix() . $this->_token;
	}

	/**
	 * @return string the shared secret.
	 */
	public function getToken(): string
	{
		return $this->_token;
	}

	/**
	 * @param mixed $value the shared secret, without the {@see getPrefix Prefix}.
	 */
	public function setToken($value): void
	{
		$this->_token = TPropertyValue::ensureString($value);
	}
}
