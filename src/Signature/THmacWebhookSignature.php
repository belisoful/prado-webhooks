<?php

/**
 * THmacWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\TPropertyValue;

/**
 * THmacWebhookSignature class.
 *
 * A keyed hash of the request, in a value of its own. This is what most providers do, and
 * everything they disagree on is a property: which hash, which header, what prefixes the
 * value, hex or base64, and -- through
 * {@see \Belisoful\Prado\Web\Webhooks\Signature\TWebhookSignature::setPayloadFormat
 * PayloadFormat} -- what is hashed.
 *
 * ```xml
 * <!-- a keyed hash of the body, under the provider's header -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *		Secret="..." Header="X-Hub-Signature-256" Prefix="sha256=" />
 *
 * <!-- the same hash, rendered base64 -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *		Secret="..." Header="X-Shopify-Hmac-Sha256" Encoding="base64" />
 *
 * <!-- the URL and the sorted form parameters, SHA-1, base64 -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *		Secret="..." Header="X-Twilio-Signature" Algorithm="sha1" Encoding="base64"
 *		PayloadFormat="{url}{params}" />
 *
 * <!-- the same, where the provider posts JSON and puts a digest of it in the URL instead -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *		Secret="..." Header="X-Twilio-Signature" Algorithm="sha1" Encoding="base64"
 *		PayloadFormat="{url}" BodyHashName="bodySHA256" BodyHashSource="query" />
 *
 * <!-- an id and a timestamp bound into the hash, several signatures through a rotation -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *		Secret="whsec_..." SecretPrefix="whsec_" SecretEncoding="base64"
 *		Header="webhook-signature" IdHeader="webhook-id" TimestampHeader="webhook-timestamp"
 *		PayloadFormat="{id}.{timestamp}.{body}" Prefix="v1," Separator=" " Encoding="base64" />
 * ```
 *
 * Verification is constant time, compares every presented signature, and returns false for
 * everything an attacker supplies rather than reporting which part was wrong. When a
 * provider packs the timestamp into the signature value itself rather than into a header of
 * its own, use {@see TFieldedWebhookSignature}.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class THmacWebhookSignature extends TWebhookSignature implements IWebhookVerifier, IWebhookSigner
{
	use TWebhookSecretTrait;

	/** @var string the hash algorithm backing the MAC */
	private string $_algorithm = 'sha256';

	/**
	 * Verifies the signature a request presents against one computed from the request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when the scheme is not configured.
	 * @return bool whether a presented signature matches and, when the scheme is
	 *   timestamped, is recent.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		// Checked before the request is looked at: a verifier with no secret is a
		// configuration error whatever arrives, and must not degrade into an endpoint that
		// reports every delivery, signed or not, as a forgery.
		$this->getSecretKey();

		$presented = $this->presentedSignatures($request);
		if ($presented === [] || !$this->bodyHashHolds($request)) {
			return false;
		}

		$timestamp = $this->presentedTimestamp($request);
		if ($this->getTimestampName() !== null && !$this->isFresh($timestamp)) {
			return false;
		}

		$bound = ['timestamp' => (string) $timestamp, 'id' => (string) $this->presentedId($request)];

		return $this->matchesAny($this->computeSignature($request, $bound), $presented);
	}

	/**
	 * Signs an outbound request, producing headers an identically configured verifier accepts.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request about to be made.
	 * @throws \Prado\Exceptions\TConfigurationException when the scheme is not configured.
	 * @return array<string, string> the signature header, plus the timestamp and id headers
	 *   when the scheme names them.
	 */
	public function sign(TWebhookRequest $request): array
	{
		$bound = ['timestamp' => '', 'id' => ''];
		if ($this->getTimestampName() !== null) {
			$bound['timestamp'] = (string) time();
		}
		if ($this->getIdName() !== null) {
			// A request that already carries an id is signed under that id.
			// {@see \Belisoful\Prado\Web\Webhooks\TWebhookSender} puts the delivery's own
			// there, which is what keeps it the same across that delivery's retries; a caller
			// signing by hand gets a fresh one rather than none.
			$bound['id'] = $this->presentedId($request) ?? bin2hex(random_bytes(16));
		}

		$signed = [$this->getName() => $this->computeSignature($request, $bound)];
		if ($bound['timestamp'] !== '') {
			$signed[(string) $this->getTimestampName()] = $bound['timestamp'];
		}
		if ($bound['id'] !== '') {
			$signed[(string) $this->getIdName()] = $bound['id'];
		}

		return $signed;
	}

	/**
	 * Computes the full value of the signature, prefix included. Signing and verifying share
	 * this method, which is what makes the two directions provably the same scheme.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param array<string, string> $bound the values `{timestamp}` and `{id}` stand for.
	 * @throws \Prado\Exceptions\TConfigurationException when the scheme is not configured.
	 * @return string the signature value.
	 */
	protected function computeSignature(TWebhookRequest $request, array $bound = []): string
	{
		$mac = hash_hmac($this->_algorithm, $this->expandPayload($request, $bound), $this->getSecretKey(), true);

		return $this->getPrefix() . $this->getEncoding()->encode($mac);
	}

	/**
	 * @return string the hash algorithm backing the MAC. Defaults to `sha256`.
	 */
	public function getAlgorithm(): string
	{
		return $this->_algorithm;
	}

	/**
	 * @param mixed $value a hash algorithm {@see hash_hmac_algos} lists.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when PHP cannot key an HMAC with $value.
	 */
	public function setAlgorithm($value): void
	{
		$algorithm = strtolower(trim(TPropertyValue::ensureString($value)));
		if (!in_array($algorithm, hash_hmac_algos(), true)) {
			throw new TInvalidDataValueException('webhooks_algorithm_invalid', $algorithm);
		}
		$this->_algorithm = $algorithm;
	}
}
