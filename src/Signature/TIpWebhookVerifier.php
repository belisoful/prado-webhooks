<?php

/**
 * TIpWebhookVerifier class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\TApplicationComponent;
use Prado\TPropertyValue;

/**
 * TIpWebhookVerifier class.
 *
 * Accepts a delivery only from addresses the provider publishes. Some providers offer
 * nothing else, and it is worth adding underneath the ones that do -- an allow list and a
 * signature fail independently, so an attacker needs both.
 *
 * ```xml
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TIpWebhookVerifier"
 *		Addresses="192.0.2.0/24, 198.51.100.17, 2001:db8::/32" />
 *
 * <!-- behind a load balancer that the application, not the caller, vouches for -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TIpWebhookVerifier"
 *		Addresses="192.0.2.0/24" ForwardedHeader="X-Forwarded-For"
 *		TrustedProxies="10.0.0.0/8" />
 * ```
 *
 * **A forwarded header is written by whoever is talking to you.** It is read only when the
 * connection itself comes from a {@see setTrustedProxies TrustedProxies} address, and even
 * then only the last entry the trusted hop added is believed -- everything to the left of
 * it was supplied by the caller. Configure `ForwardedHeader` without `TrustedProxies` and
 * verification refuses rather than trusting the caller's own claim about where they are.
 *
 * This is a verifier and not a signer: an address is a property of the connection, not
 * something a sender can put in a header. It authenticates the peer and nothing about the
 * request, so on its own it cannot tell a genuine delivery from anything else the same host
 * sends -- pair it with a keyed scheme through {@see TAllWebhookSignature} wherever the
 * provider has one.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TIpWebhookVerifier extends TApplicationComponent implements IWebhookVerifier
{
	/** @var string[] the addresses and ranges a delivery may come from */
	private array $_addresses = [];

	/** @var null|string the header a trusted proxy records the caller's address in */
	private ?string $_forwardedHeader = null;

	/** @var string[] the addresses and ranges whose forwarded header is believed */
	private array $_trustedProxies = [];

	/**
	 * Verifies that a request came from an allowed address.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when no addresses are configured, or
	 *   a forwarded header is read without trusted proxies to vouch for it.
	 * @return bool whether the address is allowed.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		if ($this->_addresses === []) {
			throw new TConfigurationException('webhooks_addresses_required', static::class);
		}
		if ($this->_forwardedHeader !== null && $this->_trustedProxies === []) {
			throw new TConfigurationException('webhooks_trusted_proxies_required', static::class);
		}

		$address = $this->clientAddress($request);
		if ($address === null) {
			return false;
		}

		return $this->matchesAny($address, $this->_addresses);
	}

	/**
	 * Works out which address to judge the request by.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|string the address, or null when there is none to judge.
	 */
	protected function clientAddress(TWebhookRequest $request): ?string
	{
		$address = $request->getRemoteAddress();
		if ($address === null || $this->_forwardedHeader === null) {
			return $address;
		}
		if (!$this->matchesAny($address, $this->_trustedProxies)) {
			// The connection is not from a hop we vouch for, so its header is just a claim.
			return $address;
		}

		$forwarded = $request->getHeader($this->_forwardedHeader);
		if ($forwarded === null || trim($forwarded) === '') {
			return $address;
		}
		$hops = array_values(array_filter(array_map('trim', explode(',', $forwarded)), static fn ($h) => $h !== ''));

		// The trusted hop appends; everything before its entry came from the caller.
		return end($hops) ?: $address;
	}

	/**
	 * @param string $address the address to test.
	 * @param string[] $ranges the addresses and CIDR ranges to test it against.
	 * @return bool whether the address falls in any of them.
	 */
	protected function matchesAny(string $address, array $ranges): bool
	{
		$packed = @inet_pton($address);
		if ($packed === false) {
			return false;
		}
		foreach ($ranges as $range) {
			if ($this->matches($packed, $range)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param string $packed the address, as {@see inet_pton} packs it.
	 * @param string $range one address or CIDR range.
	 * @return bool whether the address falls in it.
	 */
	protected function matches(string $packed, string $range): bool
	{
		[$network, $bits] = array_pad(explode('/', $range, 2), 2, null);
		$packedNetwork = @inet_pton((string) $network);
		if ($packedNetwork === false || strlen($packedNetwork) !== strlen($packed)) {
			// Different families never match, and neither does a range that will not parse.
			return false;
		}
		if ($bits === null) {
			return hash_equals($packedNetwork, $packed);
		}

		// Duplicated from setAddresses on purpose: an allow list that silently becomes
		// allow-everything is worth refusing in both places.
		if (!ctype_digit($bits)) {
			return false;
		}
		$bits = (int) $bits;
		if ($bits > strlen($packed) * 8) {
			return false;
		}
		$whole = intdiv($bits, 8);
		if ($whole > 0 && strncmp($packed, $packedNetwork, $whole) !== 0) {
			return false;
		}
		$remainder = $bits % 8;
		if ($remainder === 0) {
			return true;
		}
		$mask = chr((0xFF << (8 - $remainder)) & 0xFF);

		return (($packed[$whole] & $mask) === ($packedNetwork[$whole] & $mask));
	}

	/**
	 * @return string[] the addresses and ranges a delivery may come from.
	 */
	public function getAddresses(): array
	{
		return $this->_addresses;
	}

	/**
	 * Sets the allow list, as addresses or CIDR ranges, IPv4 or IPv6. Take it from the
	 * provider's published list and expect to revisit it: these change, usually without
	 * warning and always at an inconvenient moment.
	 * @param mixed $value the addresses, as an array or a comma separated list.
	 * @throws \Prado\Exceptions\TConfigurationException when $value names none, names an
	 *   address that will not parse, or gives a prefix length that is not a number within
	 *   the family's range. The last is refused rather than read as `/0`, which would turn
	 *   the allow list into the entire address family; write `/0` where that is meant.
	 */
	public function setAddresses($value): void
	{
		$this->_addresses = $this->parseRanges($value, 'Addresses');
	}

	/**
	 * @return null|string the header a trusted proxy records the caller's address in.
	 */
	public function getForwardedHeader(): ?string
	{
		return $this->_forwardedHeader;
	}

	/**
	 * @param mixed $value the header name, or an empty value to judge the connection itself.
	 */
	public function setForwardedHeader($value): void
	{
		$header = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_forwardedHeader = $header === '' ? null : $header;
	}

	/**
	 * @return string[] the addresses and ranges whose forwarded header is believed.
	 */
	public function getTrustedProxies(): array
	{
		return $this->_trustedProxies;
	}

	/**
	 * Sets the hops that may speak for a caller. Keep it to infrastructure the application
	 * owns; a range that is wider than it should be hands an attacker the ability to claim
	 * any address at all.
	 * @param mixed $value the addresses, as an array or a comma separated list.
	 * @throws \Prado\Exceptions\TConfigurationException when one will not parse.
	 */
	public function setTrustedProxies($value): void
	{
		$this->_trustedProxies = $value === null || $value === ''
			? []
			: $this->parseRanges($value, 'TrustedProxies');
	}

	/**
	 * @param mixed $value the configured list.
	 * @param string $property the property being set, for the error message.
	 * @throws \Prado\Exceptions\TConfigurationException when the list is empty or holds
	 *   something that is not an address or range.
	 * @return string[] the ranges.
	 */
	protected function parseRanges($value, string $property): array
	{
		$ranges = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$ranges = array_values(array_filter(array_map(
			static fn ($range) => trim((string) $range),
			$ranges
		), static fn ($range) => $range !== ''));

		if ($ranges === []) {
			throw new TConfigurationException('webhooks_addresses_required', static::class);
		}
		foreach ($ranges as $range) {
			[$network, $bits] = array_pad(explode('/', $range, 2), 2, null);
			$packed = @inet_pton((string) $network);
			if ($packed === false) {
				throw new TConfigurationException('webhooks_address_invalid', $range, $property, static::class);
			}
			// A prefix length that is not a number would read as /0 -- an allow list that
			// allows the entire address family, which is the opposite of what it says.
			if ($bits !== null && (!ctype_digit($bits) || (int) $bits > strlen($packed) * 8)) {
				throw new TConfigurationException('webhooks_prefix_invalid', $range, $property, static::class);
			}
		}

		return $ranges;
	}
}
