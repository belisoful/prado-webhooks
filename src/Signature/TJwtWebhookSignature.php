<?php

/**
 * TJwtWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookEncoding;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\TPropertyValue;
use Prado\Web\THttpHeaderName;

/**
 * TJwtWebhookSignature class.
 *
 * A JSON Web Token presented with the delivery, as `Authorization: Bearer <jwt>` or in a
 * header of the provider's own. Providers that already issue tokens for their API tend to
 * reuse them here, and a few sign the notification itself as a JWS.
 *
 * ```xml
 * <!-- a token the provider signed with a shared secret -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TJwtWebhookSignature"
 *		Secret="..." Algorithms="HS256" Issuer="https://provider.example" Audience="my-app" />
 *
 * <!-- a token signed with the provider's key, and bound to this delivery's body -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TJwtWebhookSignature"
 *		PublicKey="protected/keys/provider.pem" Algorithms="RS256, ES256"
 *		BodyHashClaim="body_sha256" />
 * ```
 *
 * **A JWT authenticates its bearer, not the request it arrived with.** Unless something ties
 * the token to *this* delivery, anyone who captures one can replay it against any body they
 * like -- which is exactly what a webhook attacker wants. {@see setBodyHashClaim
 * BodyHashClaim} names the claim holding a digest of the body, and when it is set the digest
 * has to match; use it whenever the provider offers it.
 *
 * `alg` is read from the token but never trusted: it has to appear in
 * {@see setAlgorithms Algorithms}, which is an allow list the application sets. That is what
 * stops the family of attacks where a token arrives claiming `none`, or claiming `HS256`
 * against a key the application meant to use asymmetrically.
 *
 * `exp` and `nbf` are honored when present, within {@see setLeeway Leeway}; one that is
 * present but not a number refuses the token rather than being overlooked, and
 * {@see setRequireExpiry RequireExpiry} refuses a token that carries no `exp` at all.
 * {@see setIssuer Issuer} and {@see setAudience Audience} are checked when set, and setting
 * both is worth the trouble: a token minted by the same provider for some other customer
 * is otherwise a valid token.
 *
 * A header carrying `crit` (RFC 7515 section 4.1.11) is refused: it declares extensions the
 * recipient must understand, and this class understands none. The `Bearer` scheme word is
 * matched without regard to case, as RFC 7235 says an auth-scheme is; a prefix that is not
 * an auth-scheme -- one that does not end in a space -- is matched exactly.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TJwtWebhookSignature extends TWebhookSignature implements IWebhookVerifier, IWebhookSigner
{
	use TWebhookEcdsaTrait;
	use TWebhookKeyTrait;

	/** @var int the clock skew allowed on `exp` and `nbf`, in seconds. */
	public const DEFAULT_LEEWAY = 60;

	/** @var array<string, string> the JWS algorithms this class implements, and their digests. */
	public const ALGORITHMS = [
		'HS256' => 'sha256', 'HS384' => 'sha384', 'HS512' => 'sha512',
		'RS256' => 'sha256', 'RS384' => 'sha384', 'RS512' => 'sha512',
		'ES256' => 'sha256', 'ES384' => 'sha384', 'ES512' => 'sha512',
	];

	/** @var array<string, int> the coordinate size of each ECDSA curve, in bytes. */
	private const CURVE_SIZES = ['ES256' => 32, 'ES384' => 48, 'ES512' => 66];

	/** @var string the shared secret, for the HS family */
	private string $_secret = '';

	/** @var string the public key, as PEM or a path to it, for the RS and ES families */
	private string $_publicKey = '';

	/** @var string the private key, as PEM or a path to it, for signing */
	private string $_privateKey = '';

	/** @var string[] the algorithms a token may declare */
	private array $_algorithms = ['HS256'];

	/** @var null|string the issuer a token must name */
	private ?string $_issuer = null;

	/** @var null|string the audience a token must name */
	private ?string $_audience = null;

	/** @var int the clock skew allowed on `exp` and `nbf`, in seconds */
	private int $_leeway = self::DEFAULT_LEEWAY;

	/** @var null|string the claim holding a digest of the body */
	private ?string $_bodyHashClaim = null;

	/** @var int how long a signed token is valid, in seconds */
	private int $_lifetime = 300;

	/** @var bool whether a token without `exp` is refused */
	private bool $_requireExpiry = false;

	/**
	 * Defaults to a bearer token in the `Authorization` header, the form a JWT almost
	 * always arrives in.
	 */
	public function __construct()
	{
		parent::__construct();
		$this->setName(THttpHeaderName::Authorization);
		$this->setPrefix(TTokenWebhookSignature::BEARER_PREFIX);
	}

	/**
	 * Verifies the token a request presents.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when no allowed algorithm has a key
	 *   configured, whatever the request carries, or the key for the declared one will
	 *   not parse.
	 * @return bool whether the token verifies and its claims hold for this delivery.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		// Before the request is looked at: a verifier with no key for any algorithm it
		// allows is misconfigured whatever arrives, and must not quietly refuse everything.
		$this->requireSomeKey();

		$presented = $this->readValue($request, $this->getName());
		if ($presented === null || !$this->bodyHashHolds($request)) {
			return false;
		}
		$presented = $this->stripPrefix($presented);
		if ($presented === null) {
			return false;
		}

		$parts = explode('.', trim($presented));
		if (count($parts) !== 3) {
			return false;
		}
		[$encodedHeader, $encodedClaims, $encodedSignature] = $parts;

		$header = $this->decodeSegment($encodedHeader);
		$claims = $this->decodeSegment($encodedClaims);
		$signature = TWebhookEncoding::Base64Url->decode($encodedSignature);
		if ($header === null || $claims === null || $signature === false || $signature === '') {
			return false;
		}
		if (array_key_exists('crit', $header)) {
			// RFC 7515 section 4.1.11: `crit` names extensions the recipient must understand,
			// and a recipient that understands none of them must refuse the token.
			return false;
		}

		// The token says which algorithm it used; the application says which it will accept.
		$algorithm = is_string($header['alg'] ?? null) ? $header['alg'] : '';
		if (!in_array($algorithm, $this->_algorithms, true) || !isset(self::ALGORITHMS[$algorithm])) {
			return false;
		}
		if (!$this->verifySignature($algorithm, $encodedHeader . '.' . $encodedClaims, $signature)) {
			return false;
		}

		return $this->claimsHold($claims, $request);
	}

	/**
	 * Removes {@see getPrefix Prefix} from the presented value.
	 *
	 * A prefix that ends in a space is an HTTP auth-scheme -- `Bearer ` -- and RFC 7235
	 * says an auth-scheme is matched without regard to case, so `bearer` and `BEARER` are
	 * the same scheme. Any other prefix is a literal the provider chose, and is matched
	 * exactly.
	 *
	 * @param string $presented the presented value.
	 * @return null|string the token, or null when the value does not carry the prefix.
	 * @since 0.2.0
	 */
	protected function stripPrefix(string $presented): ?string
	{
		$prefix = $this->getPrefix();
		if ($prefix === '') {
			return $presented;
		}
		$carried = str_ends_with($prefix, ' ')
			? strncasecmp($presented, $prefix, strlen($prefix)) === 0
			: str_starts_with($presented, $prefix);

		return $carried ? substr($presented, strlen($prefix)) : null;
	}

	/**
	 * Whether key material is configured for the family an algorithm belongs to.
	 * @param string $algorithm one of {@see ALGORITHMS}.
	 * @return bool whether the secret (HS) or the public key (RS, ES) is set.
	 * @since 0.2.0
	 */
	protected function hasKeyFor(string $algorithm): bool
	{
		return $algorithm[0] === 'H' ? $this->_secret !== '' : $this->_publicKey !== '';
	}

	/**
	 * Requires that at least one allowed algorithm has key material to verify with.
	 * @throws \Prado\Exceptions\TConfigurationException when none does.
	 * @since 0.2.0
	 */
	protected function requireSomeKey(): void
	{
		foreach ($this->_algorithms as $algorithm) {
			if ($this->hasKeyFor($algorithm)) {
				return;
			}
		}
		throw new TConfigurationException(
			($this->_algorithms[0] ?? 'H')[0] === 'H' ? 'webhooks_secret_required' : 'webhooks_public_key_required',
			static::class
		);
	}

	/**
	 * Mints a token for an outbound request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request about to be made.
	 * @throws \Prado\Exceptions\TConfigurationException when no algorithm or key is
	 *   configured for signing, or the signing fails.
	 * @return array<string, string> the header carrying the token.
	 */
	public function sign(TWebhookRequest $request): array
	{
		$algorithm = $this->_algorithms[0] ?? '';
		if (!isset(self::ALGORITHMS[$algorithm])) {
			throw new TConfigurationException('webhooks_algorithm_unsupported', $algorithm, static::class);
		}

		$now = time();
		$claims = ['iat' => $now, 'exp' => $now + $this->_lifetime];
		if ($this->_issuer !== null) {
			$claims['iss'] = $this->_issuer;
		}
		if ($this->_audience !== null) {
			$claims['aud'] = $this->_audience;
		}
		if ($this->_bodyHashClaim !== null) {
			$claims[$this->_bodyHashClaim] = $this->bodyDigest($request);
		}

		$signing = $this->encodeSegment(['alg' => $algorithm, 'typ' => 'JWT'])
			. '.' . $this->encodeSegment($claims);

		return [$this->getName() => $this->getPrefix() . $signing . '.'
			. TWebhookEncoding::Base64Url->encode($this->createSignature($algorithm, $signing))];
	}

	/**
	 * Whether a token's claims hold for this delivery.
	 * @param array<string, mixed> $claims the decoded claims.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return bool whether every configured check passes.
	 */
	protected function claimsHold(array $claims, TWebhookRequest $request): bool
	{
		$now = time();
		// A present `exp` or `nbf` that is not a number refuses the token: a claim that
		// cannot be read is not one that can be honored, and overlooking it would let a
		// token that says "expired: yes, in words" through.
		if (array_key_exists('exp', $claims)) {
			if (!is_numeric($claims['exp']) || $now - $this->_leeway >= (int) $claims['exp']) {
				return false;
			}
		} elseif ($this->_requireExpiry) {
			return false;
		}
		if (array_key_exists('nbf', $claims)
			&& (!is_numeric($claims['nbf']) || $now + $this->_leeway < (int) $claims['nbf'])) {
			return false;
		}
		if ($this->_issuer !== null && ($claims['iss'] ?? null) !== $this->_issuer) {
			return false;
		}
		if ($this->_audience !== null && !$this->audienceHolds($claims['aud'] ?? null)) {
			return false;
		}
		if ($this->_bodyHashClaim !== null) {
			$presented = $claims[$this->_bodyHashClaim] ?? null;
			if (!is_string($presented) || !hash_equals($this->bodyDigest($request), $presented)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * @param mixed $audience the `aud` claim, which may be one value or a list of them.
	 * @return bool whether it names this application.
	 */
	protected function audienceHolds(mixed $audience): bool
	{
		if (is_array($audience)) {
			return in_array($this->_audience, $audience, true);
		}

		return $audience === $this->_audience;
	}

	/**
	 * When the allow list mixes families -- `RS256` alongside `HS256`, say -- and only one
	 * family has key material, a token declaring the other is refused rather than reported as
	 * a configuration error: the sender chose that algorithm, and a sender must not be able
	 * to choose which exception the endpoint raises. The exception is kept for the case
	 * where no allowed algorithm has any key at all, which is genuinely unconfigured.
	 *
	 * @param string $algorithm the algorithm the token declared, already allow listed.
	 * @param string $signing the signing input, `header.claims`.
	 * @param string $signature the raw signature bytes.
	 * @throws \Prado\Exceptions\TConfigurationException when no allowed algorithm has a key.
	 * @return bool whether the signature verifies.
	 */
	protected function verifySignature(string $algorithm, string $signing, string $signature): bool
	{
		$digest = self::ALGORITHMS[$algorithm];

		if (!$this->hasKeyFor($algorithm)) {
			// Another allowed family is configured, so this is the sender's choice, not ours.
			$this->requireSomeKey();

			return false;
		}

		if ($algorithm[0] === 'H') {
			return hash_equals(hash_hmac($digest, $signing, $this->_secret, true), $signature);
		}
		$key = openssl_pkey_get_public($this->readKeyMaterial($this->_publicKey));
		if ($key === false) {
			throw new TConfigurationException('webhooks_key_invalid', 'PublicKey', static::class);
		}
		if ($algorithm[0] === 'E') {
			// JWS carries an ECDSA signature as the raw coordinates; OpenSSL wants DER.
			$signature = $this->derFromRaw($signature, self::CURVE_SIZES[$algorithm]);
			if ($signature === null) {
				return false;
			}
		}

		return openssl_verify($signing, $signature, $key, $digest) === 1;
	}

	/**
	 * @param string $algorithm the algorithm to sign with.
	 * @param string $signing the signing input.
	 * @throws \Prado\Exceptions\TConfigurationException when no key is configured, or the
	 *   signing fails.
	 * @return string the raw signature bytes.
	 */
	protected function createSignature(string $algorithm, string $signing): string
	{
		$digest = self::ALGORITHMS[$algorithm];

		if ($algorithm[0] === 'H') {
			if ($this->_secret === '') {
				throw new TConfigurationException('webhooks_secret_required', static::class);
			}

			return hash_hmac($digest, $signing, $this->_secret, true);
		}

		if ($this->_privateKey === '') {
			throw new TConfigurationException('webhooks_private_key_required', static::class);
		}
		$key = openssl_pkey_get_private($this->readKeyMaterial($this->_privateKey));
		if ($key === false) {
			throw new TConfigurationException('webhooks_key_invalid', 'PrivateKey', static::class);
		}
		$signature = '';
		if (!openssl_sign($signing, $signature, $key, $digest)) {
			throw new TConfigurationException('webhooks_signing_failed', static::class);
		}
		if ($algorithm[0] === 'E') {
			$signature = $this->rawFromDer($signature, self::CURVE_SIZES[$algorithm]);
			if ($signature === null) {
				throw new TConfigurationException('webhooks_signing_failed', static::class);
			}
		}

		return $signature;
	}

	/**
	 * @param string $segment a base64url segment of the token.
	 * @return null|array<string, mixed> the decoded object, or null when it is not one.
	 */
	protected function decodeSegment(string $segment): ?array
	{
		$json = TWebhookEncoding::Base64Url->decode($segment);
		if ($json === false) {
			return null;
		}
		$decoded = json_decode($json, true);

		return is_array($decoded) ? $decoded : null;
	}

	/**
	 * @param array<string, mixed> $value the object to encode.
	 * @return string the base64url segment.
	 */
	protected function encodeSegment(array $value): string
	{
		return TWebhookEncoding::Base64Url->encode((string) json_encode($value, JSON_UNESCAPED_SLASHES));
	}

	/**
	 * @return string the shared secret, for the HS family.
	 */
	public function getSecret(): string
	{
		return $this->_secret;
	}

	/**
	 * @param mixed $value the shared secret.
	 */
	public function setSecret($value): void
	{
		$this->_secret = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the public key, for the RS and ES families.
	 */
	public function getPublicKey(): string
	{
		return $this->_publicKey;
	}

	/**
	 * @param mixed $value the public key, as PEM text or a path to a file holding it.
	 */
	public function setPublicKey($value): void
	{
		$this->_publicKey = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the private key used for signing.
	 */
	public function getPrivateKey(): string
	{
		return $this->_privateKey;
	}

	/**
	 * @param mixed $value the private key, as PEM text or a path to a file holding it.
	 */
	public function setPrivateKey($value): void
	{
		$this->_privateKey = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string[] the algorithms a token may declare. Defaults to `['HS256']`.
	 */
	public function getAlgorithms(): array
	{
		return $this->_algorithms;
	}

	/**
	 * Sets the algorithms a token may declare, and the first of them is what {@see sign}
	 * mints with. Keep the list to what the provider actually uses: every entry is one more
	 * way a token can be presented, and a list holding both an HS and an RS algorithm lets a
	 * caller choose which of your keys to be checked against.
	 * @param mixed $value the algorithms, as an array or a comma separated list.
	 * @throws \Prado\Exceptions\TConfigurationException when the list is empty or names an
	 *   algorithm this class does not implement -- including `none`, which is not an
	 *   algorithm but the absence of one.
	 */
	public function setAlgorithms($value): void
	{
		$algorithms = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$algorithms = array_values(array_filter(array_map(
			static fn ($algorithm) => strtoupper(trim((string) $algorithm)),
			$algorithms
		), static fn ($algorithm) => $algorithm !== ''));

		if ($algorithms === []) {
			throw new TConfigurationException('webhooks_algorithms_required', static::class);
		}
		foreach ($algorithms as $algorithm) {
			if (!isset(self::ALGORITHMS[$algorithm])) {
				throw new TConfigurationException('webhooks_algorithm_unsupported', $algorithm, static::class);
			}
		}
		$this->_algorithms = $algorithms;
	}

	/**
	 * @return null|string the issuer a token must name, or null when it is not checked.
	 */
	public function getIssuer(): ?string
	{
		return $this->_issuer;
	}

	/**
	 * @param mixed $value the expected `iss`, or an empty value not to check it.
	 */
	public function setIssuer($value): void
	{
		$issuer = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_issuer = $issuer === '' ? null : $issuer;
	}

	/**
	 * @return null|string the audience a token must name, or null when it is not checked.
	 */
	public function getAudience(): ?string
	{
		return $this->_audience;
	}

	/**
	 * Sets the expected `aud`. Worth setting wherever the provider offers it: without it a
	 * token the same provider minted for a different customer is a valid token here.
	 * @param mixed $value the expected audience, or an empty value not to check it.
	 */
	public function setAudience($value): void
	{
		$audience = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_audience = $audience === '' ? null : $audience;
	}

	/**
	 * @return int the clock skew allowed on `exp` and `nbf`, in seconds. Defaults to
	 *   {@see DEFAULT_LEEWAY}.
	 */
	public function getLeeway(): int
	{
		return $this->_leeway;
	}

	/**
	 * @param mixed $value the leeway in seconds.
	 */
	public function setLeeway($value): void
	{
		$this->_leeway = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return null|string the claim holding a digest of the body, or null.
	 */
	public function getBodyHashClaim(): ?string
	{
		return $this->_bodyHashClaim;
	}

	/**
	 * Names the claim that ties the token to this delivery's body. Without one, a captured
	 * token verifies against any body at all until it expires.
	 * @param mixed $value the claim name, or an empty value for none.
	 */
	public function setBodyHashClaim($value): void
	{
		$claim = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_bodyHashClaim = $claim === '' ? null : $claim;
	}

	/**
	 * @return int how long a token this scheme mints is valid, in seconds. Defaults to 300.
	 */
	public function getLifetime(): int
	{
		return $this->_lifetime;
	}

	/**
	 * @param mixed $value the token lifetime in seconds.
	 */
	public function setLifetime($value): void
	{
		$this->_lifetime = max(1, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return bool whether a token carrying no `exp` is refused. Defaults to false, which
	 *   honors `exp` when present and accepts a token without one.
	 * @since 0.2.0
	 */
	public function getRequireExpiry(): bool
	{
		return $this->_requireExpiry;
	}

	/**
	 * Requires every token to carry an `exp`. Without one a captured token is good for ever,
	 * so turn this on for any provider that issues expiring tokens -- which is nearly all of
	 * them; it is off by default only so that a provider which does not is not refused
	 * outright on upgrade.
	 * @param mixed $value whether to refuse a token without `exp`.
	 * @since 0.2.0
	 */
	public function setRequireExpiry($value): void
	{
		$this->_requireExpiry = TPropertyValue::ensureBoolean($value);
	}
}
