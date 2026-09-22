<?php

/**
 * THttpMessageWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\TPropertyValue;

/**
 * THttpMessageWebhookSignature class.
 *
 * HTTP Message Signatures, RFC 9421. Unlike every other scheme here, the message says what
 * it signed: a `Signature-Input` header lists the components covered, and the signature is
 * computed over a base assembled from exactly those.
 *
 * ```
 * Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
 * Signature-Input: sig1=("@method" "@target-uri" "content-digest");created=1618884473;keyid="prado"
 * Signature: sig1=:wqJ3s...:
 * ```
 *
 * ```xml
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\THttpMessageWebhookSignature"
 *		Secret="..." Algorithms="hmac-sha256" KeyId="prado"
 *		RequiredComponents="@method, @target-uri, content-digest" />
 * ```
 *
 * **A signature that says what it covers is worth only what it covers.** A message is free
 * to sign nothing but `@method` and present a perfectly valid signature, so
 * {@see setRequiredComponents RequiredComponents} is the application's own list of what a
 * signature must include before it counts -- and it is the whole security of the scheme.
 * It defaults to the method, the full target URI, and the content digest, which together
 * bind a signature to one request to one URL with one body.
 *
 * `alg` in the message is read but never trusted: it has to appear in
 * {@see setAlgorithms Algorithms}. `created` is checked against {@see setMaxAge MaxAge},
 * `expires` against the clock, and {@see setKeyId KeyId} against the key this object holds.
 *
 * Derived components are supported as `@method`, `@target-uri`, `@authority`, `@scheme`,
 * `@request-target`, `@path`, and `@query`; anything else in the list is a header.
 *
 * ## Algorithms
 *
 * | Name | Key |
 * | --- | --- |
 * | `hmac-sha256`, `hmac-sha512` | {@see TWebhookSecretTrait::setSecret Secret} |
 * | `rsa-v1_5-sha256`, `rsa-v1_5-sha512` | an RSA {@see setPublicKey PublicKey} |
 * | `rsa-pss-sha512` | the same RSA key; see {@see TWebhookRsaPssTrait} for how the padding is reached |
 * | `ecdsa-p256-sha256`, `ecdsa-p384-sha384` | an EC PublicKey on that curve |
 * | `ed25519` | the raw 32-byte key, base64, and ext-sodium loaded |
 *
 * `rsa-pss-sha512` is the algorithm the RFC recommends. PHP's {@see openssl_verify} takes no
 * padding argument, so the key is rewritten as an `id-RSASSA-PSS` key -- carrying SHA-512,
 * MGF1-SHA-512 and the RFC's 64-byte salt -- and OpenSSL pads accordingly. An ordinary RSA
 * key from the provider is all that has to be configured.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class THttpMessageWebhookSignature extends TWebhookSignature implements IWebhookVerifier, IWebhookSigner
{
	use TWebhookEcdsaTrait;
	use TWebhookKeyTrait;
	use TWebhookRsaPssTrait;
	use TWebhookSecretTrait;

	/** @var string the header listing what each signature covers. */
	public const INPUT_HEADER = 'Signature-Input';

	/** @var string the header carrying the signatures. */
	public const SIGNATURE_HEADER = 'Signature';

	/** @var string the header carrying a digest of the body. */
	public const DIGEST_HEADER = 'Content-Digest';

	/** @var string[] the components a signature must cover unless told otherwise. */
	public const DEFAULT_REQUIRED_COMPONENTS = ['@method', '@target-uri', 'content-digest'];

	/** @var array<string, array{type: string, digest?: string, size?: int, salt?: int}> what each algorithm needs. */
	public const ALGORITHMS = [
		'hmac-sha256' => ['type' => 'hmac', 'digest' => 'sha256'],
		'hmac-sha512' => ['type' => 'hmac', 'digest' => 'sha512'],
		'rsa-v1_5-sha256' => ['type' => 'rsa', 'digest' => 'sha256'],
		'rsa-v1_5-sha512' => ['type' => 'rsa', 'digest' => 'sha512'],
		// The salt length is fixed by RFC 9421 rather than configurable.
		'rsa-pss-sha512' => ['type' => 'pss', 'digest' => 'sha512', 'salt' => 64],
		'ecdsa-p256-sha256' => ['type' => 'ecdsa', 'digest' => 'sha256', 'size' => 32],
		'ecdsa-p384-sha384' => ['type' => 'ecdsa', 'digest' => 'sha384', 'size' => 48],
		'ed25519' => ['type' => 'ed25519'],
	];

	/** @var array<string, string> the digest names RFC 9530 uses, and their PHP algorithms. */
	public const DIGEST_ALGORITHMS = ['sha-256' => 'sha256', 'sha-512' => 'sha512'];

	/** @var string the public key, as PEM or a path to it; base64 raw bytes for ed25519 */
	private string $_publicKey = '';

	/** @var string the private key, for signing */
	private string $_privateKey = '';

	/** @var string[] the algorithms a signature may declare */
	private array $_algorithms = ['hmac-sha256'];

	/** @var string[] the components a signature must cover */
	private array $_requiredComponents = self::DEFAULT_REQUIRED_COMPONENTS;

	/** @var null|string the one label to read, or null to try each */
	private ?string $_label = null;

	/** @var null|string the key identifier a signature must name */
	private ?string $_keyId = null;

	/** @var int how old `created` may be, in seconds; 0 accepts any */
	private int $_maxAge = 300;

	/** @var string the RFC 9530 digest name used when signing */
	private string $_digestAlgorithm = 'sha-256';

	/**
	 * Verifies a request against its own `Signature-Input`.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when no key is configured for an
	 *   allowed algorithm.
	 * @return bool whether a signature covers everything required and verifies.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		$inputs = $this->parseDictionary((string) $request->getHeader(self::INPUT_HEADER));
		$signatures = $this->parseDictionary((string) $request->getHeader(self::SIGNATURE_HEADER));
		if ($inputs === [] || $signatures === []) {
			return false;
		}

		$verified = false;
		foreach ($inputs as $label => $input) {
			if (($this->_label !== null && $label !== $this->_label) || !isset($signatures[$label])) {
				continue;
			}
			$verified = $this->verifyLabel($request, $input, $signatures[$label]) || $verified;
		}

		return $verified;
	}

	/**
	 * Verifies one labelled signature.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param string $input that label's `Signature-Input` value.
	 * @param string $signature that label's `Signature` value.
	 * @throws \Prado\Exceptions\TConfigurationException when no key is configured.
	 * @return bool whether it covers what is required and verifies.
	 */
	protected function verifyLabel(TWebhookRequest $request, string $input, string $signature): bool
	{
		[$components, $parameters] = $this->parseInput($input);
		if ($components === null) {
			return false;
		}
		if (!$this->coversWhatIsRequired($components)) {
			// The message chose what to sign; this is where the application gets a say.
			return false;
		}
		if (!$this->parametersHold($parameters)) {
			return false;
		}

		$algorithm = $this->resolveAlgorithm($parameters);
		if ($algorithm === null) {
			return false;
		}
		if (in_array('content-digest', $components, true) && !$this->contentDigestHolds($request)) {
			return false;
		}

		$base = $this->signatureBase($request, $components, $input);
		if ($base === null) {
			return false;
		}
		$raw = $this->decodeByteSequence($signature);

		return $raw !== null && $this->verifyBase($base, $raw, $algorithm);
	}

	/**
	 * Signs an outbound request.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request about to be made.
	 * @throws \Prado\Exceptions\TConfigurationException when the components cannot be built,
	 *   or no key is configured for the algorithm.
	 * @return array<string, string> the `Signature-Input` and `Signature` headers, and
	 *   `Content-Digest` when the components cover it.
	 */
	public function sign(TWebhookRequest $request): array
	{
		$algorithm = $this->_algorithms[0] ?? '';
		if (!isset(self::ALGORITHMS[$algorithm])) {
			throw new TConfigurationException('webhooks_algorithm_unsupported', $algorithm, static::class);
		}

		$label = $this->_label ?? 'sig1';
		$components = $this->_requiredComponents;
		$headers = [];
		if (in_array('content-digest', $components, true)) {
			$headers[self::DIGEST_HEADER] = $this->contentDigest($request);
			$request = $request->withHeaders(array_merge($request->getHeaders(), $headers));
		}

		$input = '(' . implode(' ', array_map(static fn ($c) => '"' . $c . '"', $components)) . ')'
			. ';created=' . time()
			. ($this->_keyId === null ? '' : ';keyid="' . $this->_keyId . '"')
			. ';alg="' . $algorithm . '"';

		$base = $this->signatureBase($request, $components, $input);
		if ($base === null) {
			throw new TConfigurationException('webhooks_component_missing', implode(', ', $components), static::class);
		}

		return $headers + [
			self::INPUT_HEADER => $label . '=' . $input,
			self::SIGNATURE_HEADER => $label . '=:' . base64_encode($this->signBase($base, $algorithm)) . ':',
		];
	}

	// ── The signature base ─────────────────────────────────────────────────────

	/**
	 * Assembles the bytes a signature is over: one line per covered component, then the
	 * signature parameters themselves, so the list cannot be edited without breaking it.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param string[] $components the covered components, in the order given.
	 * @param string $input the raw `Signature-Input` value for this label.
	 * @return null|string the base, or null when a covered component is not in the request.
	 */
	protected function signatureBase(TWebhookRequest $request, array $components, string $input): ?string
	{
		$lines = [];
		foreach ($components as $component) {
			$value = $this->componentValue($request, $component);
			if ($value === null) {
				return null;
			}
			$lines[] = '"' . $component . '": ' . $value;
		}
		$lines[] = '"@signature-params": ' . trim($input);

		return implode("\n", $lines);
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param string $component the component identifier, lower case.
	 * @return null|string its value, or null when the request does not carry it.
	 */
	protected function componentValue(TWebhookRequest $request, string $component): ?string
	{
		if ($component === '' || $component[0] !== '@') {
			$value = $request->getHeader($component);

			return $value === null ? null : trim($value);
		}

		$url = $request->getUrl();
		$parts = parse_url($url) ?: [];

		return match ($component) {
			'@method' => $request->getMethod(),
			'@target-uri' => $url === '' ? null : $url,
			'@authority' => isset($parts['host'])
				? strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '')
				: null,
			'@scheme' => isset($parts['scheme']) ? strtolower($parts['scheme']) : null,
			'@path' => $parts['path'] ?? null,
			'@query' => '?' . ($parts['query'] ?? ''),
			'@request-target' => isset($parts['path'])
				? $parts['path'] . (isset($parts['query']) ? '?' . $parts['query'] : '')
				: null,
			default => null,
		};
	}

	/**
	 * @param string[] $components what the signature covers.
	 * @return bool whether it covers everything the application requires.
	 */
	protected function coversWhatIsRequired(array $components): bool
	{
		foreach ($this->_requiredComponents as $required) {
			if (!in_array($required, $components, true)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * @param array<string, string> $parameters the signature parameters.
	 * @return bool whether `created`, `expires`, and `keyid` are acceptable.
	 */
	protected function parametersHold(array $parameters): bool
	{
		$now = time();
		if (isset($parameters['expires']) && is_numeric($parameters['expires']) && $now > (int) $parameters['expires']) {
			return false;
		}
		if ($this->_maxAge > 0) {
			if (!isset($parameters['created']) || !is_numeric($parameters['created'])) {
				return false;
			}
			if (abs($now - (int) $parameters['created']) > $this->_maxAge) {
				return false;
			}
		}
		if ($this->_keyId !== null && ($parameters['keyid'] ?? null) !== $this->_keyId) {
			return false;
		}

		return true;
	}

	/**
	 * @param array<string, string> $parameters the signature parameters.
	 * @return null|string the algorithm to verify with, or null when it is not allowed.
	 */
	protected function resolveAlgorithm(array $parameters): ?string
	{
		// The message may name one, but only the application's list decides.
		$declared = $parameters['alg'] ?? null;
		if ($declared !== null) {
			return in_array($declared, $this->_algorithms, true) && isset(self::ALGORITHMS[$declared])
				? $declared
				: null;
		}
		$algorithm = $this->_algorithms[0] ?? '';

		return isset(self::ALGORITHMS[$algorithm]) && count($this->_algorithms) === 1 ? $algorithm : null;
	}

	// ── Content-Digest ─────────────────────────────────────────────────────────

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return string the `Content-Digest` value for this body.
	 */
	protected function contentDigest(TWebhookRequest $request): string
	{
		$algorithm = self::DIGEST_ALGORITHMS[$this->_digestAlgorithm];

		return $this->_digestAlgorithm . '=:' . base64_encode(hash($algorithm, $request->getBody(), true)) . ':';
	}

	/**
	 * Whether the `Content-Digest` header matches the body.
	 *
	 * Covering `content-digest` in the signature binds the signature to the header; this is
	 * what binds the header to the bytes. Without both, a signed digest of some other body
	 * would sail through.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return bool whether a digest the header offers matches, and at least one was usable.
	 */
	protected function contentDigestHolds(TWebhookRequest $request): bool
	{
		$header = $request->getHeader(self::DIGEST_HEADER);
		if ($header === null) {
			return false;
		}

		$matched = false;
		foreach (explode(',', $header) as $entry) {
			$parts = explode('=', trim($entry), 2);
			if (count($parts) !== 2) {
				continue;
			}
			$name = strtolower(trim($parts[0]));
			if (!isset(self::DIGEST_ALGORITHMS[$name])) {
				continue;
			}
			$raw = $this->decodeByteSequence($parts[1]);
			if ($raw === null) {
				return false;
			}
			if (!hash_equals(hash(self::DIGEST_ALGORITHMS[$name], $request->getBody(), true), $raw)) {
				return false;
			}
			$matched = true;
		}

		return $matched;
	}

	// ── Structured fields ──────────────────────────────────────────────────────

	/**
	 * Splits a dictionary header into its members, at the commas that are not inside a list
	 * or a quoted string.
	 * @param string $header the header value.
	 * @return array<string, string> label => value.
	 */
	protected function parseDictionary(string $header): array
	{
		if (trim($header) === '') {
			return [];
		}

		$members = [];
		$depth = 0;
		$quoted = false;
		$current = '';
		foreach (str_split($header) as $character) {
			if ($character === '"') {
				$quoted = !$quoted;
			} elseif (!$quoted && $character === '(') {
				$depth++;
			} elseif (!$quoted && $character === ')') {
				$depth--;
			} elseif (!$quoted && $depth === 0 && $character === ',') {
				$members[] = $current;
				$current = '';
				continue;
			}
			$current .= $character;
		}
		$members[] = $current;

		$dictionary = [];
		foreach ($members as $member) {
			$parts = explode('=', trim($member), 2);
			if (count($parts) === 2 && trim($parts[0]) !== '') {
				$dictionary[trim($parts[0])] = trim($parts[1]);
			}
		}

		return $dictionary;
	}

	/**
	 * Splits one `Signature-Input` value into its component list and its parameters.
	 * @param string $input the value, `("a" "b");created=1;keyid="k"`.
	 * @return array{0: null|string[], 1: array<string, string>} the components, or null when
	 *   the value has no list, and the parameters.
	 */
	protected function parseInput(string $input): array
	{
		if (!preg_match('/^\(([^)]*)\)(.*)$/s', trim($input), $match)) {
			return [null, []];
		}

		$components = [];
		if (preg_match_all('/"([^"]*)"/', $match[1], $found)) {
			$components = array_map('strtolower', $found[1]);
		}

		$parameters = [];
		foreach (explode(';', $match[2]) as $parameter) {
			$parts = explode('=', trim($parameter), 2);
			if (count($parts) === 2 && trim($parts[0]) !== '') {
				$parameters[strtolower(trim($parts[0]))] = trim(trim($parts[1]), '"');
			}
		}

		return [$components, $parameters];
	}

	/**
	 * @param string $value a structured field byte sequence, `:base64:`.
	 * @return null|string the bytes, or null when it is not one.
	 */
	protected function decodeByteSequence(string $value): ?string
	{
		$value = trim($value);
		if (strlen($value) < 2 || $value[0] !== ':' || !str_ends_with($value, ':')) {
			return null;
		}
		$raw = base64_decode(substr($value, 1, -1), true);

		return $raw === false ? null : $raw;
	}

	// ── The cryptography ───────────────────────────────────────────────────────

	/**
	 * @param string $base the signature base.
	 * @param string $signature the raw signature bytes.
	 * @param string $algorithm the algorithm, already allow listed.
	 * @throws \Prado\Exceptions\TConfigurationException when no key is configured for it.
	 * @return bool whether the signature verifies.
	 */
	protected function verifyBase(string $base, string $signature, string $algorithm): bool
	{
		$specification = self::ALGORITHMS[$algorithm];

		if ($specification['type'] === 'hmac') {
			return hash_equals(hash_hmac($specification['digest'], $base, $this->getSecretKey(), true), $signature);
		}
		if ($specification['type'] === 'ed25519') {
			$key = $this->rawKey($this->_publicKey, 'PublicKey', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);

			return strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
				&& sodium_crypto_sign_verify_detached($signature, $base, $key);
		}

		if ($this->_publicKey === '') {
			throw new TConfigurationException('webhooks_public_key_required', static::class);
		}
		if ($specification['type'] === 'pss') {
			$key = $this->pssKey($this->readKeyMaterial($this->_publicKey), $specification['digest'], $specification['salt']);
			if ($key === false) {
				throw new TConfigurationException('webhooks_pss_key_invalid', 'PublicKey', static::class);
			}

			return openssl_verify($base, $signature, $key, $specification['digest']) === 1;
		}
		$key = openssl_pkey_get_public($this->readKeyMaterial($this->_publicKey));
		if ($key === false) {
			throw new TConfigurationException('webhooks_key_invalid', 'PublicKey', static::class);
		}
		if ($specification['type'] === 'ecdsa') {
			$signature = $this->derFromRaw($signature, $specification['size']);
			if ($signature === null) {
				return false;
			}
		}

		return openssl_verify($base, $signature, $key, $specification['digest']) === 1;
	}

	/**
	 * @param string $base the signature base.
	 * @param string $algorithm the algorithm to sign with.
	 * @throws \Prado\Exceptions\TConfigurationException when no key is configured, or the
	 *   signing fails.
	 * @return string the raw signature bytes.
	 */
	protected function signBase(string $base, string $algorithm): string
	{
		$specification = self::ALGORITHMS[$algorithm];

		if ($specification['type'] === 'hmac') {
			return hash_hmac($specification['digest'], $base, $this->getSecretKey(), true);
		}
		if ($specification['type'] === 'ed25519') {
			return sodium_crypto_sign_detached(
				$base,
				$this->rawKey($this->_privateKey, 'PrivateKey', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES)
			);
		}

		if ($this->_privateKey === '') {
			throw new TConfigurationException('webhooks_private_key_required', static::class);
		}
		if ($specification['type'] === 'pss') {
			$key = $this->pssKey($this->readKeyMaterial($this->_privateKey), $specification['digest'], $specification['salt'], true);
			if ($key === false) {
				throw new TConfigurationException('webhooks_pss_key_invalid', 'PrivateKey', static::class);
			}
			$signature = '';
			if (!openssl_sign($base, $signature, $key, $specification['digest'])) {
				throw new TConfigurationException('webhooks_signing_failed', static::class);
			}

			return $signature;
		}
		$key = openssl_pkey_get_private($this->readKeyMaterial($this->_privateKey));
		if ($key === false) {
			throw new TConfigurationException('webhooks_key_invalid', 'PrivateKey', static::class);
		}
		$signature = '';
		if (!openssl_sign($base, $signature, $key, $specification['digest'])) {
			throw new TConfigurationException('webhooks_signing_failed', static::class);
		}
		if ($specification['type'] === 'ecdsa') {
			$signature = $this->rawFromDer($signature, $specification['size']);
			if ($signature === null) {
				throw new TConfigurationException('webhooks_signing_failed', static::class);
			}
		}

		return $signature;
	}

	/**
	 * Reads an Ed25519 key, which sodium takes as raw bytes rather than as PEM.
	 * @param string $key the configured value, base64.
	 * @param string $property the property being read, for the error message.
	 * @param int $length how many bytes sodium expects.
	 * @throws \Prado\Exceptions\TConfigurationException when it is missing, will not decode,
	 *   is the wrong length, or ext-sodium is not loaded.
	 * @return string the raw key.
	 */
	protected function rawKey(string $key, string $property, int $length): string
	{
		if (!function_exists('sodium_crypto_sign_verify_detached')) {
			throw new TConfigurationException('webhooks_algorithm_unsupported', 'ed25519', static::class);
		}
		if ($key === '') {
			throw new TConfigurationException(
				$property === 'PublicKey' ? 'webhooks_public_key_required' : 'webhooks_private_key_required',
				static::class
			);
		}
		$raw = base64_decode($key, true);
		// Checked here rather than left to sodium, which raises a SodiumException that would
		// reach the provider as an error page.
		if ($raw === false || strlen($raw) !== $length) {
			throw new TConfigurationException('webhooks_key_invalid', $property, static::class);
		}

		return $raw;
	}

	// ── Configuration ──────────────────────────────────────────────────────────

	/**
	 * @return string the public key, as configured.
	 */
	public function getPublicKey(): string
	{
		return $this->_publicKey;
	}

	/**
	 * @param mixed $value the public key: PEM text, a path to a file holding it, or the raw
	 *   key in base64 for `ed25519`.
	 */
	public function setPublicKey($value): void
	{
		$this->_publicKey = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the private key, as configured.
	 */
	public function getPrivateKey(): string
	{
		return $this->_privateKey;
	}

	/**
	 * @param mixed $value the private key, in the same forms as {@see setPublicKey}.
	 */
	public function setPrivateKey($value): void
	{
		$this->_privateKey = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string[] the algorithms a signature may declare. Defaults to `['hmac-sha256']`.
	 */
	public function getAlgorithms(): array
	{
		return $this->_algorithms;
	}

	/**
	 * Sets the algorithms a signature may declare, and the first of them is what {@see sign}
	 * uses. A message that names none of them is refused; a message that names no algorithm
	 * at all is accepted only when this list holds exactly one, because otherwise there is
	 * no telling which was meant.
	 * @param mixed $value the algorithms, as an array or a comma separated list.
	 * @throws \Prado\Exceptions\TConfigurationException when the list is empty or names an
	 *   algorithm this class does not implement.
	 */
	public function setAlgorithms($value): void
	{
		$algorithms = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$algorithms = array_values(array_filter(array_map(
			static fn ($algorithm) => strtolower(trim((string) $algorithm)),
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
	 * @return string[] the components a signature must cover. Defaults to
	 *   {@see DEFAULT_REQUIRED_COMPONENTS}.
	 */
	public function getRequiredComponents(): array
	{
		return $this->_requiredComponents;
	}

	/**
	 * Sets what a signature has to cover before it counts, and what {@see sign} covers.
	 *
	 * This is the scheme's security: a message decides what it signs, and a signature over
	 * `@method` alone is as valid as any other. Require at least enough to pin the request
	 * to one URL and one body.
	 *
	 * @param mixed $value the components, as an array or a comma separated list. Header
	 *   names are lower cased; derived components start with `@`.
	 * @throws \Prado\Exceptions\TConfigurationException when the list is empty.
	 */
	public function setRequiredComponents($value): void
	{
		$components = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$components = array_values(array_filter(array_map(
			static fn ($component) => strtolower(trim((string) $component, " \t\n\r\0\x0B\"")),
			$components
		), static fn ($component) => $component !== ''));

		if ($components === []) {
			throw new TConfigurationException('webhooks_components_required', static::class);
		}
		$this->_requiredComponents = $components;
	}

	/**
	 * @return null|string the one label read, or null when every label is tried.
	 */
	public function getLabel(): ?string
	{
		return $this->_label;
	}

	/**
	 * @param mixed $value the label, or an empty value to try each one the message carries.
	 */
	public function setLabel($value): void
	{
		$label = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_label = $label === '' ? null : $label;
	}

	/**
	 * @return null|string the key identifier a signature must name, or null.
	 */
	public function getKeyId(): ?string
	{
		return $this->_keyId;
	}

	/**
	 * @param mixed $value the expected `keyid`, or an empty value not to check it. Worth
	 *   setting: it is what stops a signature made for another of the provider's keys, or
	 *   another of its customers, from being checked against this one.
	 */
	public function setKeyId($value): void
	{
		$keyId = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_keyId = $keyId === '' ? null : $keyId;
	}

	/**
	 * @return int how old `created` may be, in seconds. Defaults to 300.
	 */
	public function getMaxAge(): int
	{
		return $this->_maxAge;
	}

	/**
	 * @param mixed $value the age limit in seconds; 0 or less accepts any, and stops
	 *   requiring `created` at all.
	 */
	public function setMaxAge($value): void
	{
		$this->_maxAge = TPropertyValue::ensureInteger($value);
	}

	/**
	 * @return string the RFC 9530 digest name used when signing. Defaults to `sha-256`.
	 */
	public function getDigestAlgorithm(): string
	{
		return $this->_digestAlgorithm;
	}

	/**
	 * @param mixed $value `sha-256` or `sha-512`.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is neither.
	 */
	public function setDigestAlgorithm($value): void
	{
		$algorithm = strtolower(trim(TPropertyValue::ensureString($value)));
		if (!isset(self::DIGEST_ALGORITHMS[$algorithm])) {
			throw new TConfigurationException('webhooks_algorithm_unsupported', $algorithm, static::class);
		}
		$this->_digestAlgorithm = $algorithm;
	}
}
