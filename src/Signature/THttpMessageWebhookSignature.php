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
 * `@request-target`, `@path`, `@query`, and `@query-param;name="..."`; anything else in the
 * list is a header, and a repeated header contributes every instance joined by `, ` as RFC
 * 9421 section 2.1 says. `@authority` is lower case and drops a default port; `@path` of a
 * URL with no path is `/`.
 *
 * Component parameters are parsed as RFC 8941 inner-list item parameters, so nothing
 * attached to a component leaks into the component list or the signature parameters, and
 * a duplicate component identifier refuses the signature. Of the parameters RFC 9421
 * defines, only `name` on `@query-param` is implemented; a signature covering a component
 * carrying any other -- `sf`, `bs`, `key`, `req`, `tr` -- is refused rather than checked
 * against a base this class cannot build correctly.
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

	/**
	 * The kind of public key each algorithm type verifies with, as {@see publicKeyKind}
	 * reports it.
	 * @var array<string, string>
	 */
	protected const KEY_KINDS = [
		'rsa' => 'rsa',
		'pss' => 'rsa',
		'ecdsa' => 'ec',
		'ed25519' => 'ed25519',
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
	 * @throws \Prado\Exceptions\TConfigurationException when no allowed algorithm has a key
	 *   configured, whatever the request carries, or the key for the declared one will
	 *   not parse.
	 * @return bool whether a signature covers everything required and verifies.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		// Before the request is looked at: a verifier with no key for any algorithm it
		// allows is misconfigured whatever arrives, and must not quietly refuse everything.
		$this->requireSomeKey();

		$inputs = $this->parseDictionary((string) $this->headerValue($request, self::INPUT_HEADER));
		$signatures = $this->parseDictionary((string) $this->headerValue($request, self::SIGNATURE_HEADER));
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
		[$components, $typed] = $this->parseInputTyped($input);
		if ($components === null) {
			return false;
		}
		foreach (['created', 'expires'] as $moment) {
			// RFC 9421 section 2.3: both are Integers. A quoted "123" is a string that
			// happens to look like one, and is refused rather than read as a number.
			if (isset($typed[$moment]) && $typed[$moment]['type'] !== 'integer') {
				return false;
			}
		}
		$parameters = $this->flattenParameters($typed);
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

		$input = '(' . implode(' ', array_map(fn ($c) => $this->serializeComponent($c), $components)) . ')'
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
			$lines[] = $this->serializeComponent($component) . ': ' . $value;
		}
		$lines[] = '"@signature-params": ' . trim($input);

		return implode("\n", $lines);
	}

	/**
	 * Returns a component's value as the signature base carries it.
	 *
	 * A component is its lower case name, optionally followed by RFC 8941 parameters in the
	 * canonical form {@see parseInput} produces, such as `@query-param;name="id"`. The only
	 * parameter implemented is `name` on `@query-param`; a component carrying any other
	 * parameter has no value here, so a signature covering it is refused rather than
	 * checked against a base built wrong.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param string $component the component identifier, lower case, parameters included.
	 * @return null|string its value, or null when the request does not carry it or the
	 *   component is one this class cannot evaluate.
	 */
	protected function componentValue(TWebhookRequest $request, string $component): ?string
	{
		$split = $this->splitComponent($component);
		if ($split === null) {
			return null;
		}
		[$name, $parameters] = $split;

		if ($parameters !== []) {
			if ($name === '@query-param' && array_keys($parameters) === ['name'] && $parameters['name']['type'] === 'string') {
				return $this->queryParameterValue($request, (string) $parameters['name']['value']);
			}

			// `sf`, `bs`, `key`, `req`, `tr`, or anything else: not implemented, so fail closed.
			return null;
		}

		if ($name === '' || $name[0] !== '@') {
			return $this->headerValue($request, $name);
		}

		$url = $request->getUrl();
		$parts = parse_url($url) ?: [];

		return match ($name) {
			'@method' => $request->getMethod(),
			'@target-uri' => $url === '' ? null : $url,
			'@authority' => isset($parts['host']) ? $this->authority($parts) : null,
			'@scheme' => isset($parts['scheme']) ? strtolower($parts['scheme']) : null,
			'@path' => isset($parts['host']) || isset($parts['path']) ? ($parts['path'] ?? '/') : null,
			'@query' => '?' . ($parts['query'] ?? ''),
			'@request-target' => isset($parts['host']) || isset($parts['path'])
				? ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '')
				: null,
			default => null,
		};
	}

	/**
	 * The `@authority` component: the host in lower case, and the port only when it is not
	 * the scheme's default -- `example.com:443` and `example.com` are one authority, and a
	 * signer that writes one must verify against a receiver that sees the other.
	 * @param array<string, int|string> $parts the URL, as {@see parse_url} splits it.
	 * @return string the authority.
	 */
	protected function authority(array $parts): string
	{
		$host = strtolower((string) $parts['host']);
		if (!isset($parts['port'])) {
			return $host;
		}
		$port = (int) $parts['port'];
		$default = match (strtolower((string) ($parts['scheme'] ?? ''))) {
			'https' => 443,
			'http' => 80,
			default => null,
		};

		return $port === $default ? $host : $host . ':' . $port;
	}

	/**
	 * Gathers every instance of a header, as RFC 9421 section 2.1 has the base carry it:
	 * each value with its leading and trailing whitespace stripped and any obsolete line
	 * folding replaced by one space, then all of them joined by `, `. A request that
	 * carried the header twice signs both; reading only the first would let the second be
	 * rewritten under a valid signature.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param string $name the header name, in any case.
	 * @return null|string the combined value, or null when the request carries no such header.
	 * @since 0.1.0
	 */
	protected function headerValue(TWebhookRequest $request, string $name): ?string
	{
		$values = [];
		foreach ($request->getHeaders() as $key => $value) {
			if (strcasecmp((string) $key, $name) !== 0) {
				continue;
			}
			foreach (is_array($value) ? $value : [$value] as $instance) {
				if ($instance === null) {
					continue;
				}
				$values[] = trim((string) preg_replace('/\r?\n[ \t]*/', ' ', (string) $instance));
			}
		}

		return $values === [] ? null : implode(', ', $values);
	}

	/**
	 * The `@query-param` component, RFC 9421 section 2.2.8: one query parameter, its name
	 * and value percent-decoded and then re-encoded with the strict RFC 3986 set, so that
	 * the two ends agree whatever spelling the URL used. A parameter that occurs more than
	 * once cannot be covered this way and has no value here.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param string $name the parameter name, as the component identifier carries it.
	 * @return null|string the re-encoded value, or null when the URL does not carry exactly
	 *   one parameter of that name.
	 * @since 0.1.0
	 */
	protected function queryParameterValue(TWebhookRequest $request, string $name): ?string
	{
		$query = parse_url($request->getUrl(), PHP_URL_QUERY);
		if (!is_string($query) || $query === '') {
			return null;
		}
		$wanted = rawurldecode($name);
		$found = null;
		foreach (explode('&', $query) as $pair) {
			if ($pair === '') {
				continue;
			}
			[$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
			if (rawurldecode($key) !== $wanted) {
				continue;
			}
			if ($found !== null) {
				return null;
			}
			$found = rawurlencode(rawurldecode($value));
		}

		return $found;
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
		// An `expires` that is present but not a number refuses the signature: it cannot be
		// honored, and overlooking it would let a signature declare itself unexpiring.
		if (isset($parameters['expires']) && (!is_numeric($parameters['expires']) || $now > (int) $parameters['expires'])) {
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
		$escaped = false;
		$current = '';
		foreach (str_split($header) as $character) {
			if ($quoted) {
				// Inside a string only an unescaped quote ends it; `\"` is a quote character.
				if ($escaped) {
					$escaped = false;
				} elseif ($character === '\\') {
					$escaped = true;
				} elseif ($character === '"') {
					$quoted = false;
				}
			} elseif ($character === '"') {
				$quoted = true;
			} elseif ($character === '(') {
				$depth++;
			} elseif ($character === ')') {
				$depth--;
			} elseif ($depth === 0 && $character === ',') {
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
	 *
	 * The value is an RFC 8941 inner list: each component is a quoted string, possibly
	 * followed by parameters of its own (`"@query-param";name="id"`), and the list is
	 * followed by the signature parameters (`;created=1;keyid="k"`). Each is parsed as
	 * structured-field syntax rather than split on punctuation, so a parameter attached to a
	 * component stays with it, and a quoted value holding `;` or `\"` is one value. Every
	 * component comes back in one canonical spelling -- lower case name, parameters
	 * re-serialized -- which is what lets a duplicate be recognized and refused.
	 *
	 * @param string $input the value, `("a" "b");created=1;keyid="k"`.
	 * @return array{0: null|string[], 1: array<string, string>} the components, or null when
	 *   the value is not a well-formed list or names a component twice, and the parameters
	 *   as text, a string unquoted and a boolean as `?1` or `?0`.
	 */
	protected function parseInput(string $input): array
	{
		[$components, $typed] = $this->parseInputTyped($input);

		return [$components, $this->flattenParameters($typed)];
	}

	/**
	 * Flattens typed parameters to the text form {@see parseInput} returns.
	 * @param array<string, array{type: string, value: bool|string}> $typed the parameters.
	 * @return array<string, string> the parameters as text.
	 * @since 0.1.0
	 */
	protected function flattenParameters(array $typed): array
	{
		$flat = [];
		foreach ($typed as $key => $item) {
			$flat[$key] = $item['type'] === 'boolean' ? ($item['value'] ? '?1' : '?0') : (string) $item['value'];
		}

		return $flat;
	}

	/**
	 * {@see parseInput}, keeping each signature parameter's RFC 8941 type, so a check that
	 * needs an Integer can tell one from a string that looks like one.
	 * @param string $input the value.
	 * @return array{0: null|string[], 1: array<string, array{type: string, value: bool|string}>}
	 *   the canonical components, or null, and the typed parameters.
	 * @since 0.1.0
	 */
	protected function parseInputTyped(string $input): array
	{
		$input = trim($input);
		if ($input === '' || $input[0] !== '(') {
			return [null, []];
		}

		$components = [];
		$offset = 1;
		$length = strlen($input);
		while (true) {
			while ($offset < $length && $input[$offset] === ' ') {
				$offset++;
			}
			if ($offset >= $length) {
				return [null, []];
			}
			if ($input[$offset] === ')') {
				$offset++;
				break;
			}
			$item = $this->parseBareItem($input, $offset);
			if ($item === null || $item[0]['type'] !== 'string') {
				return [null, []];
			}
			$parameters = $this->parseParameters($input, $item[1]);
			if ($parameters === null) {
				return [null, []];
			}
			$offset = $parameters[1];
			$components[] = strtolower((string) $item[0]['value']) . $this->serializeParameters($parameters[0]);
		}
		if (count($components) !== count(array_unique($components))) {
			// RFC 9421 section 2.5: the same identifier twice is an error, not a repeat.
			return [null, []];
		}

		$parameters = $this->parseParameters($input, $offset);
		if ($parameters === null || trim(substr($input, $parameters[1])) !== '') {
			return [null, []];
		}

		return [$components, $parameters[0]];
	}

	/**
	 * Reads one RFC 8941 bare item -- a string, token, integer, decimal, byte sequence, or
	 * boolean -- from $input at $offset.
	 * @param string $input the text.
	 * @param int $offset where the item starts.
	 * @return null|array{0: array{type: string, value: bool|string}, 1: int} the typed item
	 *   and where the text continues, or null when no item starts there.
	 * @since 0.1.0
	 */
	protected function parseBareItem(string $input, int $offset): ?array
	{
		$rest = substr($input, $offset);
		if ($rest === '') {
			return null;
		}
		if ($rest[0] === '"') {
			$value = '';
			$length = strlen($rest);
			for ($i = 1; $i < $length; $i++) {
				$character = $rest[$i];
				if ($character === '\\') {
					$next = $rest[$i + 1] ?? '';
					if ($next !== '"' && $next !== '\\') {
						return null;
					}
					$value .= $next;
					$i++;
				} elseif ($character === '"') {
					return [['type' => 'string', 'value' => $value], $offset + $i + 1];
				} elseif (ord($character) < 0x20 || ord($character) > 0x7e) {
					return null;
				} else {
					$value .= $character;
				}
			}

			return null;
		}
		if ($rest[0] === ':') {
			return preg_match('/^:([A-Za-z0-9+\/=]*):/', $rest, $match)
				? [['type' => 'bytes', 'value' => $match[1]], $offset + strlen($match[0])]
				: null;
		}
		if ($rest[0] === '?') {
			return preg_match('/^\?([01])/', $rest, $match)
				? [['type' => 'boolean', 'value' => $match[1] === '1'], $offset + 2]
				: null;
		}
		if (preg_match('/^-?\d+(\.\d+)?/', $rest, $match)) {
			return [['type' => isset($match[1]) ? 'decimal' : 'integer', 'value' => $match[0]], $offset + strlen($match[0])];
		}
		if (preg_match('/^[A-Za-z*][A-Za-z0-9:\/!#$%&\'*+\-.^_`|~]*/', $rest, $match)) {
			return [['type' => 'token', 'value' => $match[0]], $offset + strlen($match[0])];
		}

		return null;
	}

	/**
	 * Reads RFC 8941 parameters, `;key=value;flag`, from $input at $offset. A repeated key
	 * keeps its last value, as the specification says.
	 * @param string $input the text.
	 * @param int $offset where the parameters start; anything other than `;` there is zero
	 *   parameters, not an error.
	 * @return null|array{0: array<string, array{type: string, value: bool|string}>, 1: int}
	 *   the parameters and where the text continues, or null when one is malformed.
	 * @since 0.1.0
	 */
	protected function parseParameters(string $input, int $offset): ?array
	{
		$parameters = [];
		$length = strlen($input);
		while ($offset < $length && $input[$offset] === ';') {
			$offset++;
			while ($offset < $length && $input[$offset] === ' ') {
				$offset++;
			}
			if (!preg_match('/^[a-z*][a-z0-9_\-.*]*/', substr($input, $offset), $match)) {
				return null;
			}
			$key = $match[0];
			$offset += strlen($key);
			if ($offset < $length && $input[$offset] === '=') {
				$item = $this->parseBareItem($input, $offset + 1);
				if ($item === null) {
					return null;
				}
				$parameters[$key] = $item[0];
				$offset = $item[1];
			} else {
				$parameters[$key] = ['type' => 'boolean', 'value' => true];
			}
		}

		return [$parameters, $offset];
	}

	/**
	 * Writes parameters back in RFC 8941 serialization: `;key="value"`, `;flag`.
	 * @param array<string, array{type: string, value: bool|string}> $parameters the typed parameters.
	 * @return string the serialization, empty for none.
	 * @since 0.1.0
	 */
	protected function serializeParameters(array $parameters): string
	{
		$serialized = '';
		foreach ($parameters as $key => $item) {
			$serialized .= ';' . $key;
			if ($item['type'] === 'boolean' && $item['value'] === true) {
				continue;
			}
			$serialized .= '=' . match ($item['type']) {
				'string' => '"' . addcslashes((string) $item['value'], '\\"') . '"',
				'bytes' => ':' . $item['value'] . ':',
				'boolean' => '?0',
				default => (string) $item['value'],
			};
		}

		return $serialized;
	}

	/**
	 * Writes a component identifier as the base and `Signature-Input` carry it: the name as a
	 * quoted string, then its parameters.
	 * @param string $component the canonical component, `name` or `name;key=value`.
	 * @return string the serialization, `"name";key=value`.
	 * @since 0.1.0
	 */
	protected function serializeComponent(string $component): string
	{
		$split = $this->splitComponent($component);
		if ($split === null) {
			return '"' . addcslashes($component, '\\"') . '"';
		}

		return '"' . addcslashes($split[0], '\\"') . '"' . $this->serializeParameters($split[1]);
	}

	/**
	 * Splits a canonical component into its name and its typed parameters.
	 * @param string $component the component, `name` or `name;key=value`.
	 * @return null|array{0: string, 1: array<string, array{type: string, value: bool|string}>}
	 *   the name and parameters, or null when the parameters are malformed.
	 * @since 0.1.0
	 */
	protected function splitComponent(string $component): ?array
	{
		$at = strpos($component, ';');
		if ($at === false) {
			return [$component, []];
		}
		$parameters = $this->parseParameters($component, $at);
		if ($parameters === null || $parameters[1] !== strlen($component)) {
			return null;
		}

		return [substr($component, 0, $at), $parameters[0]];
	}

	/**
	 * Brings a configured component into the canonical spelling {@see parseInput} produces,
	 * so `"@query-param";name="id"` and `@query-param; name="id"` both compare equal to what
	 * a message says. The name is lower cased; parameter values are not, because a query
	 * parameter name is case sensitive.
	 * @param string $component the component as configured.
	 * @return string the canonical component; one whose parameters will not parse is kept
	 *   as written, lower cased, and will match nothing.
	 * @since 0.1.0
	 */
	protected function normalizeComponent(string $component): string
	{
		$component = trim($component);
		if ($component !== '' && $component[0] === '"') {
			$item = $this->parseBareItem($component, 0);
			if ($item === null || $item[0]['type'] !== 'string') {
				return strtolower($component);
			}
			$name = (string) $item[0]['value'];
			$offset = $item[1];
		} else {
			$at = strpos($component, ';');
			$name = $at === false ? $component : substr($component, 0, $at);
			$offset = $at === false ? strlen($component) : $at;
		}
		$parameters = $this->parseParameters($component, $offset);
		if ($parameters === null || trim(substr($component, $parameters[1])) !== '') {
			return strtolower($component);
		}

		return strtolower(trim($name)) . $this->serializeParameters($parameters[0]);
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
	 * Whether key material is configured for the family an algorithm belongs to.
	 * @param string $algorithm one of {@see ALGORITHMS}.
	 * @return bool whether the secret (`hmac-*`) or the public key (everything else) is set.
	 * @since 0.1.0
	 */
	protected function hasKeyFor(string $algorithm): bool
	{
		return (self::ALGORITHMS[$algorithm]['type'] ?? '') === 'hmac' ? $this->getSecret() !== '' : $this->_publicKey !== '';
	}

	/**
	 * Whether some algorithm in {@see getAlgorithms Algorithms} verifies with a key of a kind.
	 * @param string $kind a kind as {@see publicKeyKind} reports it.
	 * @return bool whether an allowed algorithm takes that kind of key.
	 * @since 0.1.0
	 */
	protected function keyKindIsAllowed(string $kind): bool
	{
		foreach ($this->_algorithms as $allowed) {
			$type = self::ALGORITHMS[$allowed]['type'];
			if ($type !== 'hmac' && self::KEY_KINDS[$type] === $kind) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Reads what kind of key {@see getPublicKey PublicKey} holds.
	 *
	 * An Ed25519 key is 32 raw bytes in base64, which no PEM decodes to; anything else is
	 * handed to OpenSSL and named by its type.
	 *
	 * @return null|string `rsa`, `ec` or `ed25519`, or null when the material is none of
	 *   them.
	 * @since 0.1.0
	 */
	protected function publicKeyKind(): ?string
	{
		$raw = base64_decode($this->_publicKey, true);
		if ($raw !== false && strlen($raw) === 32) {
			return 'ed25519';
		}
		$key = openssl_pkey_get_public($this->readKeyMaterial($this->_publicKey));
		if ($key === false) {
			return null;
		}
		$details = openssl_pkey_get_details($key);

		return match ($details['type'] ?? null) {
			OPENSSL_KEYTYPE_RSA => 'rsa',
			OPENSSL_KEYTYPE_EC => 'ec',
			default => null,
		};
	}

	/**
	 * Requires that at least one allowed algorithm has key material to verify with.
	 * @throws \Prado\Exceptions\TConfigurationException when none does.
	 * @since 0.1.0
	 */
	protected function requireSomeKey(): void
	{
		foreach ($this->_algorithms as $algorithm) {
			if ($this->hasKeyFor($algorithm)) {
				return;
			}
		}
		throw new TConfigurationException(
			(self::ALGORITHMS[$this->_algorithms[0] ?? '']['type'] ?? 'hmac') === 'hmac'
				? 'webhooks_secret_required'
				: 'webhooks_public_key_required',
			static::class
		);
	}

	/**
	 * Verifies a signature base.
	 *
	 * When the allow list mixes families -- `rsa-v1_5-sha256` alongside `hmac-sha256` --
	 * and only one family has key material, a signature declaring the other is refused
	 * rather than reported as a configuration error: the sender chose that algorithm, and a
	 * sender must not be able to choose which exception the endpoint raises. The exception
	 * is kept for the case where no allowed algorithm has any key at all.
	 *
	 * @param string $base the signature base.
	 * @param string $signature the raw signature bytes.
	 * @param string $algorithm the algorithm, already allow listed.
	 * @throws \Prado\Exceptions\TConfigurationException when no allowed algorithm has a key,
	 *   or the key for this one will not parse.
	 * @return bool whether the signature verifies.
	 */
	protected function verifyBase(string $base, string $signature, string $algorithm): bool
	{
		$specification = self::ALGORITHMS[$algorithm];

		if (!$this->hasKeyFor($algorithm)) {
			// Another allowed family is configured, so this is the sender's choice, not ours.
			$this->requireSomeKey();

			return false;
		}

		if ($specification['type'] === 'hmac') {
			return hash_equals(hash_hmac($specification['digest'], $base, $this->getSecretKey(), true), $signature);
		}
		// The key that is configured is one kind; the message may declare any algorithm in
		// the list. When the key serves another allowed algorithm, declaring this one is the
		// sender's choice, and refused; a key no allowed algorithm could use is a
		// configuration error whichever the sender declared.
		$kind = $this->publicKeyKind();
		if ($kind !== self::KEY_KINDS[$specification['type']]) {
			if ($kind !== null && $this->keyKindIsAllowed($kind)) {
				return false;
			}
			throw new TConfigurationException(
				$specification['type'] === 'pss' ? 'webhooks_pss_key_invalid' : 'webhooks_key_invalid',
				'PublicKey',
				static::class
			);
		}
		if ($specification['type'] === 'ed25519') {
			$key = $this->rawKey($this->_publicKey, 'PublicKey', 32);

			return strlen($signature) === 64
				&& sodium_crypto_sign_verify_detached($signature, $base, $key);
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
				$this->rawKey($this->_privateKey, 'PrivateKey', 64)
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
			// Refused here rather than on the first message declaring it, which would let
			// a sender pick the error page.
			if ($algorithm === 'ed25519' && !function_exists('sodium_crypto_sign_verify_detached')) {
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
	 *   names are lower cased; derived components start with `@`; a component may carry
	 *   RFC 8941 parameters, as in `"@query-param";name="id"`.
	 * @throws \Prado\Exceptions\TConfigurationException when the list is empty.
	 */
	public function setRequiredComponents($value): void
	{
		$components = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$components = array_values(array_filter(array_map(
			fn ($component) => $this->normalizeComponent((string) $component),
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
