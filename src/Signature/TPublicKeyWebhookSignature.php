<?php

/**
 * TPublicKeyWebhookSignature class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

use Belisoful\Prado\Web\Webhooks\TWebhookPadding;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Caching\ICache;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\IO\HttpClient\THttpClient;
use Prado\IO\HttpClient\THttpClientException;
use Prado\TPropertyValue;

/**
 * TPublicKeyWebhookSignature class.
 *
 * An asymmetric signature: the provider signs with a private key it keeps, and the
 * application verifies with a public key it does not have to keep secret. Providers that
 * would otherwise have to hand every customer a shared secret use this, and it is the one
 * scheme where a leaked verification credential does not let an attacker forge deliveries.
 *
 * ```xml
 * <!-- a public key or certificate the provider publishes once -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TPublicKeyWebhookSignature"
 *		PublicKey="protected/keys/provider.pem" Header="X-Signature" Encoding="base64" />
 *
 * <!-- a certificate named by the delivery itself -->
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TPublicKeyWebhookSignature"
 *		Header="X-Signature" Encoding="base64"
 *		CertificateUrlName="X-Cert-Url"
 *		CertificateUrlPattern="#^https://[a-z0-9.-]+\.example\.com/#"
 *		PayloadFormat="{header:X-Transmission-Id}|{header:X-Transmission-Time}|{const:WEBHOOK_ID}|{crc32}"
 *		Constants="WEBHOOK_ID=WH-1234" />
 * ```
 *
 * **A certificate URL taken from the request is an instruction from a stranger.** Left
 * unchecked it is a server-side request forgery, and an attacker who can make the
 * application fetch a certificate of their choosing can sign anything. So
 * {@see setCertificateUrlPattern CertificateUrlPattern} is mandatory before a URL is ever
 * fetched: no pattern, no fetch. Set it to the narrowest expression of the provider's own
 * domain that still works, keep it anchored, and remember it is matched against the URL the
 * *caller* supplied.
 *
 * Fetched certificates are cached when a cache is available, because a provider that names
 * a certificate URL names the same handful over and over. Only a body that OpenSSL reads
 * as a key is cached, and only one no larger than
 * {@see setCertificateMaxSize CertificateMaxSize}; and nothing is fetched at all until the
 * request has presented a signature, so an unsigned body cannot make the application make
 * requests.
 *
 * Signing needs {@see setPrivateKey PrivateKey}; with only a public key the scheme
 * verifies, which is the usual arrangement for an application on the receiving end.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TPublicKeyWebhookSignature extends TWebhookSignature implements IWebhookVerifier, IWebhookSigner
{
	use TWebhookKeyTrait;
	use TWebhookRsaPssTrait;

	/** @var int how long a fetched certificate is cached, in seconds. */
	public const DEFAULT_CACHE_TTL = 3600;

	/** @var int the largest certificate body accepted from a fetch, in bytes. */
	public const DEFAULT_CERTIFICATE_MAX_SIZE = 65536;

	/** @var string the public key or certificate, as PEM or a path to it */
	private string $_publicKey = '';

	/** @var string the private key, as PEM or a path to it, for signing */
	private string $_privateKey = '';

	/** @var string the digest the signature is over */
	private string $_algorithm = 'sha256';

	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookPadding how an RSA signature is padded */
	private TWebhookPadding $_padding = TWebhookPadding::Pkcs1;

	/** @var int the PSS salt length in bytes; 0 follows the digest */
	private int $_saltLength = 0;

	/** @var null|string where the request names the certificate to verify it with */
	private ?string $_certificateUrlName = null;

	/** @var null|string the expression a named certificate URL must match before it is fetched */
	private ?string $_certificateUrlPattern = null;

	/** @var null|\Prado\IO\HttpClient\THttpClient how certificates are fetched */
	private ?THttpClient $_httpClient = null;

	/** @var null|\Prado\Caching\ICache where fetched certificates are kept */
	private ?ICache $_cache = null;

	/** @var int how long a fetched certificate is cached, in seconds */
	private int $_cacheTtl = self::DEFAULT_CACHE_TTL;

	/** @var int the largest certificate body accepted from a fetch, in bytes */
	private int $_certificateMaxSize = self::DEFAULT_CERTIFICATE_MAX_SIZE;

	/**
	 * Defaults the encoding to base64: an asymmetric signature is too long to be worth
	 * rendering as hex, and no provider does.
	 */
	public function __construct()
	{
		parent::__construct();
		// Asymmetric signatures are too long to be worth hex.
		$this->setEncoding('base64');
	}

	/**
	 * Verifies the signature a request presents against the provider's public key.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when neither a public key nor an
	 *   allow list for a certificate URL is configured.
	 * @return bool whether a presented signature verifies.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		if (!$this->bodyHashHolds($request)) {
			return false;
		}
		$bound = ['timestamp' => (string) $this->presentedTimestamp($request), 'id' => (string) $this->presentedId($request)];
		if ($this->getTimestampName() !== null && !$this->isFresh($bound['timestamp'])) {
			return false;
		}

		return $this->verifyAgainstKey($request, $this->expandPayload($request, $bound), $this->_algorithm);
	}

	/**
	 * Checks a payload against every signature the request presents.
	 *
	 * Subclasses that build their signed payload some other way -- a provider whose
	 * canonical string comes out of the body rather than out of a template -- reuse this
	 * rather than repeating the key resolution and the decode.
	 *
	 * The order matters. The configuration is checked first, so a scheme with no key is a
	 * configuration error whatever the request looks like; then the request has to present
	 * a signature; and only then is a certificate the request names fetched. An unsigned
	 * body is the cheapest thing an attacker can send, and it must not cost a network
	 * round trip.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @param string $payload the bytes that were signed.
	 * @param string $algorithm the digest to verify with.
	 * @throws \Prado\Exceptions\TConfigurationException when no key can be resolved.
	 * @return bool whether a presented signature verifies.
	 */
	protected function verifyAgainstKey(TWebhookRequest $request, string $payload, string $algorithm): bool
	{
		$key = $this->configuredKey();
		if ($key === null) {
			$this->requireCertificateConfiguration($request);
		}

		$presented = $this->presentedSignatures($request);
		if ($presented === []) {
			return false;
		}

		$key ??= $this->fetchedKey($request);
		if ($key === null) {
			return false;
		}

		$verified = false;
		foreach ($presented as $candidate) {
			$stripped = $this->stripPrefix($candidate);
			$raw = $stripped === null ? false : $this->getEncoding()->decode($stripped);
			if ($raw === false || $raw === '') {
				continue;
			}
			$verified = openssl_verify($payload, $raw, $key, $algorithm) === 1 || $verified;
		}

		return $verified;
	}

	/**
	 * Signs an outbound request with the private key.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request about to be made.
	 * @throws \Prado\Exceptions\TConfigurationException when no private key is set, or it
	 *   will not parse, or the signing fails.
	 * @return array<string, string> the signature header, plus the timestamp header when the
	 *   scheme names one.
	 */
	public function sign(TWebhookRequest $request): array
	{
		if ($this->_privateKey === '') {
			throw new TConfigurationException('webhooks_private_key_required', static::class);
		}
		$key = $this->loadPrivateKey($this->readKeyMaterial($this->_privateKey));
		if ($key === false) {
			throw new TConfigurationException(
				$this->_padding === TWebhookPadding::Pss ? 'webhooks_pss_key_invalid' : 'webhooks_key_invalid',
				'PrivateKey',
				static::class
			);
		}

		$bound = ['timestamp' => '', 'id' => ''];
		if ($this->getTimestampName() !== null) {
			$bound['timestamp'] = (string) time();
		}

		$raw = '';
		if (!openssl_sign($this->expandPayload($request, $bound), $raw, $key, $this->_algorithm)) {
			throw new TConfigurationException('webhooks_signing_failed', static::class);
		}

		$signed = [$this->getName() => $this->getPrefix() . $this->getEncoding()->encode($raw)];
		if ($bound['timestamp'] !== '') {
			$signed[(string) $this->getTimestampName()] = $bound['timestamp'];
		}

		return $signed;
	}

	/**
	 * Returns the public key to verify this request with.
	 *
	 * Null means "cannot verify this request", which is a refusal rather than an error: a
	 * certificate URL that does not match the allow list, or will not fetch, or is not a
	 * key, is all attacker-influenced input.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @throws \Prado\Exceptions\TConfigurationException when the scheme is configured with
	 *   neither a key nor a certificate URL allow list.
	 * @return null|\OpenSSLAsymmetricKey the key, or null when this request cannot be verified.
	 */
	protected function resolveKey(TWebhookRequest $request): ?\OpenSSLAsymmetricKey
	{
		$key = $this->configuredKey();
		if ($key !== null) {
			return $key;
		}
		$this->requireCertificateConfiguration($request);

		return $this->fetchedKey($request);
	}

	/**
	 * Loads the configured {@see getPublicKey PublicKey}, when there is one.
	 * @throws \Prado\Exceptions\TConfigurationException when a key is configured and will
	 *   not parse.
	 * @return null|\OpenSSLAsymmetricKey the key, or null when none is configured.
	 */
	protected function configuredKey(): ?\OpenSSLAsymmetricKey
	{
		if ($this->_publicKey === '') {
			return null;
		}
		$key = $this->loadPublicKey($this->readKeyMaterial($this->_publicKey));
		if ($key === false) {
			throw new TConfigurationException(
				$this->_padding === TWebhookPadding::Pss ? 'webhooks_pss_key_invalid' : 'webhooks_key_invalid',
				'PublicKey',
				static::class
			);
		}

		return $key;
	}

	/**
	 * Requires that, with no key configured, a certificate URL can be read from the request
	 * and an allow list exists for it. Checked before anything is read from the request, so
	 * a scheme with nothing to verify against fails as configuration and not as a stream of
	 * refused deliveries.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @throws \Prado\Exceptions\TConfigurationException when the scheme is configured with
	 *   neither a key nor a certificate URL allow list.
	 */
	protected function requireCertificateConfiguration(TWebhookRequest $request): void
	{
		if ($this->_certificateUrlName === null && $this->certificateUrl($request) === null) {
			throw new TConfigurationException('webhooks_public_key_required', static::class);
		}
		if ($this->_certificateUrlPattern === null) {
			// Refusing here rather than fetching is the whole defense: a URL out of the
			// request is a stranger's instruction until an allow list says otherwise.
			throw new TConfigurationException('webhooks_certificate_pattern_required', static::class);
		}
	}

	/**
	 * Fetches and loads the certificate the request names, once it has passed the allow list.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|\OpenSSLAsymmetricKey the key, or null when the request names no URL the
	 *   allow list accepts, or it will not fetch, or what it serves is not a key.
	 */
	protected function fetchedKey(TWebhookRequest $request): ?\OpenSSLAsymmetricKey
	{
		$url = $this->certificateUrl($request);
		if ($url === null || $this->_certificateUrlPattern === null || !preg_match($this->_certificateUrlPattern, $url)) {
			return null;
		}
		$certificate = $this->fetchCertificate($url);
		if ($certificate === null) {
			return null;
		}
		$key = $this->loadPublicKey($certificate);

		return $key === false ? null : $key;
	}

	/**
	 * Returns the certificate URL the request names, before it is checked against the allow
	 * list. Subclasses whose provider puts it somewhere other than a header or parameter --
	 * inside the JSON body, say -- override this.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|string the URL, or null when the request names none.
	 */
	protected function certificateUrl(TWebhookRequest $request): ?string
	{
		return $this->_certificateUrlName === null
			? null
			: $this->readValue($request, $this->_certificateUrlName);
	}

	/**
	 * Fetches a certificate, through the cache when there is one.
	 *
	 * Only a body that OpenSSL reads as a key is returned, and only such a body is cached:
	 * an error page, an empty document, or anything over
	 * {@see getCertificateMaxSize CertificateMaxSize} is refused without being written
	 * anywhere, so a bad response cannot be remembered for the cache lifetime.
	 *
	 * @param string $url the certificate URL, already checked against the allow list.
	 * @return null|string the certificate, or null when it could not be fetched or is not
	 *   a key.
	 */
	protected function fetchCertificate(string $url): ?string
	{
		$cache = $this->getCache();
		$cacheKey = static::class . ':' . sha1($url);
		if ($cache !== null && is_string($cached = $cache->get($cacheKey)) && $cached !== '') {
			return $cached;
		}

		try {
			$response = $this->getHttpClient()->download('GET', $url);
		} catch (THttpClientException) {
			return null;
		}
		if (!$response->isSuccess() || ($certificate = $response->getBody()) === '') {
			return null;
		}
		if (strlen($certificate) > $this->_certificateMaxSize) {
			return null;
		}
		if ($this->loadPublicKey($certificate) === false) {
			// Not cached: a response that is not a key is not worth remembering, and
			// remembering it would refuse every delivery until it expired.
			return null;
		}
		$cache?->set($cacheKey, $certificate, $this->_cacheTtl);

		return $certificate;
	}

	/**
	 * Loads a public key or certificate, as the configured padding needs it.
	 * @param string $material the key or certificate.
	 * @return false|\OpenSSLAsymmetricKey the key, or false when it cannot be used.
	 */
	protected function loadPublicKey(string $material): \OpenSSLAsymmetricKey|false
	{
		if ($this->_padding === TWebhookPadding::Pss) {
			return $this->pssKey($material, $this->pssDigest(), $this->getSaltLength());
		}

		return openssl_pkey_get_public($material);
	}

	/**
	 * Loads a private key, as the configured padding needs it.
	 * @param string $material the key.
	 * @return false|\OpenSSLAsymmetricKey the key, or false when it cannot be used.
	 */
	protected function loadPrivateKey(string $material): \OpenSSLAsymmetricKey|false
	{
		if ($this->_padding === TWebhookPadding::Pss) {
			return $this->pssKey($material, $this->pssDigest(), $this->getSaltLength(), true);
		}

		return openssl_pkey_get_private($material);
	}

	/**
	 * Returns the digest a PSS key is built around, after checking it is one PSS can carry.
	 *
	 * {@see setAlgorithm Algorithm} accepts whatever OpenSSL can sign with, which is a longer
	 * list than PSS parameters can name: a PSS key states its hash by object identifier, and
	 * only the SHA-2 family has one here. Refused as configuration rather than left to
	 * surface as a `ValueError` from {@see hash}, which a provider would see as a 500.
	 *
	 * @throws \Prado\Exceptions\TConfigurationException when the algorithm has no PSS
	 *   parameters, or PHP's hash extension does not know it.
	 * @return string the digest name.
	 * @since 0.2.0
	 */
	protected function pssDigest(): string
	{
		if (!in_array($this->_algorithm, hash_algos(), true) || $this->pssParameters($this->_algorithm, 0) === null) {
			throw new TConfigurationException('webhooks_pss_digest_unsupported', $this->_algorithm, static::class);
		}

		return $this->_algorithm;
	}

	/**
	 * Removes {@see getPrefix Prefix} from a presented signature. A value that does not carry
	 * the configured prefix is not a candidate at all, which is how {@see THmacWebhookSignature}
	 * treats one: the prefix names the scheme, and a value under another name is not this
	 * scheme's.
	 * @param string $presented the presented signature.
	 * @return null|string the signature with the prefix removed, or null when a prefix is
	 *   configured and the value does not start with it.
	 */
	protected function stripPrefix(string $presented): ?string
	{
		$prefix = $this->getPrefix();
		if ($prefix === '') {
			return $presented;
		}

		return str_starts_with($presented, $prefix) ? substr($presented, strlen($prefix)) : null;
	}

	/**
	 * @return string the public key or certificate, as configured.
	 */
	public function getPublicKey(): string
	{
		return $this->_publicKey;
	}

	/**
	 * @param mixed $value the public key or certificate, as PEM text or a path to a file
	 *   holding it.
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
	 * @param mixed $value the private key, as PEM text or a path to a file holding it. Only
	 *   an application that *sends* asymmetrically signed webhooks needs one.
	 */
	public function setPrivateKey($value): void
	{
		$this->_privateKey = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the digest the signature is over. Defaults to `sha256`.
	 */
	public function getAlgorithm(): string
	{
		return $this->_algorithm;
	}

	/**
	 * @param mixed $value a digest {@see openssl_get_md_methods} lists.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when OpenSSL does not offer $value.
	 */
	public function setAlgorithm($value): void
	{
		$algorithm = strtolower(trim(TPropertyValue::ensureString($value)));
		if (!in_array($algorithm, array_map('strtolower', openssl_get_md_methods()), true)) {
			throw new TInvalidDataValueException('webhooks_algorithm_invalid', $algorithm);
		}
		$this->_algorithm = $algorithm;
	}

	/**
	 * @return null|string where the request names the certificate to verify it with, or null.
	 */
	public function getCertificateUrlName(): ?string
	{
		return $this->_certificateUrlName;
	}

	/**
	 * Names the header or parameter carrying the certificate URL, for providers that rotate
	 * certificates and name the current one in each delivery.
	 * {@see setCertificateUrlPattern CertificateUrlPattern} has to be set as well; without
	 * it, verification refuses rather than fetching.
	 * @param mixed $value the header or parameter name, or an empty value for none.
	 */
	public function setCertificateUrlName($value): void
	{
		$name = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_certificateUrlName = $name === '' ? null : $name;
	}

	/**
	 * @return null|string the expression a named certificate URL must match, or null.
	 */
	public function getCertificateUrlPattern(): ?string
	{
		return $this->_certificateUrlPattern;
	}

	/**
	 * Sets the allow list a certificate URL out of the request must match before it is
	 * fetched. Anchor it, include the scheme and the host, and make it as narrow as the
	 * provider's own domains allow.
	 * @param mixed $value a PCRE pattern, delimiters included.
	 * @throws \Prado\Exceptions\TConfigurationException when $value is not a usable pattern;
	 *   an unusable one would otherwise match nothing and fail every delivery, or worse, be
	 *   mistaken for protection it does not give.
	 */
	public function setCertificateUrlPattern($value): void
	{
		$pattern = trim(TPropertyValue::ensureString($value ?? ''));
		if ($pattern === '') {
			$this->_certificateUrlPattern = null;

			return;
		}
		if (@preg_match($pattern, '') === false) {
			throw new TConfigurationException('webhooks_pattern_invalid', $pattern, static::class);
		}
		$this->_certificateUrlPattern = $pattern;
	}

	/**
	 * @return \Prado\IO\HttpClient\THttpClient how certificates are fetched, created on first
	 *   use.
	 */
	public function getHttpClient(): THttpClient
	{
		if ($this->_httpClient === null) {
			$this->_httpClient = THttpClient::create();
			$this->_httpClient->setFollowRedirects(false);
		}

		return $this->_httpClient;
	}

	/**
	 * @param null|\Prado\IO\HttpClient\THttpClient $value the transport used to fetch
	 *   certificates, or null to build the default again on next use.
	 */
	public function setHttpClient(?THttpClient $value): void
	{
		$this->_httpClient = $value;
	}

	/**
	 * @return null|\Prado\Caching\ICache where fetched certificates are kept. Falls back to
	 *   the application's `cache` module when one is configured.
	 */
	public function getCache(): ?ICache
	{
		if ($this->_cache === null) {
			$cache = $this->getApplication()?->getModule('cache');
			$this->_cache = $cache instanceof ICache ? $cache : null;
		}

		return $this->_cache;
	}

	/**
	 * @param null|\Prado\Caching\ICache $value where fetched certificates are kept.
	 */
	public function setCache(?ICache $value): void
	{
		$this->_cache = $value;
	}

	/**
	 * @return int how long a fetched certificate is cached, in seconds. Defaults to
	 *   {@see DEFAULT_CACHE_TTL}.
	 */
	public function getCacheTtl(): int
	{
		return $this->_cacheTtl;
	}

	/**
	 * @param mixed $value the cache lifetime in seconds.
	 */
	public function setCacheTtl($value): void
	{
		$this->_cacheTtl = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int the largest certificate body accepted from a fetch, in bytes. Defaults to
	 *   {@see DEFAULT_CERTIFICATE_MAX_SIZE}.
	 * @since 0.2.0
	 */
	public function getCertificateMaxSize(): int
	{
		return $this->_certificateMaxSize;
	}

	/**
	 * Bounds the size of a fetched certificate. A PEM certificate is a few kilobytes; a
	 * response far larger than that is not one, and reading it into memory and handing it
	 * to OpenSSL is work an attacker who controls the URL's host should not be able to
	 * order.
	 * @param mixed $value the size limit in bytes; less than 1 is read as 1.
	 * @since 0.2.0
	 */
	public function setCertificateMaxSize($value): void
	{
		$this->_certificateMaxSize = max(1, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookPadding how an RSA signature is
	 *   padded. Defaults to
	 *   {@see \Belisoful\Prado\Web\Webhooks\TWebhookPadding::Pkcs1}.
	 */
	public function getPadding(): TWebhookPadding
	{
		return $this->_padding;
	}

	/**
	 * Sets the RSA padding. `pss` is the one RFC 9421 recommends and newer providers use;
	 * it is not detectable from a signature, so a provider that sends PSS against the
	 * default fails every delivery exactly as a wrong key would. Ignored for an EC key,
	 * where padding is not a thing.
	 * @param mixed $value a padding, or its name: `pkcs1` or `pss`.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no padding.
	 */
	public function setPadding($value): void
	{
		$this->_padding = TWebhookPadding::ensure($value);
	}

	/**
	 * @throws \Prado\Exceptions\TConfigurationException when the salt follows the digest and
	 *   the digest is one PSS cannot carry, such as an OpenSSL name PHP's hash extension does
	 *   not know.
	 * @return int the PSS salt length in bytes. Defaults to the digest length, which is the
	 *   usual convention; RFC 9421 fixes it at 64 for its `rsa-pss-sha512`.
	 */
	public function getSaltLength(): int
	{
		if ($this->_saltLength > 0) {
			return $this->_saltLength;
		}
		if (!in_array($this->_algorithm, hash_algos(), true)) {
			throw new TConfigurationException('webhooks_pss_digest_unsupported', $this->_algorithm, static::class);
		}

		return strlen(hash($this->_algorithm, '', true));
	}

	/**
	 * Sets the PSS salt length. It is part of the key rather than of the signature, so it
	 * has to be the length the sender used: there is nothing to negotiate and nothing to
	 * detect, and a mismatch refuses every delivery.
	 * @param mixed $value the salt length in bytes; 0 or less follows the digest.
	 */
	public function setSaltLength($value): void
	{
		$this->_saltLength = max(0, TPropertyValue::ensureInteger($value));
	}
}
