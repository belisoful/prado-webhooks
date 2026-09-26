<?php

/**
 * TWebhookRsaPssTrait class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

/**
 * TWebhookRsaPssTrait trait.
 *
 * Makes RSASSA-PSS available to a package that only has {@see openssl_sign} and
 * {@see openssl_verify}, neither of which takes a padding argument.
 *
 * OpenSSL does not need one: it takes the padding from the *key*. An RSA key declared as
 * `id-rsaEncryption` signs PKCS#1 v1.5, and one declared as `id-RSASSA-PSS` signs PSS with
 * the hash, mask generation function, and salt length carried in the key's own parameters.
 * The two key types wrap byte-identical key material -- only the `AlgorithmIdentifier` in
 * front of it differs -- so a provider's ordinary RSA key becomes a PSS key by rewriting
 * that one structure:
 *
 * ```
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *     algorithm  AlgorithmIdentifier,   <- id-rsaEncryption, replaced by id-RSASSA-PSS + params
 *     subjectPublicKey BIT STRING       <- unchanged
 * }
 * ```
 *
 * So no cryptography is implemented here. The PSS is OpenSSL's; this moves an object
 * identifier and states the parameters that were previously implicit.
 *
 * The key is normalized through OpenSSL before being rewritten, which is what lets a
 * caller pass whatever the provider published: a PKCS#1 `RSA PRIVATE KEY`, a PKCS#8
 * `PRIVATE KEY`, a bare `PUBLIC KEY`, or an X.509 certificate all arrive here and leave as
 * the one shape this rewrites. What that shape is depends on the OpenSSL underneath: 3.x
 * exports a private key as PKCS#8, 1.1 as PKCS#1, so the rewrite reads both -- a PKCS#1
 * key has no identifier to replace and is wrapped into the PKCS#8 or `SubjectPublicKeyInfo`
 * structure that carries one.
 *
 * **The salt length is part of the key, so it has to be the one the sender used.** There is
 * no negotiation and no auto-detection: a mismatch fails every delivery, looking exactly
 * like a wrong secret. RFC 9421 fixes it at 64 for `rsa-pss-sha512`; elsewhere the digest
 * length is the common convention and the default here.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
trait TWebhookRsaPssTrait
{
	/** @var array<string, \OpenSSLAsymmetricKey> keys already rewritten, by their inputs */
	private array $_pssKeys = [];

	/**
	 * Returns a key that makes OpenSSL use PSS.
	 * @param string $material the key as the provider published it, or a certificate.
	 * @param string $digest the hash and mask generation hash, such as `sha512`.
	 * @param int $saltLength the salt length in bytes.
	 * @param bool $private whether $material is a private key.
	 * @return false|\OpenSSLAsymmetricKey the key, or false when $material is not an RSA key
	 *   this can rewrite.
	 */
	protected function pssKey(string $material, string $digest, int $saltLength, bool $private = false): \OpenSSLAsymmetricKey|false
	{
		$memo = md5($material . "\0" . $digest . "\0" . $saltLength . "\0" . ($private ? '1' : '0'));
		if (isset($this->_pssKeys[$memo])) {
			return $this->_pssKeys[$memo];
		}

		$normalized = $this->normalizeRsaKey($material, $private);
		if ($normalized === null) {
			return false;
		}
		$rewritten = $this->rewriteAsPss($normalized, $digest, $saltLength, $private);
		if ($rewritten === null) {
			return false;
		}
		$key = $private ? openssl_pkey_get_private($rewritten) : openssl_pkey_get_public($rewritten);
		if ($key === false) {
			return false;
		}

		return $this->_pssKeys[$memo] = $key;
	}

	/**
	 * Loads a key through OpenSSL and exports it in the one shape {@see rewriteAsPss} reads:
	 * a PKCS#8 `PrivateKeyInfo`, or a `SubjectPublicKeyInfo`.
	 * @param string $material the key or certificate.
	 * @param bool $private whether it is a private key.
	 * @return null|string the normalized PEM, or null when it is not an RSA key.
	 */
	protected function normalizeRsaKey(string $material, bool $private): ?string
	{
		$key = $private ? openssl_pkey_get_private($material) : openssl_pkey_get_public($material);
		if ($key === false) {
			return null;
		}
		$details = openssl_pkey_get_details($key);
		if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
			// Rewriting the identifier on anything else would produce a key that parses and
			// verifies nothing.
			return null;
		}
		if (!$private) {
			return is_string($details['key'] ?? null) ? $details['key'] : null;
		}

		return openssl_pkey_export($key, $exported) ? (string) $exported : null;
	}

	/**
	 * Replaces the algorithm identifier of a normalized key with `id-RSASSA-PSS` and its
	 * parameters.
	 * A PKCS#1 key -- `RSA PRIVATE KEY` or `RSA PUBLIC KEY`, which is what OpenSSL 1.1
	 * exports and what many providers publish -- carries no algorithm identifier to
	 * rewrite. It is wrapped instead: the whole structure becomes the key material of a
	 * PKCS#8 `PrivateKeyInfo` or a `SubjectPublicKeyInfo` whose identifier is
	 * `id-RSASSA-PSS`, which is byte for byte what OpenSSL 3 would have exported before the
	 * rewrite.
	 *
	 * @param string $pem the normalized key.
	 * @param string $digest the hash and mask generation hash.
	 * @param int $saltLength the salt length in bytes.
	 * @param bool $private whether it is a private key.
	 * @return null|string the rewritten PEM, or null when the key will not parse or the
	 *   digest has no identifier here.
	 */
	protected function rewriteAsPss(string $pem, string $digest, int $saltLength, bool $private): ?string
	{
		$parameters = $this->pssParameters($digest, $saltLength);
		if ($parameters === null) {
			return null;
		}

		$der = base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);
		if ($der === false) {
			return null;
		}
		$outer = $this->pssDerRead($der, 0);
		if ($outer === null || $outer[0] !== 0x30) {
			return null;
		}
		$body = $outer[1];
		$identifier = $this->pssDer(0x30, $this->pssDer(0x06, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a") . $parameters);
		$expected = $private ? 0x04 : 0x03;

		// A private key opens with a version INTEGER that has to be carried across; a public
		// key opens with the algorithm identifier itself.
		$prefix = '';
		$offset = 0;
		if ($private) {
			$version = $this->pssDerRead($body, 0);
			if ($version === null || $version[0] !== 0x02) {
				return null;
			}
			$prefix = $this->pssDer(0x02, $version[1]);
			$offset = $version[2];
		}

		$algorithm = $this->pssDerRead($body, $offset);
		if ($algorithm === null) {
			return null;
		}
		if ($algorithm[0] === 0x02) {
			// No identifier to rewrite: this is PKCS#1, an RSAPrivateKey (version, n, e,
			// d, ...) or an RSAPublicKey (n, e). Wrap the whole structure as the key
			// material of the outer type the identifier belongs in.
			if (!$this->isPkcs1Body($body, $private)) {
				return null;
			}
			$rewritten = $private
				? $this->pssDer(0x30, $this->pssDer(0x02, "\x00") . $identifier . $this->pssDer(0x04, $der))
				: $this->pssDer(0x30, $identifier . $this->pssDer(0x03, "\x00" . $der));
		} else {
			if ($algorithm[0] !== 0x30) {
				return null;
			}
			$keyMaterial = $this->pssDerRead($body, $algorithm[2]);
			if ($keyMaterial === null || $keyMaterial[0] !== $expected) {
				return null;
			}
			$rewritten = $this->pssDer(0x30, $prefix . $identifier . $this->pssDer($expected, $keyMaterial[1]));
		}
		$label = $private ? 'PRIVATE KEY' : 'PUBLIC KEY';

		return "-----BEGIN {$label}-----\n"
			. chunk_split(base64_encode($rewritten), 64, "\n")
			. "-----END {$label}-----\n";
	}

	/**
	 * Whether a SEQUENCE body is the shape PKCS#1 gives an RSA key: nothing but INTEGERs,
	 * exactly two of them for an `RSAPublicKey` and at least nine for an `RSAPrivateKey`.
	 * A PKCS#8 `PrivateKeyInfo` also opens with an INTEGER, and this is what keeps one
	 * handed over as a public key from being wrapped into nonsense.
	 * @param string $body the contents of the outer SEQUENCE.
	 * @param bool $private whether a private key is expected.
	 * @return bool whether the body is a PKCS#1 key of the expected kind.
	 * @since 0.2.0
	 */
	protected function isPkcs1Body(string $body, bool $private): bool
	{
		$count = 0;
		$offset = 0;
		$size = strlen($body);
		while ($offset < $size) {
			$element = $this->pssDerRead($body, $offset);
			if ($element === null || $element[0] !== 0x02) {
				return false;
			}
			$offset = $element[2];
			$count++;
		}

		return $private ? $count >= 9 : $count === 2;
	}

	/**
	 * Builds `RSASSA-PSS-params`: the hash, MGF1 over the same hash, and the salt length.
	 * The trailer field is left at its default of 1, which is the only value in use.
	 * @param string $digest the hash name.
	 * @param int $saltLength the salt length in bytes.
	 * @return null|string the DER parameters, or null when $digest has no identifier here.
	 */
	protected function pssParameters(string $digest, int $saltLength): ?string
	{
		$oids = [
			'sha256' => "\x60\x86\x48\x01\x65\x03\x04\x02\x01",
			'sha384' => "\x60\x86\x48\x01\x65\x03\x04\x02\x02",
			'sha512' => "\x60\x86\x48\x01\x65\x03\x04\x02\x03",
		];
		if (!isset($oids[$digest]) || $saltLength < 0) {
			return null;
		}

		$digestIdentifier = $this->pssDer(0x30, $this->pssDer(0x06, $oids[$digest]) . $this->pssDer(0x05, ''));

		return $this->pssDer(
			0x30,
			$this->pssDer(0xa0, $digestIdentifier)
			. $this->pssDer(0xa1, $this->pssDer(0x30, $this->pssDer(0x06, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08") . $digestIdentifier))
			. $this->pssDer(0xa2, $this->pssDerInteger($saltLength))
		);
	}

	/**
	 * Encodes a non-negative integer as a DER INTEGER.
	 *
	 * DER integers are signed, so a value whose leading byte has its high bit set needs a
	 * zero byte in front of it. Without that, a salt length of 128 encodes as -128.
	 *
	 * @param int $value the integer.
	 * @return string the encoded element.
	 */
	protected function pssDerInteger(int $value): string
	{
		$bytes = $value === 0 ? "\x00" : ltrim(pack('N', $value), "\x00");
		if (ord($bytes[0]) > 0x7f) {
			$bytes = "\x00" . $bytes;
		}

		return $this->pssDer(0x02, $bytes);
	}

	/**
	 * Wraps contents in a DER tag and length.
	 * @param int $tag the tag byte.
	 * @param string $contents the contents.
	 * @return string the encoded element.
	 */
	protected function pssDer(int $tag, string $contents): string
	{
		$length = strlen($contents);
		if ($length < 0x80) {
			return chr($tag) . chr($length) . $contents;
		}
		$bytes = ltrim(pack('N', $length), "\x00");

		return chr($tag) . chr(0x80 | strlen($bytes)) . $bytes . $contents;
	}

	/**
	 * Reads one DER element.
	 * @param string $der the encoded data.
	 * @param int $offset where the element starts.
	 * @return null|array{0: int, 1: string, 2: int} the tag, the contents, and where the next
	 *   element starts; null when the element runs past the end of $der.
	 */
	protected function pssDerRead(string $der, int $offset): ?array
	{
		$size = strlen($der);
		if ($offset + 2 > $size) {
			return null;
		}
		$tag = ord($der[$offset]);
		$length = ord($der[$offset + 1]);
		$offset += 2;

		if ($length & 0x80) {
			$count = $length & 0x7f;
			if ($count === 0 || $count > 4 || $offset + $count > $size) {
				return null;
			}
			$length = (int) hexdec(bin2hex(substr($der, $offset, $count)));
			$offset += $count;
		}
		if ($offset + $length > $size) {
			return null;
		}

		return [$tag, substr($der, $offset, $length), $offset + $length];
	}
}
