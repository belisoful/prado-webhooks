<?php

/**
 * TWebhookEcdsaTrait class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks\Signature;

/**
 * TWebhookEcdsaTrait trait.
 *
 * Converts ECDSA signatures between the two shapes in use. OpenSSL produces and consumes
 * DER: a SEQUENCE of two INTEGERs. Every web signing format -- JWS, and HTTP Message
 * Signatures after it -- carries the two coordinates raw instead, each left padded to the
 * curve's size. Neither is convertible by luck: a coordinate whose leading byte is zero,
 * or whose high bit is set, is exactly where a naive conversion stops working, and it only
 * happens in a fraction of signatures.
 *
 * | Curve | Coordinate size |
 * | --- | --- |
 * | P-256 | 32 bytes |
 * | P-384 | 48 bytes |
 * | P-521 | 66 bytes (521 bits, rounded up) |
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
trait TWebhookEcdsaTrait
{
	/**
	 * Wraps raw coordinates in the DER SEQUENCE of two INTEGERs that OpenSSL expects.
	 * @param string $raw the two coordinates, each left padded to $size.
	 * @param int $size the curve's coordinate size in bytes.
	 * @return null|string the DER signature, or null when $raw is the wrong length.
	 */
	protected function derFromRaw(string $raw, int $size): ?string
	{
		if (strlen($raw) !== $size * 2) {
			return null;
		}
		$integers = '';
		foreach ([substr($raw, 0, $size), substr($raw, $size)] as $coordinate) {
			$coordinate = ltrim($coordinate, "\x00");
			if ($coordinate === '') {
				$coordinate = "\x00";
			} elseif (ord($coordinate[0]) > 0x7f) {
				// DER INTEGERs are signed, so a leading bit of 1 needs a zero byte ahead of it.
				$coordinate = "\x00" . $coordinate;
			}
			$integers .= "\x02" . chr(strlen($coordinate)) . $coordinate;
		}

		return "\x30" . $this->derLength(strlen($integers)) . $integers;
	}

	/**
	 * Unwraps a DER signature into the raw coordinates a web format carries.
	 * @param string $der the DER signature.
	 * @param int $size the curve's coordinate size in bytes.
	 * @return null|string the coordinates, or null when $der will not parse.
	 */
	protected function rawFromDer(string $der, int $size): ?string
	{
		$offset = 0;
		if (($der[$offset] ?? '') !== "\x30") {
			return null;
		}
		$offset++;
		$length = ord($der[$offset] ?? "\x00");
		// A long-form length prefixes the byte count; a signature of these sizes never needs
		// more than one extra byte.
		$offset += $length > 0x80 ? 1 + ($length - 0x80) : 1;

		$raw = '';
		foreach ([0, 1] as $ignored) {
			if (($der[$offset] ?? '') !== "\x02") {
				return null;
			}
			$offset++;
			$coordinateLength = ord($der[$offset] ?? "\x00");
			$offset++;
			$coordinate = substr($der, $offset, $coordinateLength);
			$offset += $coordinateLength;
			$coordinate = ltrim($coordinate, "\x00");
			if (strlen($coordinate) > $size) {
				return null;
			}
			$raw .= str_pad($coordinate, $size, "\x00", STR_PAD_LEFT);
		}

		return $raw;
	}

	/**
	 * @param int $length the byte count to encode.
	 * @return string the DER length octets.
	 */
	protected function derLength(int $length): string
	{
		return $length < 0x80 ? chr($length) : "\x81" . chr($length);
	}
}
