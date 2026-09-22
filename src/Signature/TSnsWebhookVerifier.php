<?php

/**
 * TSnsWebhookVerifier class file
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
 * TSnsWebhookVerifier class.
 *
 * Amazon SNS, the one scheme in this package that could not be expressed as configuration.
 * Everything about it lives in the JSON body rather than in headers -- the signature, the
 * certificate URL, the timestamp, the topic -- and what is signed is a canonicalization of
 * that body's own fields, in a fixed order that depends on the message type:
 *
 * ```
 * Message\n<value>\nMessageId\n<value>\nSubject\n<value>\nTimestamp\n<value>\nTopicArn\n<value>\nType\n<value>\n
 * ```
 *
 * `Subject` appears only when the message carries one, and a confirmation message signs
 * `SubscribeURL` and `Token` in place of `Subject`. No template over headers and parameters
 * produces that, which is why this is a class.
 *
 * ```xml
 * <signature class="Belisoful\Prado\Web\Webhooks\Signature\TSnsWebhookVerifier"
 *		TopicArn="arn:aws:sns:us-east-1:123456789012:my-topic" SignatureVersions="2" />
 * ```
 *
 * **{@see setTopicArn TopicArn} is required, and it is the check that matters most.** The
 * certificate is Amazon's, not yours: a message from *any* SNS topic in *any* AWS account
 * verifies cryptographically. Without the topic check, an endpoint accepts anything anyone
 * with an AWS account chooses to send it.
 *
 * {@see setSignatureVersions SignatureVersions} accepts `1` (SHA-1) and `2` (SHA-256), and
 * both by default because SHA-1 is still what a topic sends until SHA-256 is switched on for
 * it. Turn that on, then set this to `2`.
 *
 * **Confirming a subscription is the handler's job.** A `SubscriptionConfirmation` message
 * arrives here first, and once verified the handler has to fetch its `SubscribeURL` before
 * any notification will follow. Confirm only topics the application expects -- the
 * `TopicArn` check above already refuses the rest.
 *
 * This verifies and does not sign: the signature belongs in the body, and a signer returns
 * headers.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TSnsWebhookVerifier extends TPublicKeyWebhookSignature
{
	/** @var string the hosts a signing certificate may be fetched from. */
	public const DEFAULT_CERTIFICATE_URL_PATTERN = '#^https://sns\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?/#';

	/** @var array<string, string[]> the fields each message type signs, in the order it signs them. */
	public const SIGNED_FIELDS = [
		'Notification' => ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type'],
		'SubscriptionConfirmation' => ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'],
		'UnsubscribeConfirmation' => ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'],
	];

	/**
	 * The digest each signature version uses. PHP folds the numeric keys to integers; a
	 * version read out of a message is a string, and both index this the same way.
	 * @var array<int, string>
	 */
	public const SIGNATURE_VERSIONS = ['1' => 'sha1', '2' => 'sha256'];

	/** @var string[] the topics a message may come from */
	private array $_topicArns = [];

	/** @var string[] the signature versions accepted */
	private array $_signatureVersions = ['1', '2'];

	/** @var int how old a message may be, in seconds; 0 accepts any */
	private int $_maxAge = 0;

	/** @var null|string the body the memo below was decoded from */
	private ?string $_decodedBody = null;

	/** @var null|array<string, mixed> the decoded body */
	private ?array $_decoded = null;

	/**
	 * Defaults the certificate URL to the field SNS names it in, and the allow list to
	 * Amazon's own signing hosts.
	 */
	public function __construct()
	{
		parent::__construct();
		$this->setCertificateUrlName('SigningCertURL');
		$this->setCertificateUrlPattern(self::DEFAULT_CERTIFICATE_URL_PATTERN);
	}

	/**
	 * Verifies an SNS message.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request as received.
	 * @throws \Prado\Exceptions\TConfigurationException when no topic is configured.
	 * @return bool whether the message is a signed notification from an expected topic.
	 */
	public function verify(TWebhookRequest $request): bool
	{
		if ($this->_topicArns === []) {
			throw new TConfigurationException('webhooks_topic_required', static::class);
		}

		$message = $this->message($request);
		if ($message === null) {
			return false;
		}

		$type = is_string($message['Type'] ?? null) ? $message['Type'] : '';
		if (!isset(self::SIGNED_FIELDS[$type])) {
			return false;
		}
		if (!in_array($message['TopicArn'] ?? null, $this->_topicArns, true)) {
			// The certificate is Amazon's; the topic is what makes the message yours.
			return false;
		}

		$version = (string) ($message['SignatureVersion'] ?? '');
		if (!in_array($version, $this->_signatureVersions, true) || !isset(self::SIGNATURE_VERSIONS[$version])) {
			return false;
		}
		if (!$this->isRecent($message)) {
			return false;
		}

		$canonical = $this->canonicalString($message);

		return $canonical !== null
			&& $this->verifyAgainstKey($request, $canonical, self::SIGNATURE_VERSIONS[$version]);
	}

	/**
	 * Signing is not available: SNS carries its signature in the body, and a signer returns
	 * headers.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @throws \Prado\Exceptions\TConfigurationException always.
	 * @return array<string, string> never returns.
	 */
	public function sign(TWebhookRequest $request): array
	{
		throw new TConfigurationException('webhooks_sign_source_unsupported', 'body', static::class);
	}

	/**
	 * Builds the string SNS signed, from the fields its message type signs.
	 *
	 * Each field contributes its name and its value, each followed by a newline, in the
	 * order {@see SIGNED_FIELDS} gives. A field the message does not carry is skipped
	 * entirely rather than contributing an empty value -- which is what `Subject` does on
	 * most notifications, and getting it wrong breaks exactly those.
	 *
	 * @param array<string, mixed> $message the decoded message.
	 * @return null|string the canonical string, or null when the type signs nothing known.
	 */
	public function canonicalString(array $message): ?string
	{
		$fields = self::SIGNED_FIELDS[$message['Type'] ?? ''] ?? null;
		if ($fields === null) {
			return null;
		}

		$canonical = '';
		foreach ($fields as $field) {
			if (!isset($message[$field]) || !is_scalar($message[$field])) {
				continue;
			}
			$canonical .= $field . "\n" . $message[$field] . "\n";
		}

		return $canonical;
	}

	/**
	 * @param array<string, mixed> $message the decoded message.
	 * @return bool whether the message is inside {@see getMaxAge MaxAge}.
	 */
	protected function isRecent(array $message): bool
	{
		if ($this->_maxAge <= 0) {
			return true;
		}
		$timestamp = is_string($message['Timestamp'] ?? null) ? strtotime($message['Timestamp']) : false;

		return $timestamp !== false && abs(time() - $timestamp) <= $this->_maxAge;
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return string[] the one signature the body carries.
	 */
	protected function presentedSignatures(TWebhookRequest $request): array
	{
		$signature = $this->message($request)['Signature'] ?? null;

		return is_string($signature) && $signature !== '' ? [$signature] : [];
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|string the certificate URL the body names.
	 */
	protected function certificateUrl(TWebhookRequest $request): ?string
	{
		$url = $this->message($request)['SigningCertURL'] ?? null;

		return is_string($url) ? $url : null;
	}

	/**
	 * Decodes the body, remembering the last one: three of the methods above need it and a
	 * message is small, but decoding it once per call would still be three times per
	 * delivery.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookRequest $request the request.
	 * @return null|array<string, mixed> the decoded message, or null when the body is not a
	 *   JSON object.
	 */
	protected function message(TWebhookRequest $request): ?array
	{
		if ($this->_decodedBody !== $request->getBody()) {
			$this->_decodedBody = $request->getBody();
			$decoded = json_decode($this->_decodedBody, true);
			$this->_decoded = is_array($decoded) ? $decoded : null;
		}

		return $this->_decoded;
	}

	/**
	 * @return string[] the topics a message may come from.
	 */
	public function getTopicArns(): array
	{
		return $this->_topicArns;
	}

	/**
	 * @return string the topics a message may come from, as a comma separated list.
	 */
	public function getTopicArn(): string
	{
		return implode(', ', $this->_topicArns);
	}

	/**
	 * Sets the topics this endpoint accepts. Required, and the most important setting here:
	 * every SNS message in every AWS account is signed by the same certificate authority, so
	 * without this the endpoint accepts whatever anyone with an AWS account sends it.
	 * @param mixed $value the topic ARNs, as an array or a comma separated list.
	 * @throws \Prado\Exceptions\TConfigurationException when $value names none.
	 */
	public function setTopicArn($value): void
	{
		$arns = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$arns = array_values(array_filter(array_map(
			static fn ($arn) => trim((string) $arn),
			$arns
		), static fn ($arn) => $arn !== ''));

		if ($arns === []) {
			throw new TConfigurationException('webhooks_topic_required', static::class);
		}
		$this->_topicArns = $arns;
	}

	/**
	 * @return string[] the signature versions accepted. Defaults to both.
	 */
	public function getSignatureVersions(): array
	{
		return $this->_signatureVersions;
	}

	/**
	 * Sets the accepted signature versions: `1` is SHA-1, `2` is SHA-256. Both are accepted
	 * by default because a topic sends `1` until SHA-256 is enabled on it; once it is, set
	 * this to `2` so the weaker one stops being accepted.
	 * @param mixed $value the versions, as an array or a comma separated list.
	 * @throws \Prado\Exceptions\TConfigurationException when $value names none, or names one
	 *   this class does not implement.
	 */
	public function setSignatureVersions($value): void
	{
		$versions = is_array($value) ? $value : explode(',', TPropertyValue::ensureString($value));
		$versions = array_values(array_filter(array_map(
			static fn ($version) => trim((string) $version),
			$versions
		), static fn ($version) => $version !== ''));

		if ($versions === []) {
			throw new TConfigurationException('webhooks_algorithms_required', static::class);
		}
		foreach ($versions as $version) {
			if (!isset(self::SIGNATURE_VERSIONS[$version])) {
				throw new TConfigurationException('webhooks_algorithm_unsupported', $version, static::class);
			}
		}
		$this->_signatureVersions = $versions;
	}

	/**
	 * @return int how old a message may be, in seconds. Defaults to 0, which accepts any.
	 */
	public function getMaxAge(): int
	{
		return $this->_maxAge;
	}

	/**
	 * Bounds how old a message may be, read from its `Timestamp`. Off by default because the
	 * timestamp is signed but SNS retries its own deliveries for a long time, and a limit
	 * set too tight refuses redeliveries that were genuinely sent.
	 * @param mixed $value the age limit in seconds; 0 or less accepts any message.
	 */
	public function setMaxAge($value): void
	{
		$this->_maxAge = TPropertyValue::ensureInteger($value);
	}
}
