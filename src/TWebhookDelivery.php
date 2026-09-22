<?php

/**
 * TWebhookDelivery class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\IO\HttpClient\THttpClientResponse;
use Prado\TEventParameter;
use Prado\TPropertyValue;

/**
 * TWebhookDelivery class.
 *
 * One attempt to deliver one payload to one target: what was sent, what came back, and how
 * many tries it took. {@see \Belisoful\Prado\Web\Webhooks\TWebhookSender} creates one per
 * target, raises its three events with it, and returns them all, so the same object is the
 * event parameter during a send and the record of it afterwards.
 *
 * ```php
 * foreach ($module->send($targets, $payload, 'invoice.paid') as $delivery) {
 *		if (!$delivery->getSuccessful()) {
 *			$this->reschedule($delivery->getTarget()->getData(), $delivery->getStatusText());
 *		}
 * }
 * ```
 *
 * During {@see TWebhookSender::onSending onSending} the delivery is still editable: a
 * handler may add to {@see getHeaders Headers}, rewrite {@see getBody Body}, or set
 * {@see setCancel Cancel} to call the delivery off. Afterwards it only reports.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TWebhookDelivery extends TEventParameter
{
	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookTarget where this is being delivered */
	private TWebhookTarget $_target;

	/** @var string the id identifying this delivery to the receiver, constant across retries */
	private string $_id;

	/** @var null|string the event being sent, when it has a name */
	private ?string $_event;

	/** @var string the encoded request body */
	private string $_body;

	/** @var array<string, string> the request headers, before signing */
	private array $_headers = [];

	/** @var bool whether a handler called the delivery off */
	private bool $_cancel = false;

	/** @var int how many requests have been made */
	private int $_attempts = 0;

	/** @var null|\Prado\IO\HttpClient\THttpClientResponse the last response, when one arrived */
	private ?THttpClientResponse $_response = null;

	/** @var null|string the last transport failure, when the request never completed */
	private ?string $_error = null;

	/** @var float how long every attempt took together, in seconds */
	private float $_duration = 0.0;

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookTarget $target where this is delivered.
	 * @param string $id the delivery id, constant across retries.
	 * @param mixed $payload the payload as the application gave it, before encoding.
	 * @param string $body the encoded request body.
	 * @param null|string $event the event being sent, when it has a name.
	 */
	public function __construct(TWebhookTarget $target, string $id, mixed $payload, string $body, ?string $event = null)
	{
		$this->_target = $target;
		$this->_id = $id;
		$this->_event = $event;
		$this->_body = $body;

		// The payload, not the encoded body, is the event parameter: a handler reading
		// $delivery['invoice']['id'] wants what the application passed in.
		parent::__construct($payload);
	}

	/**
	 * Whether the delivery arrived: a response came back, and its status was 2xx.
	 * @return bool whether the target accepted the delivery.
	 */
	public function getSuccessful(): bool
	{
		return $this->_response !== null && $this->_response->isSuccess();
	}

	/**
	 * A one-line account of how the delivery ended, for a log or a retry table.
	 * @return string the transport error, the HTTP status, or `not attempted`.
	 */
	public function getStatusText(): string
	{
		if ($this->_error !== null) {
			return $this->_error;
		}
		if ($this->_response !== null) {
			return 'HTTP ' . $this->_response->getStatusCode();
		}

		return 'not attempted';
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookTarget where this is being delivered.
	 */
	public function getTarget(): TWebhookTarget
	{
		return $this->_target;
	}

	/**
	 * @return string the id identifying this delivery to the receiver. It does not change
	 *   between retries, so a receiver can recognize a repeat of a delivery it already has.
	 */
	public function getID(): string
	{
		return $this->_id;
	}

	/**
	 * @return null|string the event being sent, or null when the send named none.
	 */
	public function getEvent(): ?string
	{
		return $this->_event;
	}

	/**
	 * @return mixed the payload as the application gave it, before encoding.
	 */
	public function getPayload(): mixed
	{
		return $this->getParameter();
	}

	/**
	 * @return string the encoded request body, which is what gets signed.
	 */
	public function getBody(): string
	{
		return $this->_body;
	}

	/**
	 * @param mixed $value the encoded request body. Changing it during
	 *   {@see TWebhookSender::onSending onSending} changes what is signed and sent; later it
	 *   changes only the record.
	 */
	public function setBody($value): void
	{
		$this->_body = TPropertyValue::ensureString($value);
	}

	/**
	 * @return array<string, string> the request headers, before the signature is added.
	 */
	public function getHeaders(): array
	{
		return $this->_headers;
	}

	/**
	 * @param array<string, string> $value the request headers.
	 */
	public function setHeaders(array $value): void
	{
		$this->_headers = $value;
	}

	/**
	 * @return bool whether a handler called the delivery off. Defaults to false.
	 */
	public function getCancel(): bool
	{
		return $this->_cancel;
	}

	/**
	 * @param mixed $value true to call the delivery off. A cancelled delivery is returned
	 *   with no attempts rather than dropped, so the caller can see it was skipped.
	 */
	public function setCancel($value): void
	{
		$this->_cancel = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return int how many requests have been made, including the one in progress.
	 */
	public function getAttempts(): int
	{
		return $this->_attempts;
	}

	/**
	 * @param mixed $value the attempt count.
	 */
	public function setAttempts($value): void
	{
		$this->_attempts = TPropertyValue::ensureInteger($value);
	}

	/**
	 * @return null|\Prado\IO\HttpClient\THttpClientResponse the last response, or null when
	 *   no attempt ever completed.
	 */
	public function getResponse(): ?THttpClientResponse
	{
		return $this->_response;
	}

	/**
	 * @param null|\Prado\IO\HttpClient\THttpClientResponse $value the response received.
	 */
	public function setResponse(?THttpClientResponse $value): void
	{
		$this->_response = $value;
		if ($value !== null) {
			$this->_error = null;
		}
	}

	/**
	 * @return null|string the last transport failure -- a refused connection, a timeout, a
	 *   name that would not resolve -- or null when the request completed.
	 */
	public function getError(): ?string
	{
		return $this->_error;
	}

	/**
	 * @param mixed $value the transport failure.
	 */
	public function setError($value): void
	{
		$this->_error = $value === null ? null : TPropertyValue::ensureString($value);
		if ($this->_error !== null) {
			$this->_response = null;
		}
	}

	/**
	 * @return float how long every attempt took together, in seconds.
	 */
	public function getDuration(): float
	{
		return $this->_duration;
	}

	/**
	 * @param mixed $value the elapsed time in seconds.
	 */
	public function setDuration($value): void
	{
		$this->_duration = TPropertyValue::ensureFloat($value);
	}
}
