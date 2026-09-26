<?php

/**
 * TWebhookQueueItem class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\Exceptions\TInvalidDataValueException;
use Prado\TEventParameter;
use Prado\TPropertyValue;

/**
 * TWebhookQueueItem class.
 *
 * One delivery waiting in a queue: where it is going, what it is sending, how many attempts
 * it has had, and when it is next due. It is also the parameter of
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookModule::onDequeue onDequeue}, so the same
 * object is the stored row and the thing a handler is given a chance to adjust before the
 * delivery is attempted.
 *
 * **The target is stored as the specification it was queued from**, not as a built
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookTarget}: a target holds a signer, and a signer
 * holds a key, which is not a thing to write into a table and read back hours later. Two
 * ways out, and an application should pick one deliberately:
 *
 * - Queue the secret with the delivery, by passing it in the specification as usual. It is
 *   then in the queue table, in reach of anything that can read that table.
 * - Queue a reference instead -- `['url' => ..., 'data' => $subscriptionId]` -- and attach a
 *   handler to `onDequeue` that looks the secret up and puts a built target on
 *   {@see setTarget Target}. Nothing secret is ever stored.
 *
 * {@see getDeliveryId DeliveryId} does not change between attempts, and is the id the
 * receiver is shown. A queue is at-least-once, so a receiver may be shown the same delivery
 * twice; that id is how it tells.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TWebhookQueueItem extends TEventParameter
{
	/** @var int the longest a recorded status may be, matching the column that holds it. */
	public const MAX_LAST_STATUS_LENGTH = 190;

	/** @var int the longest a delivery id may be, matching the column that holds it. */
	public const MAX_DELIVERY_ID_LENGTH = 64;

	/** @var int the longest an event name may be, matching the column that holds it. */
	public const MAX_EVENT_LENGTH = 190;

	/** @var null|string the lease this delivery was claimed under, if it was */
	private ?string $_leaseToken = null;

	/** @var null|int|string what the queue knows this delivery by; null until it is stored */
	private null|int|string $_id = null;

	/** @var string the id the receiver is shown, constant across attempts */
	private string $_deliveryId;

	/** @var null|string the event being sent, when it has a name */
	private ?string $_event;

	/** @var array<string, mixed>|string the specification the target is rebuilt from */
	private array|string $_targetSpec;

	/** @var null|\Belisoful\Prado\Web\Webhooks\TWebhookTarget a target a handler supplied instead */
	private ?TWebhookTarget $_target = null;

	/** @var \Belisoful\Prado\Web\Webhooks\TWebhookQueueStatus where the delivery stands */
	private TWebhookQueueStatus $_status = TWebhookQueueStatus::Pending;

	/** @var int how many attempts have been made */
	private int $_attempts = 0;

	/** @var int how many attempts this delivery gets; 0 takes the module's */
	private int $_maxAttempts = 0;

	/** @var int when the delivery is next due, in Unix seconds */
	private int $_nextAttempt = 0;

	/** @var null|string how the last attempt ended */
	private ?string $_lastStatus = null;

	/** @var int when the delivery was queued, in Unix seconds */
	private int $_createdTime = 0;

	/** @var int when the row was last written, in Unix seconds */
	private int $_updatedTime = 0;

	/**
	 * @param array<string, mixed>|string $targetSpec the specification the target is rebuilt from.
	 * @param mixed $payload the payload to send.
	 * @param null|string $event the event being sent, when it has a name.
	 * @param null|string $deliveryId the id the receiver is shown; one is minted when it is
	 *   not given.
	 */
	public function __construct(array|string $targetSpec, mixed $payload = null, ?string $event = null, ?string $deliveryId = null)
	{
		$this->_targetSpec = $targetSpec;
		$this->setEvent($event);
		$this->setDeliveryId($deliveryId ?? bin2hex(random_bytes(16)));
		$this->_createdTime = $this->_updatedTime = time();

		parent::__construct($payload);
	}

	/**
	 * @return null|int|string what the queue knows this delivery by, or null before it is
	 *   stored.
	 */
	public function getId(): null|int|string
	{
		return $this->_id;
	}

	/**
	 * @param null|int|string $value the queue's own identifier, which the queue sets.
	 */
	public function setId(null|int|string $value): void
	{
		$this->_id = $value;
	}

	/**
	 * @return string the id the receiver is shown, constant across attempts.
	 */
	public function getDeliveryId(): string
	{
		return $this->_deliveryId;
	}

	/**
	 * @param mixed $value the id the receiver is shown, at most
	 *   {@see MAX_DELIVERY_ID_LENGTH} characters.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when it is longer than the column
	 *   that holds it. A server in strict mode would refuse the row; one that is not would
	 *   truncate the id, and a receiver would then be shown an id nothing else has.
	 */
	public function setDeliveryId($value): void
	{
		$id = TPropertyValue::ensureString($value);
		if (mb_strlen($id) > self::MAX_DELIVERY_ID_LENGTH) {
			throw new TInvalidDataValueException('webhooks_queue_value_too_long', 'DeliveryId', self::MAX_DELIVERY_ID_LENGTH);
		}
		$this->_deliveryId = $id;
	}

	/**
	 * @return null|string the event being sent, or null when the send named none.
	 */
	public function getEvent(): ?string
	{
		return $this->_event;
	}

	/**
	 * @param mixed $value the event name, at most {@see MAX_EVENT_LENGTH} characters, or an
	 *   empty value for none.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when it is longer than the column
	 *   that holds it.
	 */
	public function setEvent($value): void
	{
		$event = TPropertyValue::ensureString($value ?? '');
		if (mb_strlen($event) > self::MAX_EVENT_LENGTH) {
			throw new TInvalidDataValueException('webhooks_queue_value_too_long', 'Event', self::MAX_EVENT_LENGTH);
		}
		$this->_event = $event === '' ? null : $event;
	}

	/**
	 * @return array<string, mixed>|string the specification the target is rebuilt from.
	 */
	public function getTargetSpec(): array|string
	{
		return $this->_targetSpec;
	}

	/**
	 * @param array<string, mixed>|string $value the specification.
	 */
	public function setTargetSpec(array|string $value): void
	{
		$this->_targetSpec = $value;
	}

	/**
	 * @return null|\Belisoful\Prado\Web\Webhooks\TWebhookTarget the target to deliver to, when
	 *   a handler supplied one, or null to rebuild it from the specification.
	 */
	public function getTarget(): ?TWebhookTarget
	{
		return $this->_target;
	}

	/**
	 * Supplies the target to deliver to, instead of one rebuilt from the stored
	 * specification. This is where an `onDequeue` handler puts a target carrying a secret
	 * that was deliberately never written to the queue.
	 * @param null|\Belisoful\Prado\Web\Webhooks\TWebhookTarget $value the target.
	 */
	public function setTarget(?TWebhookTarget $value): void
	{
		$this->_target = $value;
	}

	/**
	 * @return mixed the payload to send.
	 */
	public function getPayload(): mixed
	{
		return $this->getParameter();
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookQueueStatus where the delivery stands.
	 */
	public function getStatus(): TWebhookQueueStatus
	{
		return $this->_status;
	}

	/**
	 * @param mixed $value a status, or its name.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no status.
	 */
	public function setStatus($value): void
	{
		$this->_status = TWebhookQueueStatus::ensure($value);
	}

	/**
	 * @return int how many attempts have been made.
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
		$this->_attempts = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int how many attempts this delivery gets, or 0 to take the module's.
	 */
	public function getMaxAttempts(): int
	{
		return $this->_maxAttempts;
	}

	/**
	 * @param mixed $value the attempt limit; 0 takes the module's.
	 */
	public function setMaxAttempts($value): void
	{
		$this->_maxAttempts = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int when the delivery is next due, in Unix seconds. 0 means immediately.
	 */
	public function getNextAttempt(): int
	{
		return $this->_nextAttempt;
	}

	/**
	 * @param mixed $value when the delivery is next due, in Unix seconds.
	 */
	public function setNextAttempt($value): void
	{
		$this->_nextAttempt = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return null|string the lease this delivery was claimed under, or null when it was not
	 *   claimed. A queue writes a claimed delivery back only while this still matches the
	 *   row, so a runner whose lease expired cannot overwrite whoever holds it now.
	 */
	public function getLeaseToken(): ?string
	{
		return $this->_leaseToken;
	}

	/**
	 * @param null|string $value the lease token, which the queue sets when it claims.
	 */
	public function setLeaseToken(?string $value): void
	{
		$this->_leaseToken = ($value === null || $value === '') ? null : $value;
	}

	/**
	 * @return null|string how the last attempt ended, or null before there was one.
	 */
	public function getLastStatus(): ?string
	{
		return $this->_lastStatus;
	}

	/**
	 * Records how the last attempt ended.
	 *
	 * Trimmed to {@see MAX_LAST_STATUS_LENGTH}, the width of the column that holds it. This
	 * is where an exception message ends up, and those are long: a server in strict mode
	 * rejects an over-long value rather than truncating it, which would mean the write
	 * recording a failure failing in turn. The trim is marked with three ASCII dots rather
	 * than an ellipsis character, because a table on a latin1 server cannot hold the latter,
	 * and the write would fail for the mark that says it was shortened.
	 *
	 * @param mixed $value how the last attempt ended.
	 */
	public function setLastStatus($value): void
	{
		$status = $value === null ? '' : TPropertyValue::ensureString($value);
		if (mb_strlen($status) > self::MAX_LAST_STATUS_LENGTH) {
			$status = mb_substr($status, 0, self::MAX_LAST_STATUS_LENGTH - 3) . '...';
		}
		$this->_lastStatus = $status === '' ? null : $status;
	}

	/**
	 * @return int when the delivery was queued, in Unix seconds.
	 */
	public function getCreatedTime(): int
	{
		return $this->_createdTime;
	}

	/**
	 * @param mixed $value when the delivery was queued.
	 */
	public function setCreatedTime($value): void
	{
		$this->_createdTime = TPropertyValue::ensureInteger($value);
	}

	/**
	 * @return int when the row was last written, in Unix seconds.
	 */
	public function getUpdatedTime(): int
	{
		return $this->_updatedTime;
	}

	/**
	 * @param mixed $value when the row was last written.
	 */
	public function setUpdatedTime($value): void
	{
		$this->_updatedTime = TPropertyValue::ensureInteger($value);
	}
}
