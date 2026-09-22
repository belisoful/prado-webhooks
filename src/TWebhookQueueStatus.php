<?php

/**
 * TWebhookQueueStatus class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\Exceptions\TInvalidDataValueException;

/**
 * TWebhookQueueStatus enum.
 *
 * Where a queued delivery stands. A delivery is `Pending` from the moment it is queued
 * until it is either accepted or has run out of attempts; there is no separate "in flight"
 * state, because a delivery being attempted is one that has a lease on it rather than one
 * in a different condition -- which is what lets a runner that dies mid-attempt have its
 * work picked up again when the lease expires.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
enum TWebhookQueueStatus: string
{
	/** Waiting to be attempted, or waiting out the backoff after a failed attempt. */
	case Pending = 'pending';

	/** Accepted by the target. Kept only when the queue is told to keep them. */
	case Delivered = 'delivered';

	/** Out of attempts. Kept for inspection and replay until pruned. */
	case Failed = 'failed';

	/**
	 * Coerces a property or column value to a status.
	 * @param mixed $value a status, or its name in any case.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when $value names no status.
	 * @return self the status $value names.
	 */
	public static function ensure(mixed $value): self
	{
		if ($value instanceof self) {
			return $value;
		}
		$status = self::tryFrom(strtolower(trim((string) $value)));
		if ($status === null) {
			throw new TInvalidDataValueException('webhooks_queue_status_invalid', (string) $value);
		}

		return $status;
	}
}
