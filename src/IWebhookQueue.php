<?php

/**
 * IWebhookQueue interface file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

/**
 * IWebhookQueue interface.
 *
 * Where deliveries wait when they are not sent inside the request that raised them. The
 * contract is the small one a durable at-least-once queue needs, and no more.
 *
 * **Claiming is a lease, not a lock.** {@see claim} hands out work for a fixed period and
 * stamps each row with a token. A runner that finishes reports back; a runner that is
 * killed, times out, or is deployed over in the middle of an attempt simply stops, and the
 * lease expires so another runner picks the delivery up. That is what makes the guarantee
 * at-least-once rather than at-most-once: a delivery can be sent twice if a runner dies
 * after the receiver accepted it but before the row was updated, which is why every
 * delivery carries a stable id for the receiver to deduplicate on.
 *
 * An implementation must be safe against several runners claiming at once, which is the
 * normal arrangement when a cron fires faster than a batch drains. That means two things,
 * and the second is easy to miss:
 *
 * - {@see claim} hands a delivery to one runner only.
 * - {@see succeed}, {@see reschedule} and {@see abandon} take effect only while the caller
 *   still holds the lease it claimed under. A runner whose lease expired mid-attempt must not
 *   be able to write over whoever holds the delivery now, or delete the row from under it --
 *   the first would let a third runner in alongside, and the second would drop a delivery
 *   that was still being made. {@see TWebhookQueueItem::getLeaseToken} is what a claimed
 *   delivery carries for this.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
interface IWebhookQueue
{
	/**
	 * Stores a delivery to be attempted later, and gives it its {@see TWebhookQueueItem::getId Id}.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the delivery to store.
	 * @throws \Prado\Exceptions\TConfigurationException when the queue is not usable.
	 */
	public function enqueue(TWebhookQueueItem $item): void;

	/**
	 * Takes a lease on up to $limit deliveries that are due.
	 * @param int $limit how many to take at most.
	 * @param int $leaseSeconds how long the lease lasts. It has to outlast the time an
	 *   attempt can take, or a second runner will start the same delivery while the first
	 *   is still sending it.
	 * @throws \Prado\Exceptions\TConfigurationException when the queue is not usable.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem[] the claimed deliveries, due
	 *   first.
	 */
	public function claim(int $limit, int $leaseSeconds): array;

	/**
	 * Records that the target accepted the delivery.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 */
	public function succeed(TWebhookQueueItem $item): void;

	/**
	 * Returns a delivery to the queue to be attempted again, and releases its lease.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery,
	 *   carrying its updated attempt count and last status.
	 * @param int $delaySeconds how long to wait before it is due again.
	 */
	public function reschedule(TWebhookQueueItem $item, int $delaySeconds): void;

	/**
	 * Records that a delivery has run out of attempts. The row is kept, so it can be looked
	 * at and replayed, until {@see prune} removes it.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 */
	public function abandon(TWebhookQueueItem $item): void;

	/**
	 * Removes finished deliveries older than a given age.
	 * @param int $age how old, in seconds, a finished delivery must be to be removed.
	 * @return int how many were removed.
	 */
	public function prune(int $age): int;

	/**
	 * @param null|\Belisoful\Prado\Web\Webhooks\TWebhookQueueStatus $status the status to
	 *   count, or null for every delivery held.
	 * @return int how many deliveries the queue holds.
	 */
	public function getCount(?TWebhookQueueStatus $status = null): int;
}
