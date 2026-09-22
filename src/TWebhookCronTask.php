<?php

/**
 * TWebhookCronTask class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\TPropertyValue;
use Prado\Util\Cron\TCronModule;
use Prado\Util\Cron\TCronTask;

/**
 * TWebhookCronTask class.
 *
 * Sends the deliveries waiting in the queue. This is the half of guaranteed delivery that
 * runs outside a request: {@see TWebhookModule::queue} writes a delivery down and returns
 * immediately, and this picks it up however long later.
 *
 * ```xml
 * <module id="cron" class="Prado\Util\Cron\TCronModule">
 *		<job Name="webhooks" Schedule="* * * * *"
 *			Task="Belisoful\Prado\Web\Webhooks\TWebhookCronTask" />
 * </module>
 * ```
 *
 * with PRADO's cron itself run once a minute from the system crontab:
 *
 * ```
 * * * * * * php /path/to/vendor/bin/prado-cli app /path/to/app/ cron
 * ```
 *
 * ## Choosing the numbers
 *
 * One run drains up to {@see setBatchSize BatchSize} deliveries, one attempt each. The
 * retry cadence is the queue's, not the sender's: a delivery that fails goes back with a
 * doubling delay and is picked up by a later run, so `MaxAttempts` on the sender should
 * stay small -- an attempt here is already a retry.
 *
 * A run has to finish inside the schedule it is on, or runs overlap. The worst case is
 * `BatchSize` times the sender's `Timeout`, so a batch of 50 against a 10-second timeout is
 * potentially eight minutes of work on a once-a-minute schedule. Either keep the product
 * under the interval, or accept overlapping runs -- which is safe, because
 * {@see setLeaseSeconds LeaseSeconds} keeps two runs off the same delivery, but is only
 * safe while the lease outlasts an attempt.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TWebhookCronTask extends TCronTask
{
	use TWebhookTaskTrait;

	/** @var int how many deliveries one run takes. */
	public const DEFAULT_BATCH_SIZE = 20;

	/** @var int how long a run holds the deliveries it took, in seconds. */
	public const DEFAULT_LEASE_SECONDS = 300;

	/** @var int how many deliveries one run takes */
	private int $_batchSize = self::DEFAULT_BATCH_SIZE;

	/** @var int how long a run holds the deliveries it took, in seconds */
	private int $_leaseSeconds = self::DEFAULT_LEASE_SECONDS;

	/**
	 * Drains a batch of the queue.
	 * @param \Prado\Util\Cron\TCronModule $cronModule the module running this task.
	 * @throws \Prado\Exceptions\TConfigurationException when the module id names something
	 *   that is not the webhook module, or no queue is configured.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookDelivery[] what was attempted.
	 */
	public function execute($cronModule)
	{
		return $this->getWebhookModule()->drain($this->_batchSize, $this->_leaseSeconds);
	}

	/**
	 * @return int how many deliveries one run takes. Defaults to {@see DEFAULT_BATCH_SIZE}.
	 */
	public function getBatchSize(): int
	{
		return $this->_batchSize;
	}

	/**
	 * @param mixed $value the batch size; at least 1.
	 */
	public function setBatchSize($value): void
	{
		$this->_batchSize = max(1, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int how long a run holds the deliveries it took, in seconds. Defaults to
	 *   {@see DEFAULT_LEASE_SECONDS}.
	 */
	public function getLeaseSeconds(): int
	{
		return $this->_leaseSeconds;
	}

	/**
	 * Sets how long a run holds the deliveries it took. It has to outlast a whole batch, not
	 * one attempt: a delivery claimed at the start of a run is still leased while the rest of
	 * the batch is sent, and a lease that runs out in the meantime lets another run start the
	 * same delivery alongside this one.
	 * @param mixed $value the lease in seconds; at least 1.
	 */
	public function setLeaseSeconds($value): void
	{
		$this->_leaseSeconds = max(1, TPropertyValue::ensureInteger($value));
	}
}
