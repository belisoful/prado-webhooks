<?php

/**
 * TWebhookPruneCronTask class file
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
 * TWebhookPruneCronTask class.
 *
 * Removes finished deliveries from the queue once they are old enough to have stopped being
 * interesting.
 *
 * ```xml
 * <module id="cron" class="Prado\Util\Cron\TCronModule">
 *		<job Name="webhooks-prune" Schedule="0 4 * * *"
 *			Task="Belisoful\Prado\Web\Webhooks\TWebhookPruneCronTask" MaxAge="2592000" />
 * </module>
 * ```
 *
 * A delivery that runs out of attempts is kept rather than deleted, so somebody can see
 * what happened and replay it. That is only useful while somebody might: without this task
 * the table keeps every failure the application has ever had, and with
 * {@see TDbWebhookQueue::setKeepDelivered KeepDelivered} on it keeps every success too.
 *
 * Pending deliveries are never pruned, however old. A delivery still waiting is work the
 * application asked for, and age is not a reason to throw it away.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TWebhookPruneCronTask extends TCronTask
{
	use TWebhookTaskTrait;

	/** @var int how old a finished delivery must be to be removed: 30 days. */
	public const DEFAULT_MAX_AGE = 2592000;

	/** @var int how old a finished delivery must be to be removed, in seconds */
	private int $_maxAge = self::DEFAULT_MAX_AGE;

	/**
	 * Removes the finished deliveries that are old enough.
	 * @param \Prado\Util\Cron\TCronModule $cronModule the module running this task.
	 * @throws \Prado\Exceptions\TConfigurationException when no queue is configured.
	 * @return int how many were removed.
	 */
	public function execute($cronModule)
	{
		return $this->getWebhookModule()->getQueue()->prune($this->_maxAge);
	}

	/**
	 * @return int how old a finished delivery must be to be removed, in seconds. Defaults to
	 *   {@see DEFAULT_MAX_AGE}.
	 */
	public function getMaxAge(): int
	{
		return $this->_maxAge;
	}

	/**
	 * @param mixed $value the age in seconds; 0 removes every finished delivery.
	 */
	public function setMaxAge($value): void
	{
		$this->_maxAge = max(0, TPropertyValue::ensureInteger($value));
	}
}
