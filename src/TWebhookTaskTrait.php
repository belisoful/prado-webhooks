<?php

/**
 * TWebhookTaskTrait class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\Exceptions\TConfigurationException;

/**
 * TWebhookTaskTrait trait.
 *
 * Finds the webhook module a cron task works on. The tasks do unrelated things -- one sends,
 * one deletes -- so they do not share a base class, only this.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
trait TWebhookTaskTrait
{
	/**
	 * Returns the module named by `ModuleId`, defaulting to the package's own id so a task
	 * configured with nothing but a schedule still finds it.
	 *
	 * The default is applied to the lookup, not written to `ModuleId`: resolving a module is
	 * a read, and a getter that changes the task's configuration as a side effect would have
	 * a task persisted by the cron module come back different from how it was configured.
	 *
	 * @throws \Prado\Exceptions\TConfigurationException when the id names something that is
	 *   not a {@see \Belisoful\Prado\Web\Webhooks\TWebhookModule}.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookModule the module.
	 */
	public function getWebhookModule(): TWebhookModule
	{
		$id = $this->getModuleId();
		$module = $id === null
			? $this->getApplication()?->getModule(TWebhookModule::DEFAULT_MODULE_ID)
			: $this->getModule();
		if (!($module instanceof TWebhookModule)) {
			throw new TConfigurationException(
				'webhooks_task_module_invalid',
				(string) ($id ?? TWebhookModule::DEFAULT_MODULE_ID),
				static::class
			);
		}

		return $module;
	}
}
