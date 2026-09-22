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
	 * @throws \Prado\Exceptions\TConfigurationException when the id names something that is
	 *   not a {@see \Belisoful\Prado\Web\Webhooks\TWebhookModule}.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookModule the module.
	 */
	public function getWebhookModule(): TWebhookModule
	{
		if ($this->getModuleId() === null) {
			$this->setModuleId(TWebhookModule::DEFAULT_MODULE_ID);
		}
		$module = $this->getModule();
		if (!($module instanceof TWebhookModule)) {
			throw new TConfigurationException('webhooks_task_module_invalid', (string) $this->getModuleId(), static::class);
		}

		return $module;
	}
}
