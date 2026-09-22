<?php

/**
 * Composer-extension integration checks.
 *
 * The unit suite registers the extension's error messages and class map by hand, so it cannot
 * prove that a real `composer require` wires them up. This script runs inside a throwaway
 * consumer project that installed the extension through Composer and asserts the three things
 * `composer.json`'s `extra.prado` section promises:
 *
 * - `error-messages` registers `config/errorMessages.txt`, so the package's codes resolve to text.
 * - `class-map` registers the Prado3 short names, so `TWebhookModule` resolves to its FQN.
 * - `bootstrap` names the module, so `<module id="belisoful/prado-webhooks"/>` boots it.
 *
 * Each mode runs in its own process because a Prado application is a per-process singleton.
 *
 *     php verify-extension-install.php <capture|boot> <consumer-dir>
 *
 * Exits non-zero with a message on the first failed check.
 */

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TDbWebhookQueue;
use Belisoful\Prado\Web\Webhooks\TWebhookCronTask;
use Belisoful\Prado\Web\Webhooks\TWebhookModule;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Belisoful\Prado\Web\Webhooks\TWebhookService;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TException;
use Prado\Prado;
use Prado\TApplication;
use Prado\TApplicationConfiguration;

$mode = $argv[1] ?? '';
$dir = $argv[2] ?? '';
if ($mode === '' || $dir === '' || !is_file($dir . '/vendor/autoload.php')) {
	fwrite(STDERR, "usage: verify-extension-install.php <capture|boot> <consumer-dir>\n");
	exit(2);
}
require $dir . '/vendor/autoload.php';
chdir($dir);

$package = 'belisoful/prado-webhooks';
$checks = 0;
$check = function (bool $ok, string $what) use (&$checks): void {
	$checks++;
	if (!$ok) {
		fwrite(STDERR, "FAIL: {$what}\n");
		exit(1);
	}
	fwrite(STDERR, "  ok: {$what}\n");
};

$application = new TApplication($dir . '/protected', false);
$configuration = new TApplicationConfiguration();
$configuration->captureComposerExtensions();

if ($mode === 'capture') {
	$messages = $configuration->getErrorMessages();
	$check(
		count(array_filter($messages, fn ($f) => str_ends_with($f, 'config/errorMessages.txt'))) === 1,
		'extra.prado.error-messages registered the extension message file'
	);

	$map = $configuration->getClassMap();
	$declared = json_decode(
		(string) file_get_contents($dir . '/vendor/' . $package . '/config/classes.json'),
		true,
		512,
		JSON_THROW_ON_ERROR
	);
	$check($map !== [], 'extra.prado.class-map registered a class map');
	foreach ($declared as $short => $fqn) {
		if (($map[$short] ?? null) !== $fqn) {
			$check(false, "class map entry {$short} => {$fqn}");
		}
	}
	$check(true, 'every class-map entry maps to its declared FQN');

	$check(
		$configuration->getComposerExtensionClass($package) === TWebhookModule::class,
		'extra.prado.bootstrap names TWebhookModule'
	);
	// The consumer requires only this extension; the framework has to arrive through it.
	$check(
		is_dir($dir . '/vendor/pradosoft/prado'),
		'pradosoft/prado was installed transitively, without the consumer requiring it'
	);
	$check(class_exists(TApplication::class), 'the transitively-installed framework autoloads');

	foreach ($messages as $file) {
		TException::addMessageFile($file);
	}
	Prado::registerClassMap($map);

	$exception = new TConfigurationException('webhooks_secret_required', 'THmacWebhookSignature');
	$check(
		$exception->getMessage() !== 'webhooks_secret_required',
		'an extension error code resolves to its message text'
	);
	$check(
		Prado::usingClass('TWebhookModule') === TWebhookModule::class,
		'the Prado3 short name TWebhookModule resolves through the class map'
	);
	$check(
		Prado::usingClass('TWebhookService') === TWebhookService::class,
		'the inbound service resolves through the class map as well as the outbound module'
	);
} else {
	$configuration->loadFromFile($dir . '/protected/application.xml');
	$application->applyConfiguration($configuration);

	$module = $application->getModule($package);
	$check($module instanceof TWebhookModule, 'the bootstrap module booted under its package id');
	$check($module->getTimeout() === 5, 'the module element applied Timeout to the sender');
	$check($module->getMaxAttempts() === 2, 'the module element applied MaxAttempts to the sender');

	// The <signature> child is built by the module's own init(), which only runs on a real
	// boot: the unit suite constructs it by hand instead.
	$signature = $module->getSignature();
	$check($signature instanceof THmacWebhookSignature, 'the <signature> child became the sender signature');
	$check($signature->getSecret() === 's3cret', 'the signature element applied Secret');
	$request = new TWebhookRequest('POST', '{"id":1}');
	$check(
		$signature->verify($request->withHeaders($signature->sign($request))),
		'the booted signature signs what it verifies'
	);

	// A cron task configured with nothing but a schedule has to find the module on its own,
	// and it looks for it under the package name -- which only a real boot can confirm.
	$task = new TWebhookCronTask();
	$check($task->getWebhookModule() === $module, 'a cron task finds the webhook module by its package id');
	// The configured queue, resolved from its module id through a booted application -- the
	// path a unit test cannot take, since it has no application to register modules with.
	$check($module->getHasQueue(), 'QueueID is configured');
	$queue = $module->getQueue();
	$check($queue instanceof TDbWebhookQueue, 'QueueID resolved to the queue module');
	$check(
		$queue->getDbConnection() === $application->getModule('db')->getDbConnection(),
		'ConnectionID resolved to the data source module'
	);

	// And it works end to end: the table is created, a delivery is stored, and it comes back.
	$item = $module->queue('https://example.com/hooks/prado', ['invoice' => 1], 'invoice.paid')[0];
	$check($queue->getCount() === 1, 'a queued delivery was written to the table');
	$claimed = $queue->claim(10, 60);
	$check(count($claimed) === 1, 'it can be claimed back');
	$check($claimed[0]->getDeliveryId() === $item->getDeliveryId(), 'with the delivery id it was queued under');
	$check($claimed[0]->getLeaseToken() !== null, 'holding the lease it was claimed under');

	// Installed as a dependency, so getVersion() takes Composer's answer rather than the
	// declared constant -- the branch no unit test can reach, since there this package is the
	// root. It also catches the two drifting apart.
	$check(
		TWebhookModule::getVersion() === TWebhookModule::VERSION,
		'the installed version matches the declared one: ' . TWebhookModule::getVersion()
	);
}

fwrite(STDERR, "{$checks} checks passed ({$mode})\n");
