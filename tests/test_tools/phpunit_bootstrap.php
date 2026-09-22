<?php

/**
 * Common settings for all unit tests of the extension.
 *
 * Autoloads the framework and the extension through Composer's PSR-4 map, then registers the
 * extension's error message file (so exception codes resolve to text) and its Prado3 short-name
 * class map -- the two things `extra.prado.error-messages` and `extra.prado.class-map` register
 * for an installed application. The unit suite does this by hand because nothing has run a real
 * `composer require`; tests/integration proves the installed path separately.
 */

require_once(__DIR__ . '/../../vendor/autoload.php');

// Base classes the unit suite extends. PHPUnit loads only files named *Test.php, and in
// directory order, so a base living among them would not reliably be there first.
require_once(__DIR__ . '/TWebhookQueueDriverTestCase.php');

\Prado\Exceptions\TException::addMessageFile(__DIR__ . '/../../config/errorMessages.txt');
\Prado\Prado::registerClassMap(
	json_decode((string) file_get_contents(__DIR__ . '/../../config/classes.json'), true, 512, JSON_THROW_ON_ERROR)
);
