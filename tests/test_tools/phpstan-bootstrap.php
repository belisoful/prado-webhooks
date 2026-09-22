<?php

/**
 * Common bootstrap for PHPStan static analysis of the extension.
 *
 * Autoloads the framework and the extension through Composer's PSR-4 map, which is what lets
 * PHPStan resolve the PRADO classes the package extends.
 */

require_once(__DIR__ . '/../../vendor/autoload.php');
