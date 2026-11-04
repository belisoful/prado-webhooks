<?php

/**
 * Asserts which error code an expected exception carries.
 *
 * `expectException()` checks the class alone, and every configuration error in the package is
 * a `TConfigurationException`, so a test that expects one passes on the wrong refusal as
 * readily as on the right one. PRADO renders the code's message, not the code, into the
 * exception, and the arguments vary; this matches the rendered message against the code's
 * pattern with each placeholder as a wildcard.
 */
trait WebhookErrorCodeAssertions
{
	/**
	 * Expects the exception the test throws to carry an error code. Call it beside
	 * `expectException()`, which still checks the class.
	 * @param string $code the error code in config/errorMessages.txt.
	 */
	protected function expectErrorCode(string $code): void
	{
		$this->expectExceptionMessageMatches(self::errorMessageRegex($code));
	}

	/**
	 * Asserts that a callback throws an exception carrying an error code.
	 * @param string $code the error code in config/errorMessages.txt.
	 * @param callable $callback what should throw.
	 * @return \Throwable the exception, for further assertions.
	 */
	protected function assertThrowsErrorCode(string $code, callable $callback): \Throwable
	{
		try {
			$callback();
		} catch (\Throwable $e) {
			$this->assertMatchesRegularExpression(self::errorMessageRegex($code), $e->getMessage(), "the exception carries {$code}");

			return $e;
		}
		$this->fail("Expected an exception carrying {$code}; nothing was thrown.");
	}

	/**
	 * @param string $code the error code.
	 * @return string a regular expression matching the code's message with any arguments.
	 */
	private static function errorMessageRegex(string $code): string
	{
		static $messages = null;
		if ($messages === null) {
			$messages = [];
			foreach (file(__DIR__ . '/../../config/errorMessages.txt', FILE_IGNORE_NEW_LINES) as $line) {
				if (str_contains($line, '=') && !str_starts_with(trim($line), '#')) {
					[$key, $message] = explode('=', $line, 2);
					$messages[trim($key)] = trim($message);
				}
			}
		}
		if (!isset($messages[$code])) {
			throw new LogicException("No message is defined for {$code}.");
		}
		// ICU renders a doubled apostrophe as one; everything else in these messages is literal.
		$parts = preg_split('/\{\s*\d+\s*\}/', $messages[$code]);
		$parts = array_map(static fn ($part) => preg_quote(str_replace("''", "'", $part), '/'), $parts);

		return '/^' . implode('.*', $parts) . '$/s';
	}
}
