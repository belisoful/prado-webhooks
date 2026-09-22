<?php

/**
 * Package standard checks.
 *
 * These tests belong to every extension built from this skeleton, and they are the reason the
 * conventions hold: each one fails the build for a mistake that is otherwise found only when an
 * application tries to load the package. They are deliberately written against the package's own
 * files rather than against any particular class, so they keep working as a package grows and
 * need no maintenance when classes are added.
 *
 * Copy this file unchanged into a new extension. Nothing in it names this package.
 */

use Prado\Exceptions\TException;
use Prado\Prado;
use Prado\TModule;

class PackageStandardTest extends PHPUnit\Framework\TestCase
{
	/** @var string the package root directory */
	private static string $root;

	/** @var array the decoded composer.json */
	private static array $composer;

	public static function setUpBeforeClass(): void
	{
		self::$root = dirname(__DIR__, 3);
		self::$composer = json_decode(
			(string) file_get_contents(self::$root . '/composer.json'),
			true,
			512,
			JSON_THROW_ON_ERROR
		);
	}

	/**
	 * @return string the single PSR-4 root namespace of the package, with a trailing separator
	 */
	private function psr4Root(): string
	{
		$map = self::$composer['autoload']['psr-4'] ?? [];
		$this->assertCount(1, $map, 'the package declares exactly one PSR-4 root namespace');
		$dir = reset($map);
		$this->assertSame('src', rtrim((string) $dir, '/'), 'the PSR-4 root maps to src/');

		return (string) key($map);
	}

	/**
	 * @return array<string, string> every PHP file under src/, as absolute path => path relative to src/
	 */
	private function sourceFiles(): array
	{
		$base = self::$root . '/src';
		if (!is_dir($base)) {
			return [];
		}
		$files = [];
		$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS));
		foreach ($iterator as $file) {
			if ($file->isFile() && $file->getExtension() === 'php') {
				$path = $file->getPathname();
				$files[$path] = ltrim(str_replace($base, '', $path), DIRECTORY_SEPARATOR);
			}
		}
		ksort($files);

		return $files;
	}

	/**
	 * Reads the type each source file declares.
	 * @return array<string, array{kind: string, name: string, namespace: string, relative: string}>
	 */
	private function declaredTypes(): array
	{
		$types = [];
		foreach ($this->sourceFiles() as $path => $relative) {
			$code = (string) file_get_contents($path);
			if (!preg_match('/^namespace\s+([^;]+);/m', $code, $ns)) {
				continue;
			}
			if (!preg_match('/^(?:abstract\s+|final\s+|readonly\s+)*(class|interface|trait|enum)\s+(\w+)/m', $code, $type)) {
				continue;
			}
			$types[$path] = [
				'kind' => $type[1],
				'name' => $type[2],
				'namespace' => trim($ns[1]),
				'relative' => $relative,
			];
		}

		return $types;
	}

	/**
	 * @return array<string, string> the declared short name => fully qualified name class map
	 */
	private function classMap(): array
	{
		$file = self::$composer['extra']['prado']['class-map'] ?? null;
		$this->assertIsString($file, 'composer.json declares extra.prado.class-map');

		return json_decode((string) file_get_contents(self::$root . '/' . $file), true, 512, JSON_THROW_ON_ERROR);
	}

	/**
	 * @return array<string, string> the declared error message code => message text
	 */
	private function errorMessages(): array
	{
		$file = self::$composer['extra']['prado']['error-messages'] ?? null;
		$this->assertIsString($file, 'composer.json declares extra.prado.error-messages');
		$messages = [];
		foreach (file(self::$root . '/' . $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
			if (preg_match('/^([a-z][a-z0-9_]*)\s*=\s*(.*)$/', trim($line), $match)) {
				$messages[$match[1]] = trim($match[2]);
			}
		}

		return $messages;
	}

	/**
	 * @return array<string, string> every error code raised in src/, as code => file it appears in
	 */
	private function usedErrorCodes(): array
	{
		$used = [];
		foreach ($this->sourceFiles() as $path => $relative) {
			$code = (string) file_get_contents($path);
			if (preg_match_all('/new\s+\\\\?[\w\\\\]*Exception\s*\(\s*[\'"]([a-z][a-z0-9_]*)[\'"]/', $code, $matches)) {
				foreach ($matches[1] as $errorCode) {
					$used[$errorCode] = $relative;
				}
			}
		}

		return $used;
	}

	public function testComposerMetadataFollowsTheStandard()
	{
		$this->assertMatchesRegularExpression(
			'#^[a-z0-9]([a-z0-9._-]*)/[a-z0-9]([a-z0-9._-]*)$#',
			(string) (self::$composer['name'] ?? ''),
			'the package name is a valid vendor/package pair'
		);
		$this->assertSame('prado4-extension', self::$composer['type'] ?? null, 'the package type is prado4-extension');
		$this->assertNotEmpty(self::$composer['description'] ?? '', 'the package has a description');
		$this->assertNotEmpty(self::$composer['license'] ?? '', 'the package declares a license');
		$this->assertArrayHasKey('pradosoft/prado', self::$composer['require'] ?? [], 'the package requires the framework');
		$this->assertMatchesRegularExpression(
			'/>=\s*8\.1/',
			(string) (self::$composer['require']['php'] ?? ''),
			'the package requires PHP 8.1 or newer'
		);
		foreach (['phpunit/phpunit', 'phpstan/phpstan', 'friendsofphp/php-cs-fixer'] as $tool) {
			$this->assertArrayHasKey($tool, self::$composer['require-dev'] ?? [], "the package develops against {$tool}");
		}
		foreach (['lint', 'fix', 'cs', 'stan', 'unittest', 'fulltest'] as $script) {
			$this->assertArrayHasKey($script, self::$composer['scripts'] ?? [], "composer {$script} is defined");
		}
	}

	public function testComposerDeclaresTheModernPradoExtraSection()
	{
		$this->assertArrayHasKey('prado', self::$composer['extra'] ?? [], 'extension settings live under extra.prado');
		$this->assertArrayNotHasKey(
			'bootstrap',
			self::$composer['extra'] ?? [],
			'the legacy un-nested extra.bootstrap is deprecated in favour of extra.prado.bootstrap'
		);

		foreach (['error-messages', 'class-map'] as $key) {
			$value = self::$composer['extra']['prado'][$key] ?? null;
			$this->assertIsString($value, "extra.prado.{$key} names a file");
			$this->assertFileExists(self::$root . '/' . $value, "the file extra.prado.{$key} names exists");
		}
	}

	public function testBootstrapClassExistsAndIsAModule()
	{
		$bootstrap = self::$composer['extra']['prado']['bootstrap'] ?? null;
		if ($bootstrap === null) {
			$this->markTestSkipped('the package declares no bootstrap module');
		}
		$this->assertTrue(class_exists($bootstrap), "the bootstrap class {$bootstrap} autoloads");
		$this->assertTrue(
			is_subclass_of($bootstrap, TModule::class),
			"the bootstrap class {$bootstrap} is a Prado module"
		);
		$this->assertStringStartsWith(
			$this->psr4Root(),
			$bootstrap,
			'the bootstrap class lives under the PSR-4 root namespace'
		);
	}

	public function testEverySourceFileNamespaceMatchesItsPathUnderPsr4()
	{
		$root = $this->psr4Root();
		foreach ($this->declaredTypes() as $path => $type) {
			$expected = rtrim($root . str_replace(DIRECTORY_SEPARATOR, '\\', dirname($type['relative'])), '\\.');
			$this->assertSame(
				$expected,
				$type['namespace'],
				"the namespace of {$type['relative']} matches its directory under the PSR-4 root"
			);
			$this->assertSame(
				$type['name'] . '.php',
				basename($type['relative']),
				"the file name of {$type['relative']} matches the type it declares"
			);
		}
	}

	public function testTypeNamesFollowThePrefixConvention()
	{
		foreach ($this->declaredTypes() as $type) {
			$prefix = $type['kind'] === 'interface' ? 'I' : 'T';
			$this->assertMatchesRegularExpression(
				'/^' . $prefix . '[A-Z]/',
				$type['name'],
				"{$type['kind']} {$type['name']} starts with {$prefix} and continues in PascalCase"
			);
		}
	}

	public function testEveryDeclaredTypeIsInTheClassMap()
	{
		$map = $this->classMap();
		foreach ($this->declaredTypes() as $type) {
			if ($type['kind'] === 'trait') {
				continue; // A trait has no short name to resolve; it is only ever used by name.
			}
			$fqn = $type['namespace'] . '\\' . $type['name'];
			$this->assertArrayHasKey(
				$type['name'],
				$map,
				"the class map lists {$type['name']}, so Prado3 short names resolve to it"
			);
			$this->assertSame($fqn, $map[$type['name']], "the class map entry for {$type['name']} names its FQN");
		}
	}

	public function testEveryClassMapEntryResolves()
	{
		foreach ($this->classMap() as $short => $fqn) {
			$this->assertTrue(
				class_exists($fqn) || interface_exists($fqn) || enum_exists($fqn),
				"the class map entry {$short} => {$fqn} names a type that autoloads"
			);
		}
	}

	public function testClassMapShortNamesResolveToTheirClass()
	{
		foreach ($this->classMap() as $short => $fqn) {
			// Prado::using() aliases the short name to the FQN the first time it resolves one,
			// and afterwards returns the short name it was given. Comparing its return value
			// would therefore depend on what ran first; the alias itself is the real result.
			Prado::usingClass($short);
			$this->assertTrue(
				class_exists($short, false) || interface_exists($short, false),
				"the Prado3 short name {$short} resolves through the registered class map"
			);
			$this->assertSame(
				$fqn,
				(new ReflectionClass($short))->getName(),
				"the Prado3 short name {$short} resolves to {$fqn}"
			);
		}
	}

	public function testEveryErrorCodeRaisedInSourceHasAMessage()
	{
		$messages = $this->errorMessages();
		foreach ($this->usedErrorCodes() as $code => $file) {
			$this->assertArrayHasKey($code, $messages, "the error code {$code}, raised in {$file}, has message text");
			$this->assertNotSame('', $messages[$code], "the message for {$code} is not empty");
		}
	}

	public function testNoErrorMessageIsDeclaredButUnused()
	{
		$used = $this->usedErrorCodes();
		foreach (array_keys($this->errorMessages()) as $code) {
			$this->assertArrayHasKey(
				$code,
				$used,
				"the message {$code} is raised somewhere in src/ (remove it, or the code that raised it came back)"
			);
		}
	}

	public function testErrorMessageFileHasNoDuplicateKeys()
	{
		$file = self::$root . '/' . self::$composer['extra']['prado']['error-messages'];
		$seen = [];
		foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $number => $line) {
			if (preg_match('/^([a-z][a-z0-9_]*)\s*=/', trim($line), $match)) {
				$this->assertArrayNotHasKey(
					$match[1],
					$seen,
					"the message key {$match[1]} on line " . ($number + 1) . ' is declared only once'
				);
				$seen[$match[1]] = true;
			}
		}
	}

	public function testDeclaredErrorMessagesResolveThroughTheFramework()
	{
		foreach (array_keys($this->errorMessages()) as $code) {
			$exception = new TException($code);
			$this->assertNotSame(
				$code,
				$exception->getMessage(),
				"the code {$code} resolves to message text rather than to itself"
			);
		}
	}

	public function testEverySourceFileCompiles()
	{
		foreach ($this->sourceFiles() as $path => $relative) {
			$output = [];
			$status = 0;
			exec('php -l ' . escapeshellarg($path) . ' 2>&1', $output, $status);
			$this->assertSame(0, $status, "{$relative} compiles: " . implode("\n", $output));
		}
	}
}
