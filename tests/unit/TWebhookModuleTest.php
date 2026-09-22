<?php

use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\TTokenWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookModule;
use Belisoful\Prado\Web\Webhooks\TWebhookSender;
use Prado\Exceptions\TConfigurationException;
use Prado\Prado;
use Prado\Util\TPluginModule;
use Prado\Xml\TXmlDocument;

/**
 * The module with the page-service mount taken out of the way. TPluginModule::init attaches
 * to the application, which a unit test does not have; nothing below is about that mount.
 */
class TestWebhookModule extends TWebhookModule
{
	public function getPluginPagesPath()
	{
		return null;
	}
}

class TWebhookModuleTest extends PHPUnit\Framework\TestCase
{
	private TWebhookModule $_module;

	protected function setUp(): void
	{
		$this->_module = new TWebhookModule();
	}

	private function xml(string $markup): TXmlDocument
	{
		$document = new TXmlDocument();
		$document->loadFromString($markup);

		return $document;
	}

	public function testIsAPluginModule()
	{
		$this->assertInstanceOf(TPluginModule::class, $this->_module);
	}

	public function testItOwnsASenderBuiltOnFirstUse()
	{
		$sender = $this->_module->getSender();

		$this->assertInstanceOf(TWebhookSender::class, $sender);
		$this->assertSame($sender, $this->_module->getSender());
	}

	public function testASenderCanBeSubstituted()
	{
		$sender = new TWebhookSender();
		$this->_module->setSender($sender);

		$this->assertSame($sender, $this->_module->getSender());
	}

	public function testSendGoesThroughTheSender()
	{
		$sender = new class () extends TWebhookSender {
			public array $calls = [];

			public function send(mixed $targets, mixed $payload, ?string $event = null): array
			{
				$this->calls[] = [$targets, $payload, $event];

				return ['delivery'];
			}
		};
		$this->_module->setSender($sender);

		$result = $this->_module->send('https://example.com/hook', ['id' => 1], 'invoice.paid');

		$this->assertSame(['delivery'], $result);
		$this->assertSame([['https://example.com/hook', ['id' => 1], 'invoice.paid']], $sender->calls);
	}

	public function testTheSettingsAreTheSendersSettings()
	{
		$this->_module->setTimeout(5);
		$this->_module->setMaxAttempts(7);
		$this->_module->setRetryDelay(250);
		$this->_module->setRetryStatusCodes('500, 503');
		$this->_module->setUserAgent('MyApp/2.0');

		$sender = $this->_module->getSender();
		$this->assertSame(5, $sender->getTimeout());
		$this->assertSame(7, $sender->getMaxAttempts());
		$this->assertSame(250, $sender->getRetryDelay());
		$this->assertSame([500, 503], $sender->getRetryStatusCodes());
		$this->assertSame('MyApp/2.0', $sender->getUserAgent());

		// And readable back through the module, which is what a configuration file sets.
		$this->assertSame(5, $this->_module->getTimeout());
		$this->assertSame(7, $this->_module->getMaxAttempts());
		$this->assertSame(250, $this->_module->getRetryDelay());
		$this->assertSame([500, 503], $this->_module->getRetryStatusCodes());
		$this->assertSame('MyApp/2.0', $this->_module->getUserAgent());
	}

	public function testThePradoPropertyConventionReachesThem()
	{
		$this->_module->Timeout = 3;

		$this->assertSame(3, $this->_module->Timeout);
		$this->assertSame(3, $this->_module->getSender()->getTimeout());
	}

	public function testTheSignatureIsTheSendersFallback()
	{
		$signature = new TTokenWebhookSignature();
		$this->_module->setSignature($signature);

		$this->assertSame($signature, $this->_module->getSignature());
		$this->assertSame($signature, $this->_module->getSender()->getSignature());
	}

	public function testASignatureIsBuiltFromTheConfiguration()
	{
		$module = new TestWebhookModule();
		$module->init($this->xml(
			'<module id="belisoful/prado-webhooks" Timeout="5" MaxAttempts="2">'
			. '<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"'
			. ' Secret="s3cret" TimestampHeader="X-Webhook-Timestamp" PayloadFormat="{timestamp}.{body}" />'
			. '</module>'
		));

		$signature = $module->getSignature();
		$this->assertInstanceOf(THmacWebhookSignature::class, $signature);
		$this->assertSame('s3cret', $signature->getSecret());
		$this->assertSame('X-Webhook-Timestamp', $signature->getTimestampHeader());
		$this->assertSame('{timestamp}.{body}', $signature->getPayloadFormat());
	}

	public function testASignatureIsBuiltFromAPhpConfiguration()
	{
		$module = new TestWebhookModule();
		$module->init([
			'signature' => [
				'class' => THmacWebhookSignature::class,
				'properties' => ['Secret' => 's3cret', 'Prefix' => 'sha256='],
			],
		]);

		$signature = $module->getSignature();
		$this->assertInstanceOf(THmacWebhookSignature::class, $signature);
		$this->assertSame('s3cret', $signature->getSecret());
		$this->assertSame('sha256=', $signature->getPrefix());
	}

	public function testNoSignatureChildLeavesTheSenderUnsigned()
	{
		$module = new TestWebhookModule();
		$module->init($this->xml('<module id="belisoful/prado-webhooks" />'));

		$this->assertNull($module->getSignature());
	}

	public function testASignatureChildThatCannotSignIsRefused()
	{
		$module = new TestWebhookModule();

		$this->expectException(TConfigurationException::class);
		$module->init($this->xml(
			'<module id="belisoful/prado-webhooks"><signature class="Prado\TComponent" /></module>'
		));
	}

	public function testTheDeclaredVersionLooksLikeAVersion()
	{
		$this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/', TWebhookModule::VERSION);
	}

	public function testTheVersionFallsBackToTheDeclaredOneInAWorkingCopy()
	{
		// Composer reports an untagged root checkout as 1.0.0+no-version-set, which is worse
		// than saying nothing, so the declared version answers while this package is the root.
		$this->assertSame(TWebhookModule::VERSION, TWebhookModule::getVersion());
		$this->assertStringNotContainsString('no-version-set', TWebhookModule::getVersion());
	}

	public function testTheModuleIdIsThePackageName()
	{
		$this->assertSame(TWebhookModule::PACKAGE_NAME, TWebhookModule::DEFAULT_MODULE_ID);
	}

	public function testThePackagePublishesNoPages()
	{
		// TPluginModule mounts a package's Pages directory onto TPageService, which makes
		// every file in it a URL in the consuming application. This package has nothing to
		// put there, and a page shipped by accident is a page nobody asked to publish.
		$this->assertDirectoryDoesNotExist(dirname(__DIR__, 2) . '/src/Pages');
	}

	public function testTheShortNameResolvesThroughTheClassMap()
	{
		// Prado::using() aliases the short name on first resolution and then returns the short
		// name itself, so the alias, not the return value, is what tells the truth here.
		Prado::usingClass('TWebhookModule');
		$this->assertSame(TWebhookModule::class, (new ReflectionClass('TWebhookModule'))->getName());
	}
}
