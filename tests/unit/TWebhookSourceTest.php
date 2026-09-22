<?php

use Belisoful\Prado\Web\Webhooks\TWebhookSource;
use Prado\Exceptions\TInvalidDataValueException;

class TWebhookSourceTest extends PHPUnit\Framework\TestCase
{
	public function testEnsurePassesASourceThrough()
	{
		$this->assertSame(TWebhookSource::Query, TWebhookSource::ensure(TWebhookSource::Query));
	}

	public function testEnsureReadsANameInAnyCase()
	{
		$this->assertSame(TWebhookSource::Header, TWebhookSource::ensure('Header'));
		$this->assertSame(TWebhookSource::Parameter, TWebhookSource::ensure(' PARAMETER '));
	}

	public function testEnsureRejectsAnUnknownName()
	{
		$this->expectException(TInvalidDataValueException::class);
		TWebhookSource::ensure('cookie');
	}
}
