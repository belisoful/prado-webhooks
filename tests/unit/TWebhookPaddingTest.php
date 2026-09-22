<?php

use Belisoful\Prado\Web\Webhooks\TWebhookPadding;
use Prado\Exceptions\TInvalidDataValueException;

class TWebhookPaddingTest extends PHPUnit\Framework\TestCase
{
	public function testEnsurePassesAPaddingThrough()
	{
		$this->assertSame(TWebhookPadding::Pss, TWebhookPadding::ensure(TWebhookPadding::Pss));
	}

	public function testEnsureReadsANameInAnyCase()
	{
		$this->assertSame(TWebhookPadding::Pkcs1, TWebhookPadding::ensure('PKCS1'));
		$this->assertSame(TWebhookPadding::Pss, TWebhookPadding::ensure('  Pss '));
	}

	public function testEnsureRejectsAnUnknownName()
	{
		$this->expectException(TInvalidDataValueException::class);
		TWebhookPadding::ensure('oaep');
	}
}
