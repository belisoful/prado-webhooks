<?php

use Belisoful\Prado\Web\Webhooks\Signature\TTokenWebhookSignature;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;

class TTokenWebhookSignatureTest extends PHPUnit\Framework\TestCase
{
	private function request(array $headers = [], string $body = '', string $url = '', array $parameters = []): TWebhookRequest
	{
		return new TWebhookRequest('POST', $body, $headers, $url, $parameters);
	}

	private function bearer(string $token = 'sh4red'): TTokenWebhookSignature
	{
		$signature = new TTokenWebhookSignature();
		$signature->setToken($token);

		return $signature;
	}

	public function testVerifiesABearerToken()
	{
		$this->assertTrue($this->bearer()->verify($this->request(['Authorization' => 'Bearer sh4red'])));
	}

	public function testRejectsAnotherToken()
	{
		$this->assertFalse($this->bearer()->verify($this->request(['Authorization' => 'Bearer something-else'])));
	}

	public function testRejectsTheTokenWithoutItsPrefix()
	{
		$this->assertFalse($this->bearer()->verify($this->request(['Authorization' => 'sh4red'])));
	}

	public function testRejectsAMissingHeader()
	{
		$this->assertFalse($this->bearer()->verify($this->request()));
	}

	public function testSignsWhatItVerifies()
	{
		$signature = $this->bearer();
		$headers = $signature->sign($this->request([], '{"any":"body"}'));

		$this->assertSame(['Authorization' => 'Bearer sh4red'], $headers);
		$this->assertTrue($signature->verify($this->request($headers, '{"any":"body"}')));
	}

	public function testTheBodyIsNotAuthenticated()
	{
		// Stated as a test because it is the scheme's defining weakness: the same header
		// authenticates any body at all.
		$signature = $this->bearer();
		$headers = ['Authorization' => 'Bearer sh4red'];

		$this->assertTrue($signature->verify($this->request($headers, '{"amount":1}')));
		$this->assertTrue($signature->verify($this->request($headers, '{"amount":1000000}')));
	}

	public function testABasicCredential()
	{
		$signature = new TTokenWebhookSignature();
		$signature->setToken(base64_encode('provider:s3cret'));
		$signature->setPrefix('Basic ');

		$this->assertTrue($signature->verify($this->request([
			'Authorization' => 'Basic ' . base64_encode('provider:s3cret'),
		])));
	}

	public function testABareTokenInItsOwnHeader()
	{
		$signature = $this->bearer();
		$signature->setHeader('X-Api-Key');
		$signature->setPrefix('');

		$this->assertSame(['X-Api-Key' => 'sh4red'], $signature->sign($this->request()));
		$this->assertTrue($signature->verify($this->request(['x-api-key' => 'sh4red'])));
	}

	public function testATokenInTheQueryString()
	{
		$signature = $this->bearer();
		$signature->setSource('query');
		$signature->setName('key');
		$signature->setPrefix('');

		$this->assertTrue($signature->verify($this->request([], '', 'https://example.com/hook?key=sh4red')));
		$this->assertFalse($this->bearer()->verify($this->request([], '', 'https://example.com/hook?key=other')));
	}

	public function testATokenInARequestParameter()
	{
		$signature = $this->bearer();
		$signature->setSource('parameter');
		$signature->setName('key');
		$signature->setPrefix('');

		$this->assertTrue($signature->verify($this->request([], '', '', ['key' => 'sh4red'])));
	}

	public function testATokenThatDoesNotLiveInAHeaderCannotSign()
	{
		// A signer returns headers; silently dropping the token would send an
		// unauthenticated delivery that looks signed.
		$signature = $this->bearer();
		$signature->setSource('query');
		$signature->setName('key');

		$this->expectException(TConfigurationException::class);
		$signature->sign($this->request());
	}

	public function testDefaults()
	{
		$signature = new TTokenWebhookSignature();

		$this->assertSame('Authorization', $signature->getName());
		$this->assertSame(TTokenWebhookSignature::BEARER_PREFIX, $signature->getPrefix());
		$this->assertSame('', $signature->getToken());
	}

	public function testAnEmptyNameIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TTokenWebhookSignature())->setHeader('');
	}

	public function testVerifyingWithoutATokenIsAConfigurationError()
	{
		$this->expectException(TConfigurationException::class);
		(new TTokenWebhookSignature())->verify($this->request(['Authorization' => 'Bearer anything']));
	}

	public function testSigningWithoutATokenIsAConfigurationError()
	{
		$this->expectException(TConfigurationException::class);
		(new TTokenWebhookSignature())->sign($this->request());
	}
}
