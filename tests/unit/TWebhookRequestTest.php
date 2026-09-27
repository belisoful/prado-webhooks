<?php

use Belisoful\Prado\Web\Webhooks\TWebhookRequest;

class TWebhookRequestTest extends PHPUnit\Framework\TestCase
{
	public function testItCarriesWhatASchemeMayLookAt()
	{
		$request = new TWebhookRequest(
			'post',
			'{"id":1}',
			['X-Event' => 'created'],
			'https://example.com/index.php?webhook=github&token=abc',
			['webhook' => 'github', 'token' => 'abc'],
			'192.0.2.7'
		);

		$this->assertSame('POST', $request->getMethod());
		$this->assertSame('{"id":1}', $request->getBody());
		$this->assertSame(['X-Event' => 'created'], $request->getHeaders());
		$this->assertSame('https://example.com/index.php?webhook=github&token=abc', $request->getUrl());
		$this->assertSame('abc', $request->getParameterValue('token'));
		$this->assertSame('192.0.2.7', $request->getRemoteAddress());
	}

	public function testHeaderLookupIgnoresCaseAndParameterLookupDoesNot()
	{
		// Header names are case insensitive by the HTTP spec; parameter names are not.
		$request = new TWebhookRequest('POST', '', ['X-Event' => 'created'], '', ['Token' => 'abc']);

		$this->assertSame('created', $request->getHeader('x-event'));
		$this->assertSame('created', $request->getHeader('X-EVENT'));
		$this->assertNull($request->getHeader('X-Absent'));
		$this->assertSame('abc', $request->getParameterValue('Token'));
		$this->assertNull($request->getParameterValue('token'));
	}

	public function testAHeaderGivenAsAListReadsAsItsFirstValue()
	{
		$request = new TWebhookRequest('POST', '', ['X-Event' => ['created', 'updated']]);

		$this->assertSame('created', $request->getHeader('X-Event'));
	}

	public function testAHeaderThatArrivedAsAnEmptyListIsAbsent()
	{
		// Not an empty string: a scheme comparing against '' would otherwise see a header
		// that was never sent.
		$request = new TWebhookRequest('POST', '', ['X-Event' => []]);

		$this->assertNull($request->getHeader('X-Event'));
	}

	public function testQueryParametersComeFromTheUrl()
	{
		$request = new TWebhookRequest('POST', '', [], 'https://example.com/hook?token=abc&mode=live');

		$this->assertSame(['token' => 'abc', 'mode' => 'live'], $request->getQueryParameters());
	}

	public function testAUrlWithoutAQueryHasNoQueryParameters()
	{
		$this->assertSame([], (new TWebhookRequest('POST', '', [], 'https://example.com/hook'))->getQueryParameters());
	}

	public function testCopiesLeaveTheOriginalAlone()
	{
		$request = new TWebhookRequest('POST', 'original', ['A' => '1']);

		$copy = $request->withHeaders(['B' => '2'])->withBody('changed');

		$this->assertSame('original', $request->getBody());
		$this->assertSame(['A' => '1'], $request->getHeaders());
		$this->assertSame('changed', $copy->getBody());
		$this->assertSame(['B' => '2'], $copy->getHeaders());
	}

	public function testEveryPartIsSettableAfterConstruction()
	{
		// The Prado property convention, which is how a configuration would reach these.
		$request = new TWebhookRequest();
		$request->setMethod('put');
		$request->setBody('{"a":1}');
		$request->setHeaders(['X-A' => '1']);
		$request->setUrl('https://example.com/hook');
		$request->setParameters(['b' => '2']);
		$request->setRemoteAddress('192.0.2.9');

		$this->assertSame('PUT', $request->getMethod());
		$this->assertSame('{"a":1}', $request->getBody());
		$this->assertSame(['X-A' => '1'], $request->getHeaders());
		$this->assertSame('https://example.com/hook', $request->getUrl());
		$this->assertSame(['b' => '2'], $request->getParameters());
		$this->assertSame('192.0.2.9', $request->getRemoteAddress());
	}

	public function testAnEmptyRemoteAddressIsNull()
	{
		$request = new TWebhookRequest();
		$request->setRemoteAddress('  ');

		$this->assertNull($request->getRemoteAddress());
	}

	public function testANonScalarParameterReadsAsNull()
	{
		$request = new TWebhookRequest('POST', '', [], '', ['nested' => ['a' => 1]]);

		$this->assertNull($request->getParameterValue('nested'));
	}

	public function testDefaults()
	{
		$request = new TWebhookRequest();

		$this->assertSame('POST', $request->getMethod());
		$this->assertSame('', $request->getBody());
		$this->assertSame([], $request->getHeaders());
		$this->assertSame('', $request->getUrl());
		$this->assertSame([], $request->getParameters());
		$this->assertNull($request->getRemoteAddress());
	}

	public function testAQueryWithMorePairsThanPhpAllowsReadsAsEmptyRatherThanThrowing()
	{
		// parse_str warns past max_input_vars and PRADO turns the warning into an exception;
		// the URL is the caller's, so that would be a 500 anyone could cause.
		$limit = (int) ini_get('max_input_vars');
		$this->assertGreaterThan(0, $limit, 'the test needs a max_input_vars limit to exceed');
		$pairs = ['key=x'];
		for ($i = 0; $i <= $limit; $i++) {
			$pairs[] = "p$i=1";
		}
		$request = new TWebhookRequest('POST', '{}', [], 'https://example.com/hook?' . implode('&', $pairs));

		$this->assertSame([], $request->getQueryParameters());
	}

	public function testAQueryAtTheLimitStillParses()
	{
		$limit = (int) ini_get('max_input_vars');
		$pairs = [];
		for ($i = 1; $i <= $limit; $i++) {
			$pairs[] = "p$i=$i";
		}
		$request = new TWebhookRequest('POST', '{}', [], 'https://example.com/hook?' . implode('&', $pairs));

		$this->assertCount($limit, $request->getQueryParameters());
	}

	public function testAUrlThatWillNotParseHasNoQueryParameters()
	{
		$this->assertSame([], (new TWebhookRequest('POST', '{}', [], 'http:///nohost?a=1'))->getQueryParameters());
		$this->assertSame([], (new TWebhookRequest('POST', '{}', [], ''))->getQueryParameters());
	}

	public function testAQueryNestedDeeperThanPhpAllowsReadsAsEmptyRatherThanThrowing()
	{
		// parse_str also warns past max_input_nesting_level -- only when display_errors is
		// off, which is production -- and that warning was a 500 anyone could cause.
		$depth = (int) ini_get('max_input_nesting_level');
		$this->assertGreaterThan(0, $depth, 'the test needs a nesting limit to exceed');
		$query = 'sig=abc&a' . str_repeat('[x]', $depth + 1) . '=1';
		$request = new TWebhookRequest('POST', '{}', [], 'https://example.com/hook?' . $query);

		$display = ini_set('display_errors', '0');
		try {
			$parameters = $request->getQueryParameters();
		} finally {
			ini_set('display_errors', (string) $display);
		}

		$this->assertSame([], $parameters);
	}
}
