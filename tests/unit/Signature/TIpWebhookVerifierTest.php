<?php

use Belisoful\Prado\Web\Webhooks\Signature\TIpWebhookVerifier;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;

class TIpWebhookVerifierTest extends PHPUnit\Framework\TestCase
{
	private function request(?string $remote, array $headers = []): TWebhookRequest
	{
		return new TWebhookRequest('POST', '{}', $headers, '', [], $remote);
	}

	private function verifier(string $addresses = '192.0.2.0/24, 198.51.100.17'): TIpWebhookVerifier
	{
		$verifier = new TIpWebhookVerifier();
		$verifier->setAddresses($addresses);

		return $verifier;
	}

	public function testAnAddressInsideARangeIsAccepted()
	{
		$verifier = $this->verifier();

		$this->assertTrue($verifier->verify($this->request('192.0.2.1')));
		$this->assertTrue($verifier->verify($this->request('192.0.2.255')));
	}

	public function testAnAddressOutsideEveryRangeIsRejected()
	{
		$verifier = $this->verifier();

		$this->assertFalse($verifier->verify($this->request('192.0.3.1')));
		$this->assertFalse($verifier->verify($this->request('203.0.113.9')));
	}

	public function testABareAddressMatchesOnlyItself()
	{
		$verifier = $this->verifier();

		$this->assertTrue($verifier->verify($this->request('198.51.100.17')));
		$this->assertFalse($verifier->verify($this->request('198.51.100.18')));
	}

	public function testAPrefixThatIsNotAWholeNumberOfBytes()
	{
		$verifier = $this->verifier('10.1.2.0/23');

		$this->assertTrue($verifier->verify($this->request('10.1.2.5')));
		$this->assertTrue($verifier->verify($this->request('10.1.3.5')));
		$this->assertFalse($verifier->verify($this->request('10.1.4.5')));
	}

	public function testIpV6RangesWork()
	{
		$verifier = $this->verifier('2001:db8::/32');

		$this->assertTrue($verifier->verify($this->request('2001:db8:1234::1')));
		$this->assertFalse($verifier->verify($this->request('2001:db9::1')));
	}

	public function testAnAddressOfTheOtherFamilyNeverMatches()
	{
		$this->assertFalse($this->verifier('2001:db8::/32')->verify($this->request('192.0.2.1')));
		$this->assertFalse($this->verifier('192.0.2.0/24')->verify($this->request('2001:db8::1')));
	}

	public function testAnUnknownOrUnparseableAddressIsRejected()
	{
		$this->assertFalse($this->verifier()->verify($this->request(null)));
		$this->assertFalse($this->verifier()->verify($this->request('not-an-address')));
	}

	public function testAForwardedHeaderIsIgnoredWhenTheConnectionIsNotFromATrustedHop()
	{
		// The attack this closes: an attacker setting the header to an allowed address.
		$verifier = $this->verifier();
		$verifier->setForwardedHeader('X-Forwarded-For');
		$verifier->setTrustedProxies('10.0.0.0/8');

		$this->assertFalse($verifier->verify($this->request('203.0.113.9', ['X-Forwarded-For' => '192.0.2.1'])));
	}

	public function testAForwardedHeaderIsBelievedFromATrustedHop()
	{
		$verifier = $this->verifier();
		$verifier->setForwardedHeader('X-Forwarded-For');
		$verifier->setTrustedProxies('10.0.0.0/8');

		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '192.0.2.1'])));
		$this->assertFalse($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '203.0.113.9'])));
	}

	public function testOnlyTheEntryTheTrustedHopAddedIsBelieved()
	{
		// Everything left of it was written by the caller, who may write anything at all.
		$verifier = $this->verifier();
		$verifier->setForwardedHeader('X-Forwarded-For');
		$verifier->setTrustedProxies('10.0.0.0/8');

		$this->assertTrue($verifier->verify($this->request(
			'10.0.0.1',
			['X-Forwarded-For' => '203.0.113.9, 192.0.2.1']
		)));
		$this->assertFalse($verifier->verify($this->request(
			'10.0.0.1',
			['X-Forwarded-For' => '192.0.2.1, 203.0.113.9']
		)));
	}

	public function testATrustedHopWithNoForwardedHeaderIsJudgedByItsOwnAddress()
	{
		$verifier = $this->verifier('10.0.0.0/8');
		$verifier->setForwardedHeader('X-Forwarded-For');
		$verifier->setTrustedProxies('10.0.0.0/8');

		$this->assertTrue($verifier->verify($this->request('10.0.0.1')));
	}

	public function testAForwardedHeaderWithoutTrustedProxiesIsAConfigurationError()
	{
		$verifier = $this->verifier();
		$verifier->setForwardedHeader('X-Forwarded-For');

		$this->expectException(TConfigurationException::class);
		$verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '192.0.2.1']));
	}

	public function testTrustedProxiesClearBackToEmpty()
	{
		$verifier = $this->verifier();
		$verifier->setTrustedProxies('10.0.0.0/8');
		$verifier->setTrustedProxies('');

		$this->assertSame([], $verifier->getTrustedProxies());
	}

	public function testAddressesAreParsedFromAListOrAnArray()
	{
		$verifier = new TIpWebhookVerifier();
		$verifier->setAddresses(['192.0.2.0/24', '198.51.100.17']);

		$this->assertSame(['192.0.2.0/24', '198.51.100.17'], $verifier->getAddresses());
	}

	public function testAnEmptyAllowListIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TIpWebhookVerifier())->setAddresses(' , ');
	}

	public function testAPrefixLengthThatIsNotANumberIsRefused()
	{
		// It used to read as /0, which turned the allow list into the whole address family:
		// the exact opposite of what the configuration says.
		foreach (['192.0.2.0/abc', '192.0.2.0/', '192.0.2.0/33', '2001:db8::/129'] as $range) {
			try {
				(new TIpWebhookVerifier())->setAddresses($range);
				$this->fail("'{$range}' should be refused");
			} catch (TConfigurationException $e) {
				$this->assertStringContainsString('prefix', strtolower($e->getMessage()));
			}
		}
	}

	public function testAZeroPrefixIsAllowedBecauseItIsDeliberate()
	{
		// Distinct from the case above: /0 really does mean the whole family, and someone who
		// writes it means it.
		$verifier = $this->verifier('0.0.0.0/0');

		$this->assertTrue($verifier->verify($this->request('8.8.8.8')));
	}

	public function testABoundaryPrefixIsAccepted()
	{
		$this->assertTrue($this->verifier('192.0.2.1/32')->verify($this->request('192.0.2.1')));
		$this->assertFalse($this->verifier('192.0.2.1/32')->verify($this->request('192.0.2.2')));
		$this->assertTrue($this->verifier('2001:db8::1/128')->verify($this->request('2001:db8::1')));
	}

	public function testTheForwardedHeaderRoundTrips()
	{
		$verifier = $this->verifier();
		$this->assertNull($verifier->getForwardedHeader());

		$verifier->setForwardedHeader('X-Forwarded-For');
		$this->assertSame('X-Forwarded-For', $verifier->getForwardedHeader());

		$verifier->setForwardedHeader('');
		$this->assertNull($verifier->getForwardedHeader());
	}

	public function testAnUnparseableRangeIsRefusedRatherThanSilentlyMatchingNothing()
	{
		$this->expectException(TConfigurationException::class);
		(new TIpWebhookVerifier())->setAddresses('192.0.2.0/24, not-an-address');
	}

	public function testVerifyingWithNoAddressesConfiguredIsAConfigurationError()
	{
		$this->expectException(TConfigurationException::class);
		(new TIpWebhookVerifier())->verify($this->request('192.0.2.1'));
	}
}
