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

	// ── Proxy chains ───────────────────────────────────────────────────────────

	private function behindProxies(string $proxies = '10.0.0.0/8, 172.16.0.0/12'): TIpWebhookVerifier
	{
		$verifier = $this->verifier();
		$verifier->setForwardedHeader('X-Forwarded-For');
		$verifier->setTrustedProxies($proxies);

		return $verifier;
	}

	public function testATwoProxyChainIsWalkedPastEveryTrustedHop()
	{
		// caller -> edge proxy (172.16.0.9) -> inner proxy (10.0.0.1) -> us. The inner hop
		// appended the edge's address; the edge appended the caller's.
		$verifier = $this->behindProxies();

		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '192.0.2.1, 172.16.0.9'])));
		$this->assertFalse($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '203.0.113.9, 172.16.0.9'])));
	}

	public function testTheCallerCannotHideBehindTheProxiesItNames()
	{
		// An attacker connecting through the trusted edge writes an allowed address and a
		// trusted proxy to the left of their own; neither is read, because their own entry
		// -- the one the edge appended -- is the first untrusted one from the right.
		$verifier = $this->behindProxies();

		$this->assertFalse($verifier->verify($this->request(
			'10.0.0.1',
			['X-Forwarded-For' => '192.0.2.1, 172.16.0.9, 203.0.113.9, 172.16.0.9']
		)));
		$this->assertFalse($verifier->verify($this->request(
			'10.0.0.1',
			['X-Forwarded-For' => '192.0.2.1, 10.0.0.2, 203.0.113.9']
		)));
	}

	public function testAChainOfNothingButTrustedProxiesIsJudgedByItsLastEntry()
	{
		$verifier = $this->behindProxies();
		$verifier->setAddresses('172.16.0.0/12');

		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '10.0.0.3, 172.16.0.9'])));

		$verifier->setAddresses('192.0.2.0/24');
		$this->assertFalse($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '10.0.0.3, 172.16.0.9'])));
	}

	public function testAThreeHopChain()
	{
		$verifier = $this->behindProxies('10.0.0.0/8, 172.16.0.0/12, 198.51.100.0/24');
		$verifier->setAddresses('192.0.2.0/24');

		$this->assertTrue($verifier->verify($this->request(
			'10.0.0.1',
			['X-Forwarded-For' => '192.0.2.7, 198.51.100.2, 172.16.0.9']
		)));
	}

	public function testAnUnparseableEntryInTheChainIsTheCallerAndIsRefused()
	{
		$verifier = $this->behindProxies();

		$this->assertFalse($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '192.0.2.1, unknown, 172.16.0.9'])));
		$this->assertFalse($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => 'unknown'])));
	}

	// ── Ports, brackets, and mapped addresses ──────────────────────────────────

	public function testAPortSuffixIsStrippedFromAForwardedEntry()
	{
		$verifier = $this->behindProxies();

		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '192.0.2.1:51234'])));
		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '192.0.2.1:51234, 172.16.0.9:8080'])));
		$this->assertFalse($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '203.0.113.9:51234'])));
	}

	public function testABracketedIpV6EntryWithOrWithoutAPortIsRead()
	{
		$verifier = $this->behindProxies();
		$verifier->setAddresses('2001:db8::/32');

		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '[2001:db8::1]:51234'])));
		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '[2001:db8::1]'])));
		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '2001:db8::1'])));
		$this->assertFalse($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '[2001:db9::1]:51234'])));
	}

	public function testAPortOnTheConnectionAddressItselfIsStripped()
	{
		$this->assertTrue($this->verifier()->verify($this->request('192.0.2.1:443')));
		$this->assertTrue($this->verifier('2001:db8::/32')->verify($this->request('[2001:db8::1]:443')));
	}

	public function testAnIpV4MappedIpV6AddressMatchesAnIpV4AllowList()
	{
		// What a dual-stack listener reports for an IPv4 connection.
		$verifier = $this->verifier();

		$this->assertTrue($verifier->verify($this->request('::ffff:192.0.2.1')));
		$this->assertTrue($verifier->verify($this->request('::FFFF:192.0.2.1')));
		$this->assertTrue($verifier->verify($this->request('::ffff:c000:201')), 'the hex spelling of the same address');
		$this->assertFalse($verifier->verify($this->request('::ffff:203.0.113.9')));
		$this->assertFalse($verifier->verify($this->request('::fffe:192.0.2.1')), 'not the mapped prefix');
	}

	public function testAMappedAddressIsRecognizedAsATrustedProxyAndInTheChain()
	{
		$verifier = $this->behindProxies();

		$this->assertTrue($verifier->verify($this->request('::ffff:10.0.0.1', ['X-Forwarded-For' => '::ffff:192.0.2.1'])));
		$this->assertTrue($verifier->verify($this->request('::ffff:10.0.0.1', ['X-Forwarded-For' => '192.0.2.1, ::ffff:172.16.0.9'])));
		$this->assertTrue($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '[::ffff:192.0.2.1]:51234'])));
		$this->assertFalse($verifier->verify($this->request('::ffff:203.0.113.9', ['X-Forwarded-For' => '192.0.2.1'])), 'not a trusted hop');
	}

	public function testAPortSuffixOnAnUnbracketedIpV6EntryIsNotGuessedAt()
	{
		// `2001:db8::1:8080` is a valid address in its own right; only brackets say where
		// the port begins.
		$verifier = $this->behindProxies();
		$verifier->setAddresses('2001:db8::1/128');

		$this->assertFalse($verifier->verify($this->request('10.0.0.1', ['X-Forwarded-For' => '2001:db8::1:8080'])));
	}

	public function testAnEmptyArrayClearsTheTrustedProxiesAsAnEmptyStringDoes()
	{
		$verifier = $this->verifier();
		$verifier->setTrustedProxies('10.0.0.0/8');
		$verifier->setTrustedProxies([]);

		$this->assertSame([], $verifier->getTrustedProxies());
	}
}
