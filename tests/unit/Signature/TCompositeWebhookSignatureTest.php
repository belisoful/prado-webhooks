<?php

use Belisoful\Prado\Web\Webhooks\Signature\IWebhookVerifier;
use Belisoful\Prado\Web\Webhooks\Signature\TAllWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\TAnyWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature;
use Belisoful\Prado\Web\Webhooks\Signature\TIpWebhookVerifier;
use Belisoful\Prado\Web\Webhooks\TWebhookRequest;
use Prado\Exceptions\TConfigurationException;
use Prado\Xml\TXmlDocument;

/**
 * A verifier that answers what it is told to and counts how often it was asked.
 */
class TestRecordingVerifier implements IWebhookVerifier
{
	public int $calls = 0;

	public function __construct(private bool $_answer)
	{
	}

	public function verify(TWebhookRequest $request): bool
	{
		$this->calls++;

		return $this->_answer;
	}
}

class TCompositeWebhookSignatureTest extends PHPUnit\Framework\TestCase
{
	private const BODY = '{"id":1}';

	private function request(array $headers = [], ?string $remote = null): TWebhookRequest
	{
		return new TWebhookRequest('POST', self::BODY, $headers, '', [], $remote);
	}

	private function hmac(string $secret): THmacWebhookSignature
	{
		$signature = new THmacWebhookSignature();
		$signature->setSecret($secret);
		$signature->setHeader('X-Signature');

		return $signature;
	}

	private function signedWith(string $secret): array
	{
		return ['X-Signature' => hash_hmac('sha256', self::BODY, $secret)];
	}

	private function xml(string $markup): TXmlDocument
	{
		$document = new TXmlDocument();
		$document->loadFromString($markup);

		return $document;
	}

	// ── Any ────────────────────────────────────────────────────────────────────

	public function testAnyAcceptsADeliveryThatSatisfiesOneChild()
	{
		$any = new TAnyWebhookSignature();
		$any->addSignature($this->hmac('the-new-one'));
		$any->addSignature($this->hmac('the-old-one'));

		$this->assertTrue($any->verify($this->request($this->signedWith('the-new-one'))));
		$this->assertTrue($any->verify($this->request($this->signedWith('the-old-one'))));
		$this->assertFalse($any->verify($this->request($this->signedWith('neither'))));
	}

	public function testAnySignsWithItsFirstSigner()
	{
		$any = new TAnyWebhookSignature();
		$any->addSignature(new TIpWebhookVerifier());
		$any->addSignature($this->hmac('the-new-one'));

		$headers = $any->sign($this->request());

		$this->assertSame($this->signedWith('the-new-one'), $headers);
	}

	public function testDroppingTheOldChildEndsTheRotation()
	{
		$any = new TAnyWebhookSignature();
		$any->addSignature($this->hmac('the-new-one'));

		$this->assertFalse($any->verify($this->request($this->signedWith('the-old-one'))));
	}

	// ── All ────────────────────────────────────────────────────────────────────

	public function testAllRequiresEveryChild()
	{
		$addresses = new TIpWebhookVerifier();
		$addresses->setAddresses('192.0.2.0/24');
		$all = new TAllWebhookSignature();
		$all->addSignature($addresses);
		$all->addSignature($this->hmac('s3cret'));

		$this->assertTrue($all->verify($this->request($this->signedWith('s3cret'), '192.0.2.1')));
		// The signature alone is not enough.
		$this->assertFalse($all->verify($this->request($this->signedWith('s3cret'), '203.0.113.9')));
		// Neither is the address alone.
		$this->assertFalse($all->verify($this->request($this->signedWith('wrong'), '192.0.2.1')));
	}

	public function testAllSignsWithEveryChildThatCan()
	{
		$second = $this->hmac('s3cret');
		$second->setHeader('X-Other-Signature');

		$all = new TAllWebhookSignature();
		$all->addSignature(new TIpWebhookVerifier());
		$all->addSignature($this->hmac('s3cret'));
		$all->addSignature($second);

		$headers = $all->sign($this->request());

		$this->assertSame(['X-Signature', 'X-Other-Signature'], array_keys($headers));
	}

	public function testACompositeThatCanOnlyVerifyCannotSign()
	{
		$all = new TAllWebhookSignature();
		$all->addSignature(new TIpWebhookVerifier());

		$this->expectException(TConfigurationException::class);
		$all->sign($this->request());
	}

	public function testAnyCannotSignWhenNoChildCan()
	{
		$any = new TAnyWebhookSignature();
		$any->addSignature(new TIpWebhookVerifier());

		$this->expectException(TConfigurationException::class);
		$any->sign($this->request());
	}

	// ── Configuration ──────────────────────────────────────────────────────────

	public function testChildrenAreBuiltFromXml()
	{
		$any = new TAnyWebhookSignature();
		$any->init($this->xml(
			'<signature>'
			. '<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"'
			. ' Secret="the-new-one" Header="X-Signature" />'
			. '<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"'
			. ' Secret="the-old-one" Header="X-Signature" />'
			. '</signature>'
		));

		$this->assertCount(2, $any->getSignatures());
		$this->assertTrue($any->verify($this->request($this->signedWith('the-old-one'))));
	}

	public function testChildrenAreBuiltFromAPhpConfiguration()
	{
		$all = new TAllWebhookSignature();
		$all->init([
			'signature' => [
				[
					'class' => THmacWebhookSignature::class,
					'properties' => ['Secret' => 's3cret', 'Header' => 'X-Signature'],
				],
				[
					'class' => TIpWebhookVerifier::class,
					'properties' => ['Addresses' => '192.0.2.0/24'],
				],
			],
		]);

		$this->assertCount(2, $all->getSignatures());
		$this->assertTrue($all->verify($this->request($this->signedWith('s3cret'), '192.0.2.1')));
	}

	public function testAChildThatIsNeitherAVerifierNorASignerIsRefused()
	{
		$any = new TAnyWebhookSignature();

		$this->expectException(TConfigurationException::class);
		$any->init($this->xml('<signature><signature class="Prado\TComponent" /></signature>'));
	}

	public function testAddingSomethingThatIsNeitherIsRefused()
	{
		$this->expectException(TConfigurationException::class);
		(new TAnyWebhookSignature())->addSignature(new stdClass());
	}

	public function testACompositeWithNoChildrenRefusesToAnswer()
	{
		// Answering either way on no evidence would be worse than saying so.
		foreach ([new TAnyWebhookSignature(), new TAllWebhookSignature()] as $composite) {
			try {
				$composite->verify($this->request());
				$this->fail($composite::class . ' should refuse to verify with no children');
			} catch (TConfigurationException $e) {
				$this->assertNotSame('', $e->getMessage());
			}
		}
	}

	public function testNoChildrenInTheConfigurationLeavesTheCompositeEmpty()
	{
		$any = new TAnyWebhookSignature();
		$any->init($this->xml('<signature />'));

		$this->assertSame([], $any->getSignatures());
	}

	// ── Every child is evaluated ───────────────────────────────────────────────

	public function testAnyEvaluatesEveryChildEvenAfterOneAccepts()
	{
		// No short circuit: which child matched must not be observable in the response
		// time, and a child that throws on configuration must throw whatever its siblings
		// said.
		$first = new TestRecordingVerifier(true);
		$second = new TestRecordingVerifier(false);
		$third = new TestRecordingVerifier(true);
		$any = new TAnyWebhookSignature();
		foreach ([$first, $second, $third] as $child) {
			$any->addSignature($child);
		}

		$this->assertTrue($any->verify($this->request()));
		$this->assertSame([1, 1, 1], [$first->calls, $second->calls, $third->calls]);
	}

	public function testAllEvaluatesEveryChildEvenAfterOneRefuses()
	{
		$first = new TestRecordingVerifier(false);
		$second = new TestRecordingVerifier(true);
		$third = new TestRecordingVerifier(false);
		$all = new TAllWebhookSignature();
		foreach ([$first, $second, $third] as $child) {
			$all->addSignature($child);
		}

		$this->assertFalse($all->verify($this->request()));
		$this->assertSame([1, 1, 1], [$first->calls, $second->calls, $third->calls]);
	}

	public function testAnyRefusesWhenEveryChildRefusesAndAllAcceptsWhenEveryChildAccepts()
	{
		$any = new TAnyWebhookSignature();
		$any->addSignature(new TestRecordingVerifier(false));
		$any->addSignature(new TestRecordingVerifier(false));
		$this->assertFalse($any->verify($this->request()));

		$all = new TAllWebhookSignature();
		$all->addSignature(new TestRecordingVerifier(true));
		$all->addSignature(new TestRecordingVerifier(true));
		$this->assertTrue($all->verify($this->request()));
	}

	public function testAChildThatOnlySignsCountsAsRefusingInAVerification()
	{
		// A composite made of a signer and a verifier: the signer has nothing to say about
		// an inbound request, and All must not read that silence as consent.
		$signer = new class () implements Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner {
			public function sign(TWebhookRequest $request): array
			{
				return ['X-Nothing' => '1'];
			}
		};
		$all = new TAllWebhookSignature();
		$all->addSignature($signer);
		$all->addSignature(new TestRecordingVerifier(true));
		$this->assertFalse($all->verify($this->request()));

		$any = new TAnyWebhookSignature();
		$any->addSignature($signer);
		$any->addSignature(new TestRecordingVerifier(true));
		$this->assertTrue($any->verify($this->request()));
	}

	public function testAMisconfiguredChildThrowsWhateverItsSiblingsSaid()
	{
		$any = new TAnyWebhookSignature();
		$any->addSignature(new TestRecordingVerifier(true));
		$any->addSignature(new THmacWebhookSignature());

		$this->expectException(TConfigurationException::class);
		$any->verify($this->request());
	}
}
