prado-webhooks
==============

[![Extension](https://github.com/belisoful/prado-webhooks/actions/workflows/prado-webhooks.yml/badge.svg)](https://github.com/belisoful/prado-webhooks/actions/workflows/prado-webhooks.yml)

Inbound and outbound webhooks for PRADO 4.4: a signature-verifying receiver service, and a
sender that signs and retries.

The package does not own your subscriptions. Which URLs a user has subscribed, to what, and
under whose secret is your application's question; you hand the answer to `send()` as an
array, and the package delivers it.

```
composer require belisoful/prado-webhooks
```

**This is a 0.x package.** Everything here is tested -- the signature schemes against
OpenSSL's own output, the queue against SQLite, MySQL and PostgreSQL -- but the version is the
honest signal that the interfaces are not frozen. Expect them to move between minor versions
until 1.0, and pin accordingly.

Receiving
---------

Add the service. Each `<endpoint>` is one provider, reachable at `index.php?webhook=<id>`.

```xml
<services>
	<service id="webhook" class="Belisoful\Prado\Web\Webhooks\TWebhookService">
		<endpoint id="github" EventHeader="X-GitHub-Event">
			<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
				Secret="..." Header="X-Hub-Signature-256" Prefix="sha256=" />
		</endpoint>
		<endpoint id="payments" EventProperty="type">
			<signature class="Belisoful\Prado\Web\Webhooks\Signature\TFieldedWebhookSignature"
				Secret="whsec_..." Header="Stripe-Signature" />
		</endpoint>
	</service>
</services>
```

Attach handlers from a module, once the services exist:

```php
public function init($config)
{
	parent::init($config);
	$this->getApplication()->onInitComplete[] = function () {
		// Null on any request another service is handling, which is most of them.
		$service = TWebhookService::getInstance();
		if ($service === null) {
			return;
		}
		$service->onWebhook[] = [$this, 'anyWebhook'];   // every endpoint's accepted deliveries
		$service->onRefused[] = [$this, 'countRefusal']; // and the ones an endpoint turned away
		if (($github = $service->getEndpoint('github')) !== null) {
			$github->onWebhook[] = [$this, 'github'];
		}
	};
}

public function github(TWebhookEndpoint $sender, TWebhookEventParameter $param): void
{
	if ($param->getEvent() !== 'push') {
		return;
	}
	$this->queueDeploy($param['repository']['full_name'], $param['after']);
	$param->setStatusCode(202);
}
```

`$param` carries the raw `Body`, the decoded `Payload` (and array access to it), the
`Headers`, the `Event` name, the whole `Request`, and the response: `StatusCode`,
`ResponseBody`, `ResponseContentType`. Do not throw out of a handler — a provider shown a
PRADO error page gets a 500, keeps retrying, and learns about your application. Set a status
instead.

The endpoint refuses a delivery before any handler sees it when the method is not allowed
(405), the body is over `MaxBodySize` (413), the signature does not verify (401), or the
body is not JSON and `RequireJson` is on (400). The checks run in that order, so an
unauthenticated caller cannot make the endpoint hash a large body, and nothing reads the
payload before the signature has been checked — the body is not even decoded until then,
and a request whose `Content-Length` already exceeds `MaxBodySize` is refused before it is
read. A refused delivery reaches the service's `onRefused` event, never `onWebhook`, with
its payload undecoded; a handler there may count or rate limit, and may swap the status for
another refusal but not for a success.

An endpoint with no `<signature>` child accepts everything, which is only right behind
something that already authenticates the request. A misspelled child element is refused at
boot rather than ignored, and `RequireVerifier="true"` makes a missing verifier a
configuration error instead of an open door.

Sending
-------

Configure the module — the `<signature>` child is the fallback for targets that bring no
secret of their own:

```xml
<modules>
	<module id="belisoful/prado-webhooks" Timeout="5" MaxAttempts="3">
		<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
			Secret="..." TimestampHeader="X-Webhook-Timestamp"
			PayloadFormat="{timestamp}.{body}" />
	</module>
</modules>
```

Then send whatever list of subscribers your application keeps:

```php
$webhooks = $this->getApplication()->getModule('belisoful/prado-webhooks');

$deliveries = $webhooks->send([
	['url' => $row['url'], 'secret' => $row['secret'], 'events' => ['invoice.paid']],
	'https://example.com/hooks/prado',
], ['invoice' => $invoice->toArray()], 'invoice.paid');

foreach ($deliveries as $delivery) {
	if (!$delivery->getSuccessful()) {
		$this->reschedule($delivery->getTarget()->getData(), $delivery->getStatusText());
	}
}
```

A target may be a `TWebhookTarget`, a URL string, or an array of its properties, in which
`secret` is shorthand for an HMAC signature keyed with it. Targets that are disabled, or
that subscribe to other events, are skipped.

**Retries.** A 2xx is delivered and a 4xx is refused — the receiver understood the request
and will not like it better next time. Transport failures and the statuses in
`RetryStatusCodes` (500, 502, 503, 504, plus 408, 425 and 429) are retried, with the delay doubling
from `RetryDelay` up to `MaxRetryDelay`, and a `Retry-After` — seconds or an HTTP date —
overriding it, capped the same way. A queued delivery honors `Retry-After` too, capped at
`QueueMaxRetryDelay`.

**Deliveries are sent inside the request that triggered them**, so keep `Timeout` ×
`MaxAttempts` to something a page can afford. `onSending`, `onDelivered` and `onFailed` are
raised on the sender for every delivery, and a handler of the first may add headers, rewrite
the body, or cancel the delivery outright — which is where an application that outgrows
sending inline puts its queue.

Guaranteed delivery
-------------------

`send()` delivers inside the request that called it, so a delivery dies with the process. For
deliveries that must not be lost, `queue()` writes them down and a cron run sends them.

```xml
<modules>
	<module id="db" class="Prado\Data\TDataSourceConfig">
		<database ConnectionString="sqlite:protected/runtime/app.db" />
	</module>
	<module id="webhook-queue" class="Belisoful\Prado\Web\Webhooks\TDbWebhookQueue"
		ConnectionID="db" AutoCreateTable="true" />

	<module id="belisoful/prado-webhooks" QueueID="webhook-queue" QueueMaxAttempts="10" />

	<module id="cron" class="Prado\Util\Cron\TCronModule">
		<job Name="webhooks" Schedule="* * * * *"
			Task="Belisoful\Prado\Web\Webhooks\TWebhookCronTask" />
		<job Name="webhooks-prune" Schedule="0 4 * * *"
			Task="Belisoful\Prado\Web\Webhooks\TWebhookPruneCronTask" />
	</module>
</modules>
```

with PRADO's cron run once a minute from the system crontab:

```
* * * * * php /path/to/vendor/bin/prado-cli app /path/to/app/ cron
```

Then queue instead of sending:

```php
$webhooks->queue($subscriberRows, ['invoice' => $invoice->toArray()], 'invoice.paid');
```

Both calls stay available — `queue()` is a different call, not a mode the module is in.

The queue works on SQLite, MySQL and PostgreSQL; all three are exercised by CI.

**The guarantee is at-least-once.** A drain takes a lease on each delivery rather than a lock,
so a runner that is killed mid-attempt has its work picked up when the lease expires — which
also means a delivery can go out twice if the runner dies after the receiver accepted it.
That is what the delivery id is for, and it stays the same across every attempt. A runner
whose lease has expired can no longer write its result back: the write names the lease, so a
late finisher cannot disturb whoever holds the delivery now.

A delivery that cannot be attempted at all — a stored target that will not rebuild, a signer
with no key — does not take the rest of the batch with it. It uses up its attempts like any
other failure and settles as a `failed` row with the reason on it.

One attempt is made per drain: the queue owns the retry cadence, doubling from
`QueueRetryDelay` up to `QueueMaxRetryDelay`, for up to `QueueMaxAttempts`. The retry policy
is the sender's: a status outside `RetryStatusCodes` -- a 4xx -- settles the delivery as
`failed` on the spot rather than sending it again for hours. Deliveries that run out of
attempts are kept as `failed` rows to be looked at and replayed, until the prune task
removes them; accepted ones are deleted unless `KeepDelivered` is on.

**Secrets and the queue table.** A target holds a signer, and a signer holds a key, which is
not something to write into a table. Two ways, and pick one deliberately:

```php
// the secret goes into the queue table with the delivery
$webhooks->queue([['url' => $row['url'], 'secret' => $row['secret']]], $payload, 'invoice.paid');

// or queue a reference, and put the target back on the way out
$webhooks->queue([['url' => $row['url'], 'data' => $row['id']]], $payload, 'invoice.paid');

$webhooks->onDequeue[] = function ($sender, TWebhookQueueItem $item) {
	$target = TWebhookTarget::ensure($item->getTargetSpec());
	$target->setSignature($this->signerFor($item->getTargetSpec()['data']));
	$item->setTarget($target);
};
```

Passing an already-built `TWebhookTarget` that carries a signature is refused rather than
quietly queueing a delivery that would go out unsigned.

Sizing: one run sends up to `BatchSize` deliveries and holds them for `LeaseSeconds`. The
worst case of a run is the sum of the batch's timeouts — each target's own `Timeout` where
it sets one, the sender's otherwise — so keep that inside the cron interval, or accept
overlapping runs, which is safe only while the lease outlasts a whole batch. Handlers that
throw during a run are recorded on the delivery rather than turning an accepted delivery
into a retry. `TWebhookPruneCronTask` takes a `BatchSize` too, to bound one prune. Target
URLs are the application's; `TWebhookTarget::setUrlValidator()` is where it refuses
private or link-local ones before a subscriber-supplied URL reaches `send()` or `queue()`.

Signature schemes
-----------------

The schemes are general and configured, not one class per provider.

| Class | The shape it covers |
| --- | --- |
| `THmacWebhookSignature` | a keyed hash in a value of its own |
| `TFieldedWebhookSignature` | a keyed hash packed into one value with named fields, `t=…,v1=…` |
| `TPublicKeyWebhookSignature` | an asymmetric signature, PKCS#1 v1.5 or PSS, with a configured key or a certificate the delivery names |
| `TJwtWebhookSignature` | a JSON Web Token: HS256/384/512, RS256/384/512, ES256/384/512, with claim checks |
| `THttpMessageWebhookSignature` | HTTP Message Signatures, RFC 9421 — the message lists what it covers |
| `TTokenWebhookSignature` | a shared secret presented as it is, in a header, the query string, or a parameter |
| `TIpWebhookVerifier` | an address allow list, with CIDR and a chain of trusted proxies |
| `TSnsWebhookVerifier` | Amazon SNS, whose signed string is a canonicalization of the body's own fields |
| `TAnyWebhookSignature` / `TAllWebhookSignature` | several of the above, for a secret rotation or a layered check |

Everything above implements **both** `IWebhookVerifier` and `IWebhookSigner` except the last
three: an address is not something a sender can put in a header, and SNS carries its
signature in the body. For the rest, what one PRADO application signs, another verifies with
an identically configured object.

### What gets signed

`PayloadFormat` is the part providers disagree about most, so it is a template:

| Token | Expands to |
| --- | --- |
| `{body}` | the raw request body, byte for byte |
| `{method}` `{url}` | the HTTP method, the absolute request URL |
| `{timestamp}` `{id}` | the timestamp and delivery id the signature is bound to |
| `{crc32}` | the CRC32 of the body, as a decimal string |
| `{header:Name}` `{param:name}` `{query:name}` | one header, request parameter, or query parameter |
| `{const:NAME}` | one entry of `Constants`, for values that come from your own configuration |
| `{params}` | every request parameter, sorted by name, as name and value concatenated |

A scheme whose payload leaves out `{body}` is not bound to the body at all unless something
else ties them together. `BodyHashName` is that something: it names where the request
presents a digest of its own body — which the signature then covers — and requires it to
match. `BodyHashSource`, `BodyHashAlgorithm` and `BodyHashEncoding` say where and how.

Which turns the schemes in the wild into configuration:

```
{body}                             a keyed hash of the body alone — the common case
{timestamp}.{body}                 a timestamped hash, and this package's own default
{id}.{timestamp}.{body}            the Standard Webhooks layout
{url}{body}                        the URL and the body
{url}{params}                      the URL and the sorted form parameters
{param:timestamp}{param:token}     values the provider posted in the body
{header:X-Id}|{const:HOOK}|{crc32} a canonical string of headers, your own id, and a checksum
{url} + BodyHashName               the URL alone, with a digest of the body carried in it
```

### Worked examples

```xml
<!-- hex hash of the body, under the provider's header -->
<signature class="...\THmacWebhookSignature"
	Secret="..." Header="X-Hub-Signature-256" Prefix="sha256=" />

<!-- the same hash, base64 -->
<signature class="...\THmacWebhookSignature"
	Secret="..." Header="X-Hmac-Sha256" Encoding="base64" />

<!-- SHA-1 over the URL and sorted parameters -->
<signature class="...\THmacWebhookSignature"
	Secret="..." Header="X-Signature" Algorithm="sha1" Encoding="base64"
	PayloadFormat="{url}{params}" />

<!-- a displayed secret that is a marker plus base64, several signatures through a rotation -->
<signature class="...\THmacWebhookSignature"
	Secret="whsec_..." SecretPrefix="whsec_" SecretEncoding="base64"
	Header="webhook-signature" IdHeader="webhook-id" TimestampHeader="webhook-timestamp"
	PayloadFormat="{id}.{timestamp}.{body}" Prefix="v1," Separator=" " Encoding="base64" />

<!-- the URL alone, where the provider posts JSON and puts a digest of it in the URL -->
<signature class="...\THmacWebhookSignature"
	Secret="..." Header="X-Signature" Algorithm="sha1" Encoding="base64"
	PayloadFormat="{url}" BodyHashName="bodySHA256" BodyHashSource="query" />

<!-- an asymmetric signature whose provider uses PSS rather than PKCS#1 v1.5 -->
<signature class="...\TPublicKeyWebhookSignature"
	PublicKey="protected/keys/provider.pem" Header="X-Signature"
	Algorithm="sha512" Padding="pss" />

<!-- Amazon SNS: the topic is required, and is the check that matters -->
<signature class="...\TSnsWebhookVerifier"
	TopicArn="arn:aws:sns:us-east-1:123456789012:my-topic" SignatureVersions="2" />

<!-- RFC 9421, where the application decides what a signature must cover -->
<signature class="...\THttpMessageWebhookSignature"
	Secret="..." Algorithms="hmac-sha256" KeyId="provider"
	RequiredComponents="@method, @target-uri, content-digest" />

<!-- Basic credentials, for a provider that signs nothing -->
<signature class="...\TTokenWebhookSignature" Token="aGVsbG86d29ybGQ=" Prefix="Basic " />

<!-- rotate a secret without an outage -->
<signature class="...\TAnyWebhookSignature">
	<signature class="...\THmacWebhookSignature" Secret="the-new-one" Header="X-Signature" />
	<signature class="...\THmacWebhookSignature" Secret="the-old-one" Header="X-Signature" />
</signature>

<!-- an address allow list underneath a signature -->
<signature class="...\TAllWebhookSignature">
	<signature class="...\TIpWebhookVerifier" Addresses="192.0.2.0/24" />
	<signature class="...\THmacWebhookSignature" Secret="..." Header="X-Signature" />
</signature>
```

### Notes on the harder ones

- **A timestamped scheme is worth the extra header.** Put `{timestamp}` in the template so
  the timestamp is inside the hash; a captured request then cannot be replayed under a new
  one, and `Tolerance` bounds how old a delivery may be.
- **`TPublicKeyWebhookSignature` will not fetch a certificate URL out of a request without
  `CertificateUrlPattern`.** That URL is an instruction from a stranger, and fetching it
  unchecked is a server-side request forgery. Anchor the pattern on the provider's domain.
- **A JWT authenticates its bearer, not the delivery.** Set `BodyHashClaim` where the
  provider offers it; otherwise a captured token verifies against any body until it expires.
  `Algorithms` is an allow list, and the token's own `alg` is never what decides.
- **An address allow list authenticates the peer and nothing about the request.** Pair it
  with a keyed scheme through `TAllWebhookSignature` wherever the provider has one, and read
  `ForwardedHeader` only with `TrustedProxies` set.
- **`TSnsWebhookVerifier` requires `TopicArn`, and that is the setting that matters.** Every
  SNS message in every AWS account is signed by the same certificate authority, so without
  the topic check the endpoint accepts whatever anyone with an AWS account sends it. Note
  also that confirming a subscription is the handler's job: verify the
  `SubscriptionConfirmation`, then fetch its `SubscribeURL`.
- **`THttpMessageWebhookSignature` is only as strong as `RequiredComponents`.** The message
  decides what it signs, and a signature over `@method` alone is perfectly valid; the
  required list is the application's say in what that has to include. It covers HMAC, RSA
  PKCS#1 v1.5, `rsa-pss-sha512`, ECDSA on P-256 and P-384, and `ed25519` — the last needing
  ext-sodium and its keys as raw bytes in base64.
- **RSA padding is a setting, and the wrong one fails silently.** `TPublicKeyWebhookSignature`
  defaults to `Padding="pkcs1"`; providers using RSASSA-PSS need `Padding="pss"`, and
  `SaltLength` if they depart from the digest length. Neither padding is detectable from a
  signature, so the two produce identical symptoms to a wrong key. PHP's `openssl_verify`
  takes no padding argument, so the package reaches PSS by rewriting the key as an
  `id-RSASSA-PSS` key and letting OpenSSL pad accordingly — an ordinary RSA key from the
  provider is all that has to be configured.

Anything a provider does that none of this expresses is an `IWebhookVerifier` of your own:
the endpoint takes any implementation.

Development
-----------

`composer fulltest` runs the full check: compile, code style, static analysis, unit tests.

`composer integration` installs the package into a throwaway consumer project and verifies
the `extra.prado` wiring against a real `composer require`. It needs a PRADO checkout to
install the framework from, at `../prado.master` unless another path is given:
`tests/integration/run-install-test.sh /path/to/prado`.

Some tests shell out to the `openssl` command line to check this package's signatures
against OpenSSL's own rather than against itself; they skip where the binary is missing.

The queue suite runs against SQLite always, and against MySQL and PostgreSQL when you point
it at a server. Both are worth running: each is strict where SQLite is relaxed, in ways this
package has to respect — MySQL has no `IF NOT EXISTS` on `CREATE INDEX`, PostgreSQL rejects
`AUTO_INCREMENT` — and CI fails the build if either leg quietly skips.

```bash
mysql -uroot < tests/initdb_mysql.sql
psql -d postgres -f tests/initdb_pgsql.sql

PRADO_WEBHOOKS_MYSQL_DSN='mysql:host=127.0.0.1;dbname=prado_webhooks_test' \
PRADO_WEBHOOKS_MYSQL_USER=prado_webhooks \
PRADO_WEBHOOKS_MYSQL_PASSWORD=prado_webhooks \
PRADO_WEBHOOKS_PGSQL_DSN='pgsql:host=127.0.0.1;dbname=prado_webhooks_test' \
PRADO_WEBHOOKS_PGSQL_USER=prado_webhooks \
PRADO_WEBHOOKS_PGSQL_PASSWORD=prado_webhooks \
composer unittest
```

See AGENTS.md for the conventions this package holds to.
