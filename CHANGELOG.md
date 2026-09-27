# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-27

The first release. Before it was tagged the package went through a full security review;
every finding is fixed here, and the review is recorded in the commit history rather than
as changes to a version nobody ran.

### Added

- The package, from the PRADO extension skeleton.
- `TWebhookService` and `TWebhookEndpoint`: the inbound half. One endpoint per provider,
  reachable at `index.php?webhook=<id>`, each with its own verifier and an `onWebhook`
  event. The service raises `onWebhook` for every endpoint's accepted deliveries.
- `TWebhookEventParameter`: the inbound request and the response a handler shapes, with
  array access to the decoded payload and the raw body kept separate from it.
- `TWebhookModule`, `TWebhookSender`, `TWebhookTarget` and `TWebhookDelivery`: the outbound
  half. Deliveries are signed, sent inside the request, and retried with a doubling backoff
  that honors `Retry-After`; `onSending`, `onDelivered` and `onFailed` report each one.
- `TWebhookTarget::ensure()`, which takes a target, a URL, or an application's own
  subscription row as an array -- `secret` being shorthand for an HMAC signature.
- `TWebhookRequest`: everything a signature scheme may look at -- the raw body, the headers,
  the method, the URL, the request parameters, and the peer address -- built by both halves,
  so schemes that sign the URL or the form parameters can be expressed at all.
- A general signature layer, one class per *shape* rather than per provider, each
  implementing both `IWebhookVerifier` and `IWebhookSigner` unless the shape has no outbound
  form: `THmacWebhookSignature`, `TFieldedWebhookSignature`, `TPublicKeyWebhookSignature`,
  `TJwtWebhookSignature` (HS, RS and ES at 256, 384 and 512),
  `THttpMessageWebhookSignature` (RFC 9421), `TTokenWebhookSignature`, `TIpWebhookVerifier`,
  and the `TAnyWebhookSignature` / `TAllWebhookSignature` composites.
- `TSnsWebhookVerifier`, the one provider-specific class: Amazon SNS signs a canonicalization
  of the message body's own fields, which no payload template can produce. `TopicArn` is
  required, because the certificate is Amazon's rather than any one sender's.
- Guaranteed delivery, as an alternative to sending inline: `TWebhookModule::queue()` writes
  a delivery to an `IWebhookQueue`, `TDbWebhookQueue` keeps those in a database table, and
  `TWebhookCronTask` sends them from PRADO's own cron. `TWebhookPruneCronTask` removes
  finished ones. Claiming is a lease rather than a lock, so a runner that dies mid-attempt
  has its work picked up; the guarantee is at-least-once, and the delivery id is stable
  across every attempt so a receiver can deduplicate. Write-backs name the lease, so a runner
  that finishes late cannot disturb the one that took over, and a delivery that cannot be
  built costs itself an attempt rather than ending the run. The queue is exercised against
  SQLite, MySQL and PostgreSQL.
- `onDequeue`, where an application puts back a target it deliberately did not store --
  queueing a reference rather than a secret keeps keys out of the queue table entirely.
- `BodyHashName`, which binds a delivery to its body for the schemes whose signed payload
  leaves the body out and carries a digest of it in the URL instead.
- RSASSA-PSS: `Padding` and `SaltLength` on `TPublicKeyWebhookSignature`, and
  `rsa-pss-sha512` in `THttpMessageWebhookSignature`, which is the algorithm RFC 9421
  recommends. PHP's `openssl_verify` takes no padding argument, so the key is rewritten as an
  `id-RSASSA-PSS` key carrying the hash, mask generation function and salt length, and
  OpenSSL pads accordingly; an ordinary RSA key from the provider is all that is configured.
- `PayloadFormat`, a template over `{body}`, `{method}`, `{url}`, `{timestamp}`, `{id}`,
  `{crc32}`, `{header:…}`, `{param:…}`, `{query:…}`, `{const:…}` and `{params}`, which is what
  makes the schemes in common use configuration rather than code.
- `TWebhookEncoding` (raw, hex, base64, base64url, with decoding) and `TWebhookSource`
  (header, query, parameter).
- Security properties that were written down before the tag rather than after it, and are
  what the unit suite enforces: the body is neither read past `MaxBodySize` nor decoded
  before the method, size and signature checks; a declared `Content-Length` over the limit
  is refused with a 413 before the body is read; every keyed or public-key verifier throws
  when it has no secret or key, even for a request presenting no signature, so a
  misconfigured endpoint cannot look like a stream of forgeries; a JWS `alg`, an SNS
  `SignatureVersion` and an RFC 9421 `alg` are each required to appear in a list the
  application set; `Signature-Input` is parsed as RFC 8941 structured-field syntax, with a
  duplicate component or an unimplemented component parameter failing closed; a
  certificate URL named by a request is fetched only after a signature is presented, only
  when it matches the configured pattern, and only up to `CertificateMaxSize`; base64url
  decoding is strict; `TIpWebhookVerifier` walks a forwarded-for chain from the right past
  every trusted proxy and reads `:port`, `[v6]:port` and IPv4-mapped IPv6 as the address
  they name.
- `TWebhookService::onRefused`, raised once per delivery an endpoint refused, with the
  status the provider will see and the payload undecoded. `onWebhook` is raised only for
  accepted deliveries, so a handler on the accepted path cannot be shown a forgery.
- `TWebhookEndpoint::RequireVerifier`, which makes an endpoint with no verifier a
  configuration error at boot rather than an endpoint that accepts everything. An endpoint
  configuration carrying a child element other than `signature` is refused at boot, as is a
  PHP configuration whose `endpoint` children are a list or not arrays.
- `TWebhookEventParameter::getAccepted()`, `getPayloadDecoded()`, `getPayloadIsJson()` and
  `decodePayload()`; the body is decoded on first read, after verification.
- `TPublicKeyWebhookSignature::CertificateMaxSize` (int, default 65536), and PKCS#1
  `RSA PRIVATE KEY` / `RSA PUBLIC KEY` wrapped into the PSS structure so PSS padding works
  on OpenSSL 1.1; a PSS `Algorithm` OpenSSL cannot carry is refused as
  `webhooks_pss_digest_unsupported`.
- `TJwtWebhookSignature::RequireExpiry` (bool, default false): refuse a token without `exp`.
  A header carrying `crit` is refused; the `Bearer` scheme word is matched without regard to
  case.
- `THttpMessageWebhookSignature`: `@query-param;name="…"` (RFC 9421 §2.2.8) as a covered
  component on both sides; a header component covers every instance of a repeated header
  joined by `, `; `@authority` is lower case and omits a default port.
- `TWebhookSender::MaxRetryDelay`, the ceiling on the doubling backoff and on what a
  `Retry-After` is honored for (default 60 s); `parseRetryAfter()` reads a response's
  `Retry-After` in either RFC 9110 form. `FollowRedirects` is forced off on every delivery.
  Every target is built and validated before any is delivered to or enqueued, so a bad
  specification refuses the whole call with nothing sent or stored.
- `TWebhookTarget::setUrlValidator()` / `getUrlValidator()`: one process-wide check every
  target URL must pass, so an application can refuse private, loopback and link-local
  addresses. The class docblock has the example. A target's headers merge with the defaults
  case-insensitively.
- `TWebhookSender::ContainHandlerErrors` and `TWebhookDelivery::HandlerError`: an
  `onDelivered` or `onFailed` handler that throws is recorded on the delivery instead of
  propagated when the sender is asked to contain it, which a drain does for its run.
- `TDbWebhookQueue::prune($age, $limit)` removes at most `$limit` finished rows, oldest
  first, in chunks; `TWebhookPruneCronTask::BatchSize` passes the bound. `claim()` re-checks
  that a row is still due when stamping the lease, and `remove()` with an unclaimed item
  never deletes a row another runner holds. `TWebhookModule::drain()` honors `Retry-After`,
  capped at `QueueMaxRetryDelay`.
- `TWebhookQueueItem::MAX_DELIVERY_ID_LENGTH` and `MAX_EVENT_LENGTH`; a delivery id or event
  wider than its column is refused rather than truncated, and a payload or target
  specification that will not encode as JSON is refused before anything is queued.
- Outside Apache, `Content-Type` and `Content-Length` are restored to the headers a scheme
  sees, so an RFC 9421 signature covering either verifies under php-fpm as it does under
  Apache.

[Unreleased]: https://github.com/belisoful/prado-webhooks/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/belisoful/prado-webhooks/releases/tag/v0.1.0
