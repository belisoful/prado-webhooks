# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

An audit release: every finding of a full review of the package, fixed and tested.

### Security

- `TSnsWebhookVerifier`: a message whose `SignatureVersion`, `Type`, or any signed field is
  a list, object, boolean, or null is refused instead of raising a type error the provider
  would see as a 500; `canonicalString()` no longer errors on a non-string `Type`.
- `TPublicKeyWebhookSignature`: a certificate URL named by the request is fetched only
  after the request has presented a signature, so an unsigned body cannot trigger a
  network round trip; a fetched body is cached only when OpenSSL reads it as a key, and
  one larger than the new `CertificateMaxSize` (default 65536) is refused.
- `TSnsWebhookVerifier::DEFAULT_CERTIFICATE_URL_PATTERN` requires a `.pem` path with no
  query string or fragment, as Amazon's own validator does.
- `TPublicKeyWebhookSignature`: a presented value that does not carry the configured
  `Prefix` is no longer accepted as a candidate, matching the keyed schemes.
- `TJwtWebhookSignature`: a present but non-numeric `exp` or `nbf` refuses the token; a
  header carrying `crit` (RFC 7515 §4.1.11) is refused.
- `TJwtWebhookSignature` and `THttpMessageWebhookSignature`: with an algorithm list mixing
  key families and only one family configured, a message declaring the other is refused
  rather than raising a configuration exception of the sender's choosing; a verifier with
  no key for any allowed algorithm still throws.
- `THttpMessageWebhookSignature`: `Signature-Input` is parsed as RFC 8941 structured-field
  syntax -- parameters attached to a component no longer leak into the component list or
  the signature parameters, a quoted value holding `;` or `\"` is one value, a duplicate
  component refuses the signature, and a component carrying a parameter this class does
  not implement (`sf`, `bs`, `key`, `req`, `tr`) fails closed. `created` and `expires`
  must be Integers; a non-numeric `expires` refuses the signature instead of being ignored.
- `THttpMessageWebhookSignature`: a header component covers every instance of a repeated
  header joined by `, ` (RFC 9421 §2.1), each trimmed with line folding collapsed;
  `Signature-Input` and `Signature` split over several header lines read as one dictionary.
- Every keyed or public-key verifier throws a configuration exception when it has no
  secret or key, even for a request that presents no signature, so it cannot degrade into
  an endpoint that reports every delivery as a forgery.
- `TWebhookEncoding::Base64Url->decode()` is strict per RFC 4648 §5 and RFC 7515: `+`,
  `/`, `=`, and whitespace are refused.
- `TIpWebhookVerifier`: a forwarded-for chain is walked from the right past every trusted
  proxy, so multi-hop proxy setups judge the real caller; a `:port` suffix, `[v6]:port`
  brackets, and IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are read as the address
  they name.
- `TWebhookService::onWebhook` is raised only for deliveries an endpoint accepted. It was
  raised for every request, so a service-level handler written to the documented contract
  saw refused -- and possibly forged -- deliveries with their payload populated, and could
  overwrite the 401. Refused deliveries now raise the new `onRefused` event instead, which
  may swap one refusal for another but cannot turn one into a success.
- The body is no longer decoded before the method, size and signature checks. It was
  decoded in the event parameter's constructor, so an unauthenticated caller could make
  the endpoint parse a body up to PHP's own limit; it is now decoded on first read, after
  verification, and `TWebhookEventParameter::getPayloadDecoded()` says whether it has been.
- A request whose declared `Content-Length` exceeds the endpoint's `MaxBodySize` is
  refused with a 413 before the body is read.
- `TWebhookRequest::getQueryParameters()` no longer throws when the query string carries
  more pairs than `max_input_vars`; the URL is the caller's, and that was a 500 anyone
  could cause. Such a query reads as empty and the scheme refuses.
- `TSnsWebhookVerifier` no longer throws on a message whose `SignatureVersion` -- or any
  other field it reads -- is not a string. A body with a valid topic and an array there
  was a 500 to the provider, which then retried forever.

### Added

- `TPublicKeyWebhookSignature::CertificateMaxSize` (int, default 65536).
- `TJwtWebhookSignature::RequireExpiry` (bool, default false): refuse a token without
  `exp`. The `Bearer` scheme word is matched without regard to case; a prefix that does
  not end in a space is matched exactly.
- `THttpMessageWebhookSignature`: `@query-param;name="…"` (RFC 9421 §2.2.8) as a covered
  component on both sides; `RequiredComponents` accepts it in any spelling.
- Error message `webhooks_pss_digest_unsupported`.
- `TWebhookSender::MaxRetryDelay`, the ceiling on the doubling backoff and on what a
  `Retry-After` is honored for (default 60 s); `parseRetryAfter()` reads a response's
  `Retry-After` in either RFC 9110 form, uncapped.
- `TWebhookTarget::setUrlValidator()` / `getUrlValidator()`: one process-wide check every
  target URL must pass, so an application can refuse private, loopback and link-local
  addresses. The class docblock has the example.
- `TWebhookSender::ContainHandlerErrors` and `TWebhookDelivery::HandlerError`: an
  `onDelivered` or `onFailed` handler that throws is recorded on the delivery instead of
  propagated when the sender is asked to contain it, which a drain does for its run.
- `TDbWebhookQueue::prune($age, $limit)` removes at most `$limit` finished rows, oldest
  first, in chunks; `TWebhookPruneCronTask::BatchSize` passes the bound.
- `TWebhookQueueItem::MAX_DELIVERY_ID_LENGTH` and `MAX_EVENT_LENGTH`; a delivery id or
  event wider than its column is refused rather than truncated.
- `TWebhookService::onRefused`, raised once per delivery an endpoint refused, with the
  status the provider will see and the payload undecoded.
- `TWebhookEndpoint::RequireVerifier`, which makes an endpoint with no verifier a
  configuration error at boot rather than an endpoint that accepts everything.
- `TWebhookEventParameter::getAccepted()`, `getPayloadDecoded()`, `getPayloadIsJson()` and
  `decodePayload()`.

### Changed

- `{params}`, `{param:name}` and `Source="parameter"` mean the posted form fields alone:
  the scalar entries of `$_POST`. `TWebhookService::getRequestParameters()` read the
  framework's merged view of the request, which put the URL's `?webhook=<id>` and the rest
  of the query string among them, so a Twilio-shaped `{url}{params}` hashed values Twilio
  never signed and refused every delivery. The query string stays reachable through
  `{url}`, `{query:name}` and `Source="query"`.
- `TWebhookSender` shows a scheme the decoded fields of a form-encoded body as the request
  parameters -- per attempt, and by the `Content-Type` actually sent -- so a delivery signed
  with `{url}{params}` verifies through `TWebhookService` at the other end. It showed none,
  so what this package signed under `{params}` was not what a PRADO receiver computed.
- `TWebhookSender::send()` and `TWebhookModule::queue()` build and validate every target
  before delivering to or enqueueing any, so a bad specification refuses the whole call
  with nothing sent or stored.
- An HTTP-date `Retry-After` is honored as the time until then, capped, where it used to
  fall back to the backoff; a negative one waits nothing rather than a negative time.
- `TWebhookModule::drain()` honors a response's `Retry-After`, in seconds and capped at
  `QueueMaxRetryDelay`, in place of the computed backoff; contains handler exceptions for
  the run so an accepted delivery is never rescheduled because a handler threw; and counts
  an attempt once even when the write-back fails.
- `TWebhookTarget::buildHeaders()` merges a target's headers case-insensitively, so a
  `content-type` replaces the default `Content-Type` instead of sending both.
- `TWebhookTarget::ensure()` refuses a built target with no URL, and reports an unknown
  specification key as a `TConfigurationException` naming the key.
- `TWebhookSender::pause()` waits in chunks of at most one second, since `usleep` above
  that is not portable.
- `TWebhookQueueItem` marks a trimmed last status with `...` rather than a UTF-8 ellipsis,
  which a latin1 table cannot hold.
- `TDbWebhookQueue` creates its MySQL table with `DEFAULT CHARSET=utf8mb4`; its docblock
  names SQLite, MySQL and PostgreSQL rather than every driver, and notes that lease times
  come from the runner's clock.
- `TWebhookTaskTrait::getWebhookModule()` no longer writes the default id into `ModuleId`.
- An endpoint configuration carrying a child element other than `signature` is refused at
  boot; a misspelled `signatrue` was silently ignored, leaving the endpoint open.
- A PHP configuration whose `endpoint` children are a list, or whose child is not an
  array, is refused rather than built as an empty, verifier-less endpoint at `?webhook=0`.
- `RequireJson` asks whether the body is JSON rather than whether it decoded to something
  other than null, so a body holding the literal `null` is accepted as JSON.
- A status code outside 100 to 599 is refused where it is set -- `SuccessStatus="ok"`
  coerced to 0 and became an error page on every accepted delivery -- and a status the
  framework has no reason phrase for is sent with one rather than thrown over.
- A response body set on the default 204 is answered as a 200, since a 204 cannot carry
  one; a string body defaults to `text/plain` and an encoded one to `application/json`.
- An array response body that cannot be encoded throws rather than answering with an
  empty body and a success.
- Outside Apache, `Content-Type` and `Content-Length` are restored to the headers a scheme
  sees; CGI hands them to PHP without the `HTTP_` prefix and the framework left them out,
  so an RFC 9421 signature covering either verified under Apache and failed under php-fpm.

### Fixed

- `TFieldedWebhookSignature`: with `IdField` set, the packed id is read from the request
  under `IdName` when present -- which is where `TWebhookSender` puts the delivery id -- so
  every attempt of one delivery packs the same id; it is minted only when the request
  carries none.
- `TWebhookRsaPssTrait`: a PKCS#1 `RSA PRIVATE KEY` (what OpenSSL 1.1 exports) or `RSA
  PUBLIC KEY` is wrapped into the PSS structure rather than refused, so PSS padding works
  on OpenSSL 1.1.
- `TPublicKeyWebhookSignature`: with `Padding="pss"`, an `Algorithm` OpenSSL knows but PSS
  cannot carry is refused as `webhooks_pss_digest_unsupported` instead of a `ValueError`
  or a misleading "key invalid".
- `THttpMessageWebhookSignature`: `@authority` is lower case and omits a default port;
  `@path` and `@request-target` of a URL with no path are `/`.
- The retry backoff overflowed to a wait of 0 at high attempt counts; the exponent is now
  capped and the wait bounded by `MaxRetryDelay`.
- `TWebhookSender` forces `FollowRedirects` off on every delivery, so a substituted client
  cannot follow a 3xx with the signed body.
- `TDbWebhookQueue::claim()` re-checks that a row is still due when stamping the lease, so
  a delivery rescheduled by another runner between the two statements is not sent before
  its backoff.
- `TDbWebhookQueue::remove()` with an unclaimed item no longer deletes a row another runner
  currently holds.
- `TDbWebhookQueue::enqueue()` refuses a payload or target specification that will not
  encode as JSON instead of storing an empty string, and `TWebhookModule::queue()` refuses
  such a payload before anything is queued.
- The configuration examples in `TWebhookConfigurationTrait` used a `webhook` element and
  a `webhooks` service id; the element is `endpoint` and the id `webhook`.

## [0.1.0] - 2026-09-22

The first release.

### Added

- The package, from the PRADO extension skeleton.
- `TWebhookService` and `TWebhookEndpoint`: the inbound half. One endpoint per provider,
  reachable at `index.php?webhook=<id>`, each with its own verifier and an `onWebhook`
  event. The service raises `onWebhook` for every endpoint's deliveries.
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

[Unreleased]: https://github.com/belisoful/prado-webhooks/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/belisoful/prado-webhooks/releases/tag/v0.1.0
