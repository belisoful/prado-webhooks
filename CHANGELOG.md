# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release will be 0.1.0.

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
