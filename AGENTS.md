# AGENTS.md

## What This Is

`belisoful/prado-webhooks`: Inbound and outbound webhooks for PRADO: a signature-verifying receiver service and a retrying sender.

## Commands

| Command | What it does |
| --- | --- |
| `composer lint` | Compile-check `src/` and `tests/` with `php -l` |
| `composer cs` | Check code style without writing (what CI runs) |
| `composer fix` | Apply php-cs-fixer |
| `composer stan` | PHPStan at the level in `phpstan.neon.dist` |
| `composer unittest` | The unit suite |
| `composer coverage` | Unit suite with a text and Clover report |
| `composer integration` | The Composer install test (needs a PRADO checkout, default `../prado.master`) |
| `composer fulltest` | The full check, in order |

Run one test or file with
`vendor/bin/phpunit --testsuite unit --filter <test, class, or directory>`. Never add or change
phpunit options beyond `--filter`; the options in `phpunit.xml` are the project's.

**The full check is `composer fulltest`: `php -l`, php-cs-fixer, PHPStan, PHPUnit, in that
order. All four must pass before code is ready to commit.**

## Architecture

Two halves that do not depend on each other, and a third piece either may use. An
application may configure any of them alone.

```
src/TWebhookService.php            inbound: the TService, routes ?webhook=<id> to an endpoint
src/TWebhookEndpoint.php           inbound: one provider -- verifier, checks, onWebhook
src/TWebhookEventParameter.php     inbound: the request, and the response a handler shapes
src/TWebhookModule.php             outbound: the bootstrap module; owns the sender and its settings
src/TWebhookSender.php             outbound: delivery, signing, the retry policy, the three events
src/TWebhookTarget.php             outbound: one subscription; ensure() takes the app's own rows
src/TWebhookDelivery.php           outbound: the event parameter during a send, the record after
src/IWebhookQueue.php              deferred: the contract a durable queue meets
src/TDbWebhookQueue.php            deferred: that contract over a database table, leased not locked
src/TWebhookQueueItem.php          deferred: one waiting delivery, and the onDequeue parameter
src/TWebhookQueueStatus.php        deferred: pending, delivered, failed
src/TWebhookCronTask.php           deferred: the cron job that drains the queue
src/TWebhookPruneCronTask.php      deferred: the cron job that removes finished deliveries
src/TWebhookTaskTrait.php          deferred: how either cron job finds the webhook module
src/TWebhookRequest.php            both: everything a scheme may look at, built by each side
src/TWebhookEncoding.php           raw, hex, base64, base64url
src/TWebhookPadding.php            pkcs1 or pss, for RSA
src/TWebhookSource.php             header, query, parameter -- where a scheme's values live
src/TWebhookConfigurationTrait.php builds children from XML or PHP configuration, identically
src/Signature/                     the interfaces, the base, and the schemes
config/classes.json                Prado3 short name => FQN, registered by extra.prado.class-map
config/errorMessages.txt           message code => text, registered by extra.prado.error-messages
tests/unit/Package/                the package standard checks, inherited by every extension
tests/integration/                 installs the package into a throwaway consumer and boots it
```

The signature layer is one base plus one class per *shape*, never per provider:

```
TWebhookSignature              abstract: source, encoding, freshness, payload template, body digest
  THmacWebhookSignature        a keyed hash in a value of its own
    TFieldedWebhookSignature   the same, packed into one value as named fields
  TTokenWebhookSignature       a shared secret presented as it is
  TPublicKeyWebhookSignature   an asymmetric signature; a configured key, or one the delivery names
    TSnsWebhookVerifier        Amazon SNS -- verify only; the signature is in the body
  TJwtWebhookSignature         a JWS bearer token, HS/RS/ES, with claim checks
  THttpMessageWebhookSignature RFC 9421, where the message lists what it covers
TIpWebhookVerifier             an address allow list -- verify only; an address cannot be sent
TCompositeWebhookSignature     abstract: TAny... (rotation) and TAll... (layering)
```

Shared pieces are traits, so they stay out of the class map: `TWebhookSecretTrait` (the
secret and what providers do to it before it is a key), `TWebhookKeyTrait` (PEM or a path),
`TWebhookEcdsaTrait` (raw coordinates to DER and back, for both JWS and RFC 9421), and
`TWebhookRsaPssTrait` (rewriting an RSA key as an `id-RSASSA-PSS` key, which is how PSS is
reached at all -- `openssl_sign` and `openssl_verify` take no padding argument, and OpenSSL
pads according to the key type).

`PayloadFormat` is what keeps the class list short: the template tokens in
`TWebhookSignature` express what each provider signs, and `BodyHashName` binds the body when
the template leaves it out. **Add a token before adding a class, and add a class before
adding a provider-specific one.** Only two of these are named after a provider, and each is
there because no template could produce what it signs:

- `TSnsWebhookVerifier` -- the signed string is a canonicalization of the *body's* own
  fields, in an order that depends on the message type.
- nothing else. RFC 9421 is a specification rather than a vendor, and everything else in the
  wild is configuration.

Every scheme except `TIpWebhookVerifier`, `TSnsWebhookVerifier` and the composites
implements **both** `IWebhookVerifier` and `IWebhookSigner`, and each runs both directions
through one place. That is what makes "what this package signs, it verifies" a property
rather than a promise; keep it that way when adding a scheme.

## Invariants

These are what the package standard checks enforce. Breaking one fails the unit suite.

- Every type in `src/` has a namespace matching its path under the single PSR-4 root, and a file
  name matching the type it declares.
- Classes, traits, and enums are prefixed `T`; interfaces are prefixed `I`; both continue in
  PascalCase.
- Every class, interface, and enum in `src/` is listed in `config/classes.json`, mapped to its
  fully qualified name. Traits are exempt: they have no short name to resolve.
- Every error code raised in `src/` has text in `config/errorMessages.txt`, and every message in
  that file is raised somewhere in `src/`. No duplicate keys.
- Extension settings live under `extra.prado`. The un-nested `extra.bootstrap` is deprecated; do
  not reintroduce it.
- The bootstrap class autoloads, is a `TModule`, and lives under the PSR-4 root.

Two more that the checks cannot see:

- Changes stay backward compatible.
- New public classes and methods carry PHPDoc with `@param`, `@return`, `@throws`, `@author`,
  and `@since` set to the next release version. Dynamic events (`dy*`) are documented with
  `@method` on the class, because no class declares them.

## Conventions

- Tabs for indentation. PascalCase classes, camelCase methods and variables,
  SCREAMING_SNAKE_CASE constants. `php-cs-fixer` settles the rest; run `composer fix` rather
  than hand-formatting.
- Properties are a getter and setter pair (`getPropertyA`/`setPropertyA`), with the setter
  coercing through `TPropertyValue`.
- Throw PRADO exceptions (`TConfigurationException`, `TInvalidDataValueException`,
  `TInvalidOperationException`) with a message code, never a literal string.
- Page templates are `.page`, control templates `.tpl`.
- A package declares its own messages and class map in `config/`. `TPluginModule` also looks for
  an `errorMessages.txt` beside the module class; this package does not use that path, because
  `extra.prado.error-messages` applies even when the module is not configured.

## Webhook rules

These are security properties, not preferences. Breaking one is a vulnerability even when
every test still passes.

- **Verify against the raw body.** The bytes as received, never a re-encoded copy of the
  decoded payload: whitespace and key order are part of what the provider hashed.
- **Compare with `hash_equals`.** Never `===`, and never report *which* part of a signature
  was wrong.
- **Return false, do not throw, for anything an attacker controls** -- a missing header, a
  malformed signature, a stale timestamp. Throw only when the *configuration* is unusable, so
  a verifier with no secret cannot degrade into an endpoint that reports forgeries.
- **Check cheap things first.** Method, then size, then signature, then anything that reads
  the payload. An unauthenticated caller must not be able to make the endpoint hash an
  arbitrarily large body.
- **Answer a refused delivery with a status, never an exception.** A PRADO error page reaching
  a provider is a 500 -- so it retries -- and an information leak.
- **Sign per attempt, not per delivery.** A timestamped signature made before a backoff is
  stale by the time the retry arrives.
- **Do not follow redirects when delivering.** Following one posts the signed body somewhere
  the subscriber did not name.
- **Never fetch a URL that came out of a request** without an allow list the application
  configured. A certificate URL in a header is an instruction from a stranger, and following
  it unchecked is a server-side request forgery that ends in an attacker-chosen key.
- **Never let a message say how it should be checked.** A JWS `alg`, an SNS
  `SignatureVersion`, an RFC 9421 `alg`: read it, then require it to appear in a list the
  application set. The `none` algorithm and key-type substitution both close here and
  nowhere else.
- **Never let a message say what it signed, either.** RFC 9421's `Signature-Input` lists the
  covered components, and a signature over `@method` alone is perfectly valid; the
  application's `RequiredComponents` is what makes it mean something.
- **A shared certificate authority is not an identity.** Every SNS message in every AWS
  account verifies against the same chain, so the topic check is what makes a message
  yours. Any scheme where the key is not per-sender needs an equivalent.
- **An address allow list authenticates the peer, not the request**, and a forwarded header
  is written by whoever is talking to you. Believe one only from a trusted hop, and only the
  entry that hop added.
- **Never log a secret, a token, or a signature header**, and think twice before writing one
  to a table. The queue refuses to store a built target's signer for this reason; anything
  added there should refuse the same way rather than quietly dropping it, which would send
  the delivery unsigned.
- **A queue is at-least-once, so a delivery id is load-bearing.** It has to be the same on
  every attempt -- across retries inside a run and across the hours a queued delivery
  spans -- or a receiver cannot tell a repeat from a new event.
- **A lease has to fence the write-back, not just the claim.** A runner that finishes after
  its lease expired must not be able to overwrite or delete the row somebody else now holds;
  every write names the lease token. Guarding only the claim looks correct and is not.
- **A drain must survive its worst row.** One delivery that cannot be built has to cost that
  delivery an attempt, not end the run -- a run that dies part way is claimed again next
  time, so an uncontained failure stops the queue permanently rather than once.

## PRADO framework notes

The framework is at `vendor/pradosoft/prado/`, with its own `AGENTS.md`. What matters most here:

- Everything descends from `TComponent`, which supplies dynamic properties (`__get`/`__set`),
  behaviors, and dynamic events.
- `dy*` methods are dynamic events implemented by attached behaviors, not by the calling class.
  The first parameter is filtered and returned.
- `fx*` methods are global events, registered according to `getAutoGlobalListen()`.
- Events are raised in priority order.
- Application lifecycle: `onInitComplete` → `onBeginRequest` → `onLoadState` →
  `onLoadStateComplete` → `onAuthentication` → `onAuthenticationComplete` → `onAuthorization` →
  `onAuthorizationComplete` → `onPreRunService` → `runService` → `onSaveState` →
  `onSaveStateComplete` → `onPreFlushOutput` → `flushOutput` → `onEndRequest` (or `onError`).
- `TPageService::onPreRunPage` gives a module access to the page lifecycle before it runs.
- Application configuration is XML or PHP.

## Testing

- New code ships with unit tests covering typical cases, edge cases, and error paths.
- The queue suite lives once in `tests/test_tools/TWebhookQueueDriverTestCase.php` and runs
  per driver through a subclass -- SQLite, MySQL, PostgreSQL. SQLite alone proves nothing
  about the DDL, the auto-increment spelling, or a repeated placeholder, each of which has
  already been wrong on one server while green on another. Anything touching SQL goes in the
  shared case rather than a subclass, and CI fails when a driver's leg skips.
- Tests are isolated: no shared state between them.
- When working on one class or cluster, run only those tests with `--filter`.

## Safeguards -- ANTI-PATTERNS

Required without exception:

- NEVER run these `git` commands without asking first: clone, checkout, mv, restore, rm, branch,
  add, commit, merge, rebase, reset, pull, push, fetch.
- NEVER run `rm` on any path without asking first.
- NEVER remove composer `--dev` dependencies; they are required to develop the package.
- NEVER erase or overwrite files while unit testing and fixing. The file changes are the thing
  under test.
- NEVER delete a folder or file until the task it belongs to is completely finished.
