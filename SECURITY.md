# Security

## Reporting a vulnerability

Report privately, not as a public issue: open a
[security advisory](https://github.com/belisoful/prado-webhooks/security/advisories/new), or
email <belisoful@icloud.com>.

Please say what an attacker gains and how you reached it. A signature that verifies when it
should not, or a request accepted from someone who should not be able to produce one, is the
kind of thing this package exists to prevent and is worth reporting even if you are unsure.

## What this package is responsible for

It decides whether an inbound webhook is authentic, and signs outbound ones. Within that:

- **Verification.** A signature that verifies for a request the provider did not send is a
  vulnerability. So is a scheme that can be made to accept a request by anything the sender
  controls -- an algorithm named in the message, a key named in the message, a component list
  chosen by the message.
- **Refusal.** A verifier that quietly answers false when it is *misconfigured* is also a
  problem: it turns an unreachable endpoint into what looks like a stream of forged requests.
  The package throws in that case, and treats that distinction as part of the contract.
- **What it does not read.** A delivery is never parsed, logged, or acted on before its
  signature has been checked.

## What it is not responsible for

- **The URLs an application sends to.** Targets come from the application; this package will
  post where it is told, including to an address inside your own network. Validate them
  before they reach `send()` or `queue()`.
- **Where secrets live.** Keys come from the application's configuration or its own storage.
  Queueing a target's secret writes it into the queue table -- documented, and avoidable with
  `onDequeue`; that choice is the application's.
- **What a handler does with a verified payload.** Verification says the delivery is genuine,
  not that its contents are safe to trust as instructions.

## Supported versions

Until 1.0 there is one supported version: the newest 0.x release. Fixes land there rather
than being backported, so an application on an older 0.x upgrades to get them. Expect the
interfaces to move between minor versions while the package settles.
