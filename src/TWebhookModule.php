<?php

/**
 * TWebhookModule class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner;
use Composer\InstalledVersions;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\TPropertyValue;
use Prado\Web\TMediaType;
use Prado\Util\TPluginModule;
use Throwable;

/**
 * TWebhookModule class.
 *
 * The package's bootstrap module, named by `extra.prado.bootstrap`, and the thing an
 * application calls to send a webhook. It owns a
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookSender} and the settings and signature that
 * sender uses, so an application configures outbound webhooks in one place:
 *
 * ```xml
 * <modules>
 *		<module id="belisoful/prado-webhooks" Timeout="5" MaxAttempts="3">
 *			<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *				Secret="..." TimestampHeader="X-Webhook-Timestamp"
 *				PayloadFormat="{timestamp}.{body}" />
 *		</module>
 * </modules>
 * ```
 *
 * The module is loaded by package name rather than by class; the class comes from
 * composer.json. Sending is then one call, with whatever list of subscribers the
 * application keeps:
 *
 * ```php
 * $webhooks = $this->getApplication()->getModule('belisoful/prado-webhooks');
 * $webhooks->send($subscriberRows, ['invoice' => $invoice], 'invoice.paid');
 * ```
 *
 * The `signature` child above is the fallback for targets that bring no secret of their
 * own. Per-subscriber secrets belong on the target, and
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookTarget::ensure} takes them straight from an
 * application's own rows.
 *
 * ## Sending now, or sending for certain
 *
 * {@see send} delivers inside the request that called it. It is the right thing while the
 * targets are quick and the occasional lost delivery is survivable -- a request that fails
 * after send() returns has already sent, and one that dies during it has not.
 *
 * {@see queue} writes the delivery down instead and returns. A cron run picks it up, retries
 * it over hours rather than seconds, and keeps it through a deploy, a crash, or a receiver
 * that is down all afternoon. Set `QueueID` to turn it on:
 *
 * ```xml
 * <module id="webhook-queue" class="Belisoful\Prado\Web\Webhooks\TDbWebhookQueue"
 *		ConnectionID="db" />
 * <module id="belisoful/prado-webhooks" QueueID="webhook-queue" />
 * ```
 *
 * Both remain available; `queue()` is not a mode the module is in, it is a different call.
 *
 * Receiving is the other direction and is configured as a service: see
 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookService}. Neither half needs the other, so an
 * application that only receives need not configure this module at all -- the package's
 * class map and error messages are registered by Composer either way.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 * @method void dyDequeue(TWebhookQueueItem $item)
 */
class TWebhookModule extends TPluginModule
{
	use TWebhookConfigurationTrait;

	/** @var string the Composer package this module belongs to. */
	public const PACKAGE_NAME = 'belisoful/prado-webhooks';

	/**
	 * The version this working copy declares. {@see getVersion} prefers what Composer
	 * actually installed and falls back to this, so bump it when cutting a release.
	 * @var string
	 */
	public const VERSION = '0.1.0';

	/**
	 * The id an application loads this module under, and cron tasks look for. It is the
	 * package name because that is how `extra.prado.bootstrap` modules are configured.
	 * @var string
	 */
	public const DEFAULT_MODULE_ID = self::PACKAGE_NAME;

	/** @var int how many attempts a queued delivery gets before it is abandoned. */
	public const DEFAULT_QUEUE_MAX_ATTEMPTS = 10;

	/** @var int how long a queued delivery waits before its second attempt, in seconds. */
	public const DEFAULT_QUEUE_RETRY_DELAY = 60;

	/** @var int the longest a queued delivery ever waits between attempts, in seconds. */
	public const DEFAULT_QUEUE_MAX_RETRY_DELAY = 3600;

	/** @var null|\Belisoful\Prado\Web\Webhooks\TWebhookSender the sender this module owns */
	private ?TWebhookSender $_sender = null;

	/** @var null|\Belisoful\Prado\Web\Webhooks\IWebhookQueue where deferred deliveries wait */
	private ?IWebhookQueue $_queue = null;

	/** @var null|string the id of the queue module to use */
	private ?string $_queueId = null;

	/** @var int how many attempts a queued delivery gets */
	private int $_queueMaxAttempts = self::DEFAULT_QUEUE_MAX_ATTEMPTS;

	/** @var int how long a queued delivery waits before its second attempt, in seconds */
	private int $_queueRetryDelay = self::DEFAULT_QUEUE_RETRY_DELAY;

	/** @var int the longest a queued delivery ever waits between attempts, in seconds */
	private int $_queueMaxRetryDelay = self::DEFAULT_QUEUE_MAX_RETRY_DELAY;

	/**
	 * Configures the module, including the `signature` child that signs deliveries from
	 * targets carrying no secret of their own.
	 * @param mixed $config the module configuration.
	 * @throws \Prado\Exceptions\TConfigurationException when the signature names no class, or
	 *   names one that cannot sign.
	 */
	public function init($config): void
	{
		if (($signature = $this->childConfiguration($config, 'signature')) !== null) {
			/** @var \Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner $signer */
			$signer = $this->createConfigured($signature, IWebhookSigner::class);
			$this->setSignature($signer);
		}
		parent::init($config);
	}

	/**
	 * Returns the version of this package that is running.
	 *
	 * Composer records the version it installed a package at, which is the repository's own
	 * rather than a number written down in two places -- so that is the answer wherever there
	 * is one. There is not always one: the package being the root of a checkout means somebody
	 * is working on it, and Composer reports an untagged working copy as
	 * `1.0.0+no-version-set`, which is worse than saying nothing. {@see VERSION} answers then.
	 *
	 * @return string the version, as Composer spells it -- a release like `0.1.0`, or a branch
	 *   like `dev-main` for an application tracking one.
	 */
	public static function getVersion(): string
	{
		if (
			class_exists(InstalledVersions::class)
			&& InstalledVersions::getRootPackage()['name'] !== self::PACKAGE_NAME
			&& InstalledVersions::isInstalled(self::PACKAGE_NAME)
		) {
			return (string) InstalledVersions::getPrettyVersion(self::PACKAGE_NAME);
		}

		return self::VERSION;
	}

	/**
	 * Delivers one payload to every target that wants it.
	 *
	 * This package does not keep the list: which URLs are subscribed, to what, and under
	 * whose secret is the application's to answer, and the answer is passed in here. See
	 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookTarget::ensure} for the shapes $targets
	 * may take.
	 *
	 * @param mixed $targets the targets, or one target.
	 * @param mixed $payload the payload.
	 * @param null|string $event the event name, sent as a header and matched against each
	 *   target's subscription.
	 * @throws \Prado\Exceptions\TConfigurationException when a target cannot be built.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the payload cannot be encoded.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookDelivery[] one delivery per target that
	 *   wanted the event.
	 */
	public function send(mixed $targets, mixed $payload, ?string $event = null): array
	{
		return $this->getSender()->send($targets, $payload, $event);
	}

	/**
	 * Writes deliveries down to be sent later, instead of sending them now.
	 *
	 * {@see send} delivers inside the request that called it, which is right when the
	 * targets are quick and wrong when the request must not wait -- or when a delivery must
	 * survive the request failing halfway. This stores each delivery in the queue and
	 * returns; {@see \Belisoful\Prado\Web\Webhooks\TWebhookCronTask} sends it.
	 *
	 * ```php
	 * $webhooks->queue($subscriberRows, ['invoice' => $invoice], 'invoice.paid');
	 * ```
	 *
	 * The delivery guarantee is at-least-once: a runner that dies between a receiver
	 * accepting a delivery and the queue being told will send it again, which is what the
	 * delivery id is for.
	 *
	 * Targets are filtered here, not at drain time, so a subscription that changes in the
	 * meantime does not retroactively change what was queued.
	 *
	 * @param mixed $targets the targets, or one target. A built
	 *   {@see \Belisoful\Prado\Web\Webhooks\TWebhookTarget} carrying a signature cannot be
	 *   queued: see the exception below.
	 * @param mixed $payload the payload.
	 * @param null|string $event the event name, matched against each target's subscription.
	 * @throws \Prado\Exceptions\TConfigurationException when no queue is configured, a target
	 *   cannot be built, or a target carries something that cannot be written down -- a signer,
	 *   or any other object, at any depth of the specification. Queue the secret in the
	 *   specification, or queue a reference and rebuild the target in an `onDequeue` handler.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the payload cannot be written
	 *   down, or cannot be encoded the way a target asks -- found now, not hours later when
	 *   the drain tries to send it.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem[] what was queued.
	 */
	public function queue(mixed $targets, mixed $payload, ?string $event = null): array
	{
		$queue = $this->getQueue();
		if ($targets instanceof TWebhookTarget || is_string($targets) || !is_iterable($targets)) {
			$targets = [$targets];
		}

		// Everything is built and checked before anything is stored, so a bad specification
		// at position N is refused with nothing queued rather than after 1..N-1 were.
		$items = [];
		foreach ($targets as $spec) {
			// Checked before the target is built: an object in the specification makes
			// TWebhookTarget throw an Error of its own, and a configuration mistake deserves
			// a message that says what to do about it.
			$storable = $this->storableSpec($spec);
			$target = TWebhookTarget::ensure($spec);
			if (!$target->getEnabled() || !$target->acceptsEvent($event)) {
				continue;
			}
			$this->assertEncodable($payload, $target);
			$item = new TWebhookQueueItem($storable, $payload, $event);
			$item->setMaxAttempts($target->getMaxAttempts());
			$items[] = $item;
		}

		foreach ($items as $item) {
			$queue->enqueue($item);
		}

		return $items;
	}

	/**
	 * Refuses a payload that could not be sent to a target once it is read back.
	 *
	 * The same checks {@see TWebhookSender} makes when it encodes for the wire, made now:
	 * a payload that will not encode as JSON cannot be written to the queue at all -- the
	 * queue stores it as JSON whatever the target's content type -- and one that is not an
	 * array or object cannot be sent as a form. Left until the drain, either is a row that
	 * fails every attempt for a reason the code that queued it never saw.
	 *
	 * @param mixed $payload the payload as the application gave it.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookTarget $target the target it is for.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when it cannot be encoded.
	 * @since 0.2.0
	 */
	protected function assertEncodable(mixed $payload, TWebhookTarget $target): void
	{
		if (json_encode($payload) === false) {
			throw new TInvalidDataValueException('webhooks_payload_invalid', json_last_error_msg());
		}
		if (
			!is_string($payload)
			&& !is_array($payload)
			&& !is_object($payload)
			&& str_starts_with(strtolower($target->getContentType()), TMediaType::FORM)
		) {
			throw new TInvalidDataValueException('webhooks_payload_invalid', get_debug_type($payload));
		}
	}

	/**
	 * Reduces a target to something that can be written to the queue and read back.
	 * @param mixed $spec the target as it was given.
	 * @throws \Prado\Exceptions\TConfigurationException when it holds an object, which
	 *   cannot survive the round trip.
	 * @return array<string, mixed>|string the specification to store.
	 */
	protected function storableSpec(mixed $spec): array|string
	{
		if ($spec instanceof TWebhookTarget) {
			if ($spec->getSignature() !== null) {
				throw new TConfigurationException('webhooks_queue_signature_unsupported', static::class);
			}
			$spec = $spec->toSpec();
		}
		if (is_string($spec)) {
			return $spec;
		}
		$spec = (array) $spec;
		$this->assertStorable($spec);

		return $spec;
	}

	/**
	 * Refuses a specification that will not survive being written down and read back.
	 *
	 * Checked at every depth, not just the top: `json_encode` turns an object into whatever
	 * its public properties happen to be and a resource into null, so a signer tucked inside
	 * a header or hung off a target's Data would come back as something else entirely --
	 * silently, and having written part of itself into the table on the way.
	 *
	 * @param mixed $value the specification, or part of one.
	 * @param string $path where in the specification $value sits, for the message.
	 * @throws \Prado\Exceptions\TConfigurationException when $value holds anything but
	 *   scalars, nulls, and arrays of them.
	 */
	protected function assertStorable(mixed $value, string $path = ''): void
	{
		if (is_array($value)) {
			foreach ($value as $key => $nested) {
				$this->assertStorable($nested, $path === '' ? (string) $key : $path . '.' . $key);
			}

			return;
		}
		if ($value !== null && !is_scalar($value)) {
			throw new TConfigurationException(
				'webhooks_queue_spec_unsupported',
				$path === '' ? get_debug_type($value) : $path,
				static::class
			);
		}
	}

	/**
	 * Sends a batch of the queued deliveries that are due.
	 *
	 * One attempt each: the queue owns the retry cadence, and a delivery that fails goes
	 * back with a longer delay rather than being hammered inside one run.
	 *
	 * A delivery that cannot be attempted at all is counted as a failed attempt rather than
	 * allowed to end the run. A stored specification that will not rebuild, a signer with no
	 * key: left to propagate, one such row ends every drain before the rest of the batch, and
	 * because it is claimed again next time the queue never moves. Contained, it uses up its
	 * attempts like anything else and settles as a failed row with the reason on it.
	 *
	 * What a handler does after the request is another matter. An `onDelivered` or `onFailed`
	 * handler that throws has thrown after the receiver answered, so the answer stands: the
	 * sender is asked to contain those for the length of the run, and the delivery is
	 * recorded as it went, with the handler's exception on its
	 * {@see TWebhookDelivery::getHandlerError HandlerError} and in the row's last status.
	 * Treated as a failed attempt instead, an accepted delivery would be sent again.
	 *
	 * @param int $limit how many deliveries to take.
	 * @param int $leaseSeconds how long to hold them for.
	 * @throws \Prado\Exceptions\TConfigurationException when no queue is configured.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookDelivery[] what was attempted. A
	 *   delivery that could not be built is absent, having never become one.
	 */
	public function drain(int $limit = 20, int $leaseSeconds = 300): array
	{
		$queue = $this->getQueue();
		$sender = $this->getSender();

		$deliveries = [];
		$contained = $sender->getContainHandlerErrors();
		$sender->setContainHandlerErrors(true);
		try {
			foreach ($queue->claim($limit, $leaseSeconds) as $item) {
				try {
					$delivery = $this->attempt($sender, $item);
				} catch (Throwable $e) {
					// Thrown before or while sending: the row could not be built, or the signer
					// could not sign. That is an attempt spent.
					$item->setAttempts($item->getAttempts() + 1);
					$item->setLastStatus($e->getMessage());
					$this->failAttempt($queue, $item);

					continue;
				}
				$deliveries[] = $delivery;
				$item->setAttempts($item->getAttempts() + $delivery->getAttempts());
				$status = $delivery->getStatusText();
				if ($delivery->getHandlerError() !== null) {
					$status .= '; handler: ' . $delivery->getHandlerError();
				}
				$item->setLastStatus($status);
				try {
					$this->recordAttempt($queue, $item, $delivery);
				} catch (Throwable $e) {
					// The attempt was made and counted once; a write-back that fails does not
					// make it a second one.
					$item->setLastStatus($e->getMessage());
					$this->failAttempt($queue, $item);
				}
			}
		} finally {
			$sender->setContainHandlerErrors($contained);
		}

		return $deliveries;
	}

	/**
	 * Makes one attempt at a claimed delivery.
	 *
	 * One, not several: the queue owns the retry cadence, so the target is copied with its
	 * attempt limit set to a single try rather than letting the sender spend them all inside
	 * this run.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookSender $sender the sender to deliver with.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 * @throws \Prado\Exceptions\TConfigurationException when the stored target cannot be
	 *   rebuilt, or its signer is not configured.
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the payload cannot be encoded.
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookDelivery what happened.
	 */
	protected function attempt(TWebhookSender $sender, TWebhookQueueItem $item): TWebhookDelivery
	{
		$this->onDequeue($item);

		$target = $item->getTarget() ?? TWebhookTarget::ensure($item->getTargetSpec());
		$attempt = clone $target;
		$attempt->setMaxAttempts(1);

		return $sender->deliver($attempt, $item->getPayload(), $item->getEvent(), $item->getDeliveryId());
	}

	/**
	 * Writes back what one attempt did to a queued delivery.
	 *
	 * A failed attempt goes back with the computed backoff -- unless the receiver said when
	 * to come back. A `Retry-After` on the response is honored in place of the backoff, up
	 * to {@see getQueueMaxRetryDelay QueueMaxRetryDelay}: a receiver answering 429 with one
	 * has said exactly when trying again stops being a waste.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\IWebhookQueue $queue the queue it came from.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookDelivery $delivery what happened.
	 */
	protected function recordAttempt(IWebhookQueue $queue, TWebhookQueueItem $item, TWebhookDelivery $delivery): void
	{
		if ($delivery->getSuccessful()) {
			$queue->succeed($item);

			return;
		}
		if ($delivery->getCancel()) {
			// A handler called it off, which is a decision rather than a failure to retry.
			$item->setLastStatus('cancelled');
			$queue->abandon($item);

			return;
		}
		$retryAfter = $this->retryAfterFor($delivery);
		if ($retryAfter === null) {
			$this->failAttempt($queue, $item);

			return;
		}
		$this->retryOrAbandon($queue, $item, min($retryAfter, $this->_queueMaxRetryDelay));
	}

	/**
	 * Reads how long the receiver asked to be left alone for, when it said.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookDelivery $delivery what happened.
	 * @return null|int the `Retry-After` of the last response in whole seconds, rounded up,
	 *   or null when there was no response or it named none.
	 * @since 0.2.0
	 */
	protected function retryAfterFor(TWebhookDelivery $delivery): ?int
	{
		$response = $delivery->getResponse();
		if ($response === null) {
			return null;
		}
		$milliseconds = $this->getSender()->parseRetryAfter($response);

		return $milliseconds === null ? null : (int) ceil($milliseconds / 1000);
	}

	/**
	 * Puts a delivery back for another go, or gives up on it.
	 * @param \Belisoful\Prado\Web\Webhooks\IWebhookQueue $queue the queue it came from.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery,
	 *   carrying its updated attempt count.
	 */
	protected function failAttempt(IWebhookQueue $queue, TWebhookQueueItem $item): void
	{
		$this->retryOrAbandon($queue, $item, $this->retryDelayFor($item->getAttempts()));
	}

	/**
	 * Puts a delivery back to be tried again after a given delay, or gives up on it when it
	 * has had every attempt it gets.
	 * @param \Belisoful\Prado\Web\Webhooks\IWebhookQueue $queue the queue it came from.
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery,
	 *   carrying its updated attempt count.
	 * @param int $delaySeconds how long before it is due again.
	 * @since 0.2.0
	 */
	protected function retryOrAbandon(IWebhookQueue $queue, TWebhookQueueItem $item, int $delaySeconds): void
	{
		if ($item->getAttempts() >= ($item->getMaxAttempts() ?: $this->_queueMaxAttempts)) {
			$queue->abandon($item);

			return;
		}
		$queue->reschedule($item, max(0, $delaySeconds));
	}

	/**
	 * @param int $attempts how many attempts have been made.
	 * @return int how long to wait before the next one, in seconds.
	 */
	protected function retryDelayFor(int $attempts): int
	{
		return (int) min(
			$this->_queueRetryDelay * (2 ** max(0, $attempts - 1)),
			$this->_queueMaxRetryDelay
		);
	}

	/**
	 * Raises the `OnDequeue` event, once per delivery a drain claimed, before it is sent.
	 *
	 * This is where an application puts back what it deliberately did not store: a handler
	 * that looks a subscriber up and sets
	 * {@see \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem::setTarget Target} keeps
	 * secrets out of the queue table entirely.
	 *
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookQueueItem $item the claimed delivery.
	 */
	public function onDequeue(TWebhookQueueItem $item): void
	{
		$this->raiseEvent('onDequeue', $this, $item);
	}

	/**
	 * @return bool whether a queue is configured, so {@see queue} and {@see drain} can be used.
	 */
	public function getHasQueue(): bool
	{
		return $this->_queue !== null || $this->_queueId !== null;
	}

	/**
	 * @throws \Prado\Exceptions\TConfigurationException when none is configured, or the id
	 *   names something that is not a queue.
	 * @return \Belisoful\Prado\Web\Webhooks\IWebhookQueue where deferred deliveries wait.
	 */
	public function getQueue(): IWebhookQueue
	{
		if ($this->_queue === null) {
			if ($this->_queueId === null) {
				throw new TConfigurationException('webhooks_queue_required', static::class);
			}
			$queue = $this->getApplication()?->getModule($this->_queueId);
			if (!($queue instanceof IWebhookQueue)) {
				throw new TConfigurationException('webhooks_queue_invalid', $this->_queueId, static::class);
			}
			$this->_queue = $queue;
		}

		return $this->_queue;
	}

	/**
	 * @param null|\Belisoful\Prado\Web\Webhooks\IWebhookQueue $value where deferred
	 *   deliveries wait.
	 */
	public function setQueue(?IWebhookQueue $value): void
	{
		$this->_queue = $value;
	}

	/**
	 * @return null|string the id of the queue module in use.
	 */
	public function getQueueID(): ?string
	{
		return $this->_queueId;
	}

	/**
	 * @param mixed $value the id of a module implementing
	 *   {@see \Belisoful\Prado\Web\Webhooks\IWebhookQueue}, such as
	 *   {@see \Belisoful\Prado\Web\Webhooks\TDbWebhookQueue}.
	 */
	public function setQueueID($value): void
	{
		$id = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_queueId = $id === '' ? null : $id;
		$this->_queue = null;
	}

	/**
	 * @return int how many attempts a queued delivery gets. Defaults to
	 *   {@see DEFAULT_QUEUE_MAX_ATTEMPTS}.
	 */
	public function getQueueMaxAttempts(): int
	{
		return $this->_queueMaxAttempts;
	}

	/**
	 * @param mixed $value the attempt limit for queued deliveries; at least 1. Higher than
	 *   the sender's, because these are spread over hours rather than over one request.
	 */
	public function setQueueMaxAttempts($value): void
	{
		$this->_queueMaxAttempts = max(1, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int how long a queued delivery waits before its second attempt, in seconds.
	 *   Defaults to {@see DEFAULT_QUEUE_RETRY_DELAY}.
	 */
	public function getQueueRetryDelay(): int
	{
		return $this->_queueRetryDelay;
	}

	/**
	 * @param mixed $value the first retry delay in seconds; it doubles on each further
	 *   attempt, up to {@see getQueueMaxRetryDelay QueueMaxRetryDelay}.
	 */
	public function setQueueRetryDelay($value): void
	{
		$this->_queueRetryDelay = max(0, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return int the longest a queued delivery ever waits between attempts, in seconds.
	 *   Defaults to {@see DEFAULT_QUEUE_MAX_RETRY_DELAY}.
	 */
	public function getQueueMaxRetryDelay(): int
	{
		return $this->_queueMaxRetryDelay;
	}

	/**
	 * @param mixed $value the delay ceiling in seconds; without one, doubling reaches days.
	 */
	public function setQueueMaxRetryDelay($value): void
	{
		$this->_queueMaxRetryDelay = max(1, TPropertyValue::ensureInteger($value));
	}

	/**
	 * @return \Belisoful\Prado\Web\Webhooks\TWebhookSender the sender, created on first use.
	 *   Attach handlers to its events to log or record deliveries.
	 */
	public function getSender(): TWebhookSender
	{
		if ($this->_sender === null) {
			$this->_sender = new TWebhookSender();
		}

		return $this->_sender;
	}

	/**
	 * @param \Belisoful\Prado\Web\Webhooks\TWebhookSender $value the sender to use instead of
	 *   the default one.
	 */
	public function setSender(TWebhookSender $value): void
	{
		$this->_sender = $value;
	}

	/**
	 * @return int the per-request timeout in seconds.
	 */
	public function getTimeout(): int
	{
		return $this->getSender()->getTimeout();
	}

	/**
	 * @param mixed $value the timeout in seconds. Deliveries are sent inside the request
	 *   that triggered them, so this is time a page can spend waiting.
	 */
	public function setTimeout($value): void
	{
		$this->getSender()->setTimeout($value);
	}

	/**
	 * @return int how many times a delivery is attempted.
	 */
	public function getMaxAttempts(): int
	{
		return $this->getSender()->getMaxAttempts();
	}

	/**
	 * @param mixed $value the attempt count, including the first; 1 disables retrying.
	 */
	public function setMaxAttempts($value): void
	{
		$this->getSender()->setMaxAttempts($value);
	}

	/**
	 * @return int the first retry delay in milliseconds.
	 */
	public function getRetryDelay(): int
	{
		return $this->getSender()->getRetryDelay();
	}

	/**
	 * @param mixed $value the first retry delay in milliseconds; it doubles on each further
	 *   attempt.
	 */
	public function setRetryDelay($value): void
	{
		$this->getSender()->setRetryDelay($value);
	}

	/**
	 * @return int[] the statuses worth trying again.
	 */
	public function getRetryStatusCodes(): array
	{
		return $this->getSender()->getRetryStatusCodes();
	}

	/**
	 * @param mixed $value the statuses, as an array or a comma separated list.
	 */
	public function setRetryStatusCodes($value): void
	{
		$this->getSender()->setRetryStatusCodes($value);
	}

	/**
	 * @return string the User-Agent deliveries carry.
	 */
	public function getUserAgent(): string
	{
		return $this->getSender()->getUserAgent();
	}

	/**
	 * @param mixed $value the User-Agent deliveries carry.
	 */
	public function setUserAgent($value): void
	{
		$this->getSender()->setUserAgent($value);
	}

	/**
	 * @return null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner the signer used for
	 *   targets that carry none of their own.
	 */
	public function getSignature(): ?IWebhookSigner
	{
		return $this->getSender()->getSignature();
	}

	/**
	 * @param null|\Belisoful\Prado\Web\Webhooks\Signature\IWebhookSigner $value the signer.
	 */
	public function setSignature(?IWebhookSigner $value): void
	{
		$this->getSender()->setSignature($value);
	}
}
