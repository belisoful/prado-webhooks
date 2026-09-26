<?php

/**
 * TWebhookRequest class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Prado\TComponent;
use Prado\TPropertyValue;

/**
 * TWebhookRequest class.
 *
 * Everything a signature scheme is allowed to look at, in one object: the raw body, the
 * headers, the method, the URL, the request parameters, and the address it came from.
 * Both directions build one -- {@see TWebhookEndpoint} from the request it received,
 * {@see TWebhookSender} from the request it is about to make -- so a scheme signs and
 * verifies against the same shape and cannot accidentally depend on being on one side.
 *
 * The URL and the parameters are here because not every provider signs the body alone.
 * Square signs the URL followed by the body, Twilio signs the URL followed by its sorted
 * form parameters, and Mailgun signs values it posted in the body. A verifier that could
 * see only the body could not express any of them.
 *
 * {@see getBody Body} is the bytes as received, byte for byte. Nothing in this package
 * re-encodes it before verification, because whitespace and key order are part of what the
 * provider hashed.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
class TWebhookRequest extends TComponent
{
	/** @var string the HTTP method, upper case */
	private string $_method = 'POST';

	/** @var string the raw body, byte for byte */
	private string $_body = '';

	/** @var array<string, string|string[]> the headers, in whatever case they arrived */
	private array $_headers = [];

	/** @var string the absolute URL of the request */
	private string $_url = '';

	/** @var array<string, mixed> the request parameters, as the server parsed them */
	private array $_parameters = [];

	/** @var null|string the address the request came from */
	private ?string $_remoteAddress = null;

	/**
	 * @param string $method the HTTP method.
	 * @param string $body the raw body.
	 * @param array<string, string|string[]> $headers the headers; a repeated header may
	 *   arrive as a list, and reads as its first value.
	 * @param string $url the absolute URL, for schemes that sign it.
	 * @param array<string, mixed> $parameters the request parameters, for schemes that
	 *   read or sign them. A nested value -- what `a[b]=c` parses to -- has no defined
	 *   serialization here and is skipped rather than guessed at.
	 * @param null|string $remoteAddress the address the request came from.
	 */
	public function __construct(
		string $method = 'POST',
		string $body = '',
		array $headers = [],
		string $url = '',
		array $parameters = [],
		?string $remoteAddress = null
	) {
		$this->_method = strtoupper($method);
		$this->_body = $body;
		$this->_headers = $headers;
		$this->_url = $url;
		$this->_parameters = $parameters;
		$this->_remoteAddress = $remoteAddress;
		parent::__construct();
	}

	/**
	 * Returns a copy of this request with different headers, which is how a signer's output
	 * is folded back in without the original being mutated underneath a caller.
	 * @param array<string, string|string[]> $headers the headers of the copy.
	 * @return self the copy.
	 */
	public function withHeaders(array $headers): self
	{
		$request = clone $this;
		$request->_headers = $headers;

		return $request;
	}

	/**
	 * Returns a copy of this request with a different body.
	 * @param string $body the body of the copy.
	 * @return self the copy.
	 */
	public function withBody(string $body): self
	{
		$request = clone $this;
		$request->_body = $body;

		return $request;
	}

	/**
	 * @return string the HTTP method, upper case.
	 */
	public function getMethod(): string
	{
		return $this->_method;
	}

	/**
	 * @param mixed $value the HTTP method.
	 */
	public function setMethod($value): void
	{
		$this->_method = strtoupper(TPropertyValue::ensureString($value));
	}

	/**
	 * @return string the raw body, byte for byte as received or as it will be sent.
	 */
	public function getBody(): string
	{
		return $this->_body;
	}

	/**
	 * @param mixed $value the raw body.
	 */
	public function setBody($value): void
	{
		$this->_body = TPropertyValue::ensureString($value);
	}

	/**
	 * @return array<string, string|string[]> the headers, in whatever case they arrived.
	 */
	public function getHeaders(): array
	{
		return $this->_headers;
	}

	/**
	 * @param array<string, string|string[]> $value the headers.
	 */
	public function setHeaders(array $value): void
	{
		$this->_headers = $value;
	}

	/**
	 * Reads one header without regard to the case of its name, which is what makes a scheme
	 * independent of the web server that parsed the request.
	 * @param string $name the header name.
	 * @return null|string the header value, or null when the header is absent.
	 */
	public function getHeader(string $name): ?string
	{
		foreach ($this->_headers as $key => $value) {
			if (strcasecmp((string) $key, $name) !== 0) {
				continue;
			}
			if (is_array($value)) {
				// A repeated header reads as its first value; one that arrived as an empty
				// list is absent rather than an empty string.
				$value = array_shift($value);
			}

			return $value === null ? null : (string) $value;
		}

		return null;
	}

	/**
	 * @return string the absolute URL of the request, or an empty string when it is not known.
	 */
	public function getUrl(): string
	{
		return $this->_url;
	}

	/**
	 * @param mixed $value the absolute URL.
	 */
	public function setUrl($value): void
	{
		$this->_url = TPropertyValue::ensureString($value);
	}

	/**
	 * @return array<string, mixed> the request parameters.
	 */
	public function getParameters(): array
	{
		return $this->_parameters;
	}

	/**
	 * @param array<string, mixed> $value the request parameters.
	 */
	public function setParameters(array $value): void
	{
		$this->_parameters = $value;
	}

	/**
	 * Reads one request parameter. Unlike a header, a parameter name is case sensitive.
	 * @param string $name the parameter name.
	 * @return null|string the parameter value, or null when it is absent or not a scalar.
	 */
	public function getParameterValue(string $name): ?string
	{
		$value = $this->_parameters[$name] ?? null;

		return is_scalar($value) ? (string) $value : null;
	}

	/**
	 * Returns the parameters of the URL's query string alone.
	 *
	 * The URL is the caller's, so the query is bounded before it is parsed: `parse_str`
	 * warns past `max_input_vars`, PRADO turns the warning into an exception, and an
	 * exception here would be a 500 that anyone can cause. A query with more pairs than
	 * the limit reads as empty instead, and a scheme that needed one of them refuses.
	 *
	 * @return array<string, string> the query parameters, or none when there are more than
	 *   `max_input_vars` of them.
	 */
	public function getQueryParameters(): array
	{
		$query = parse_url($this->_url, PHP_URL_QUERY);
		if (!is_string($query) || $query === '') {
			return [];
		}
		$limit = (int) ini_get('max_input_vars');
		if ($limit > 0 && count(explode('&', $query)) > $limit) {
			return [];
		}
		parse_str($query, $parameters);

		return array_map(static fn ($value) => is_scalar($value) ? (string) $value : '', $parameters);
	}

	/**
	 * @return null|string the address the request came from, or null when it is not known.
	 */
	public function getRemoteAddress(): ?string
	{
		return $this->_remoteAddress;
	}

	/**
	 * @param mixed $value the address the request came from.
	 */
	public function setRemoteAddress($value): void
	{
		$address = trim(TPropertyValue::ensureString($value ?? ''));
		$this->_remoteAddress = $address === '' ? null : $address;
	}
}
