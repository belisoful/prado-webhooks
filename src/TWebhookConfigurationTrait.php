<?php

/**
 * TWebhookConfigurationTrait class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

use Belisoful\Prado\Web\Webhooks\Signature\TCompositeWebhookSignature;
use Prado\Exceptions\TConfigurationException;
use Prado\Prado;
use Prado\Xml\TXmlElement;

/**
 * TWebhookConfigurationTrait trait.
 *
 * Builds child components out of an application configuration, in either of the two forms
 * PRADO accepts. An XML application writes children as elements and their properties as
 * attributes; a PHP application writes the same thing as nested arrays. Everything in this
 * package that is configured with children -- the service with its endpoints, an endpoint
 * with its signature -- reads them through here, so the two forms cannot drift apart.
 *
 * ```xml
 * <service id="webhook" class="Belisoful\Prado\Web\Webhooks\TWebhookService">
 *		<endpoint id="github">
 *			<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *				Secret="..." Header="X-Hub-Signature-256" Prefix="sha256=" />
 *		</endpoint>
 * </service>
 * ```
 *
 * ```php
 * 'services' => [
 *		'webhook' => [
 *			'class' => TWebhookService::class,
 *			'endpoint' => [
 *				'github' => [
 *					'signature' => [
 *						'class' => THmacWebhookSignature::class,
 *						'properties' => ['Secret' => '...', 'Header' => 'X-Hub-Signature-256'],
 *					],
 *				],
 *			],
 *		],
 * ],
 * ```
 *
 * The PHP form is held to the same rules as the XML one: a child keyed by a number is a
 * list where a map was meant, and a child that is not an array is a typo, and either is
 * refused rather than built as an empty -- and so unguarded -- component.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 0.1.0
 */
trait TWebhookConfigurationTrait
{
	/**
	 * Returns the child configurations of one tag, keyed by the id each declares.
	 *
	 * In XML the id is the element's `id` attribute; in PHP it is the array key. An XML child
	 * without one is a configuration error rather than an anonymous child, because nothing
	 * could then address it in a URL.
	 *
	 * @param mixed $config this component's own configuration.
	 * @param string $tag the child element name, or array key, to collect.
	 * @throws \Prado\Exceptions\TConfigurationException when a child declares no id -- an
	 *   XML element without the attribute, or a PHP child keyed by a number -- two XML
	 *   children declare the same id, or a PHP child is not an array.
	 * @return array<string, array<string, mixed>|\Prado\Xml\TXmlElement> id => configuration.
	 */
	protected function childConfigurations(mixed $config, string $tag): array
	{
		$children = [];
		if ($config instanceof TXmlElement) {
			foreach ($config->getElementsByTagName($tag) as $child) {
				$id = $child->getAttribute('id');
				if ($id === null || $id === '') {
					throw new TConfigurationException('webhooks_child_id_required', $tag, static::class);
				}
				if (isset($children[$id])) {
					// The later element would replace the earlier one, verifier and all.
					throw new TConfigurationException('webhooks_child_id_duplicate', $tag, $id, static::class);
				}
				$children[$id] = $child;
			}
		} elseif (is_array($config) && is_array($config[$tag] ?? null)) {
			foreach ($config[$tag] as $id => $child) {
				if (is_int($id)) {
					throw new TConfigurationException('webhooks_child_id_required', $tag, static::class);
				}
				if (!is_array($child)) {
					throw new TConfigurationException('webhooks_child_invalid', $id, $tag, static::class);
				}
				$children[(string) $id] = $child;
			}
		}

		return $children;
	}

	/**
	 * Returns the child configurations of one tag, in order, for children that have no id.
	 *
	 * A composite scheme's children are a list rather than a map: nothing addresses one by
	 * name, and the same class may appear twice with different properties.
	 *
	 * @param mixed $config this component's own configuration.
	 * @param string $tag the child element name, or array key, to collect.
	 * @throws \Prado\Exceptions\TConfigurationException when a PHP child is not an array.
	 * @return array<int, array<string, mixed>|\Prado\Xml\TXmlElement> the configurations.
	 */
	protected function childConfigurationList(mixed $config, string $tag): array
	{
		$children = [];
		if ($config instanceof TXmlElement) {
			foreach ($config->getElementsByTagName($tag) as $child) {
				$children[] = $child;
			}
		} elseif (is_array($config) && is_array($config[$tag] ?? null)) {
			foreach ($config[$tag] as $index => $child) {
				if (!is_array($child)) {
					throw new TConfigurationException('webhooks_child_invalid', (string) $index, $tag, static::class);
				}
				$children[] = $child;
			}
		}

		return $children;
	}

	/**
	 * Returns the single child configuration of one tag, or null when there is none.
	 *
	 * A PHP child that is present but not an array -- a class name where the array holding
	 * one was meant, or a null -- is refused, as the plural forms refuse it. Returning null
	 * would build the parent without the child, and for an endpoint that child is the
	 * verifier.
	 *
	 * @param mixed $config this component's own configuration.
	 * @param string $tag the child element name, or array key, to read.
	 * @throws \Prado\Exceptions\TConfigurationException when a PHP child is present but not
	 *   an array.
	 * @return null|array<string, mixed>|\Prado\Xml\TXmlElement the child configuration.
	 */
	protected function childConfiguration(mixed $config, string $tag): null|array|TXmlElement
	{
		if ($config instanceof TXmlElement) {
			return $config->getElementByTagName($tag);
		}
		if (is_array($config) && array_key_exists($tag, $config)) {
			if (!is_array($config[$tag])) {
				throw new TConfigurationException('webhooks_child_not_array', $tag, static::class);
			}

			return $config[$tag];
		}

		return null;
	}

	/**
	 * Creates a component from a child configuration and applies its properties. A composite
	 * scheme is given its own `signature` children from the same configuration.
	 *
	 * @param null|array<string, mixed>|\Prado\Xml\TXmlElement $config the child configuration.
	 * @param string|string[] $type the type, or any one of the types, the result must be an
	 *   instance of.
	 * @param null|string $default the class to create when the configuration names none; null
	 *   makes `class` required.
	 * @param bool $strictKeys whether a PHP configuration may hold only `class`, `properties`,
	 *   and, for a composite scheme, its `signature` children. A property written beside
	 *   `class` rather than inside `properties` is otherwise ignored, and for a scheme that
	 *   drops a check: a JWT `Audience` there leaves the audience unchecked. XML cannot make
	 *   this mistake, since every attribute is a property.
	 * @throws \Prado\Exceptions\TConfigurationException when no class is named and there is no
	 *   default, the created component is not a $type, or a strict PHP configuration holds a
	 *   key it does not read.
	 * @return object the configured component.
	 */
	protected function createConfigured(null|array|TXmlElement $config, string|array $type, ?string $default = null, bool $strictKeys = false): object
	{
		$properties = [];
		$class = $default;
		if ($config instanceof TXmlElement) {
			$attributes = $config->getAttributes();
			$class = $attributes->remove('class') ?? $default;
			$properties = $attributes->toArray();
		} elseif (is_array($config)) {
			$class = $config['class'] ?? $default;
			$properties = $config['properties'] ?? [];
		}
		if (!is_string($class) || $class === '') {
			throw new TConfigurationException('webhooks_class_required', static::class);
		}

		$component = Prado::createComponent($class);
		$accepted = (array) $type;
		$matched = false;
		foreach ($accepted as $candidate) {
			$matched = $matched || $component instanceof $candidate;
		}
		if (!$matched) {
			throw new TConfigurationException('webhooks_component_invalid', $class, implode(' or ', $accepted));
		}
		if ($strictKeys && is_array($config)) {
			$known = ['class', 'properties'];
			if ($component instanceof TCompositeWebhookSignature) {
				$known[] = 'signature';
			}
			$unknown = array_diff(array_map('strval', array_keys($config)), $known);
			if ($unknown !== []) {
				throw new TConfigurationException('webhooks_property_misplaced', implode(', ', $unknown), $class);
			}
		}
		foreach ($properties as $name => $value) {
			if (strcasecmp((string) $name, 'id') === 0) {
				continue;
			}
			$component->setSubproperty((string) $name, $value);
		}
		if ($component instanceof TCompositeWebhookSignature) {
			// A composite's children are in the same configuration; built without them, it
			// throws on its first delivery.
			$component->init($config);
		}

		return $component;
	}
}
