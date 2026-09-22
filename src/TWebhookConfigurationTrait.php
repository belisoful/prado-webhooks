<?php

/**
 * TWebhookConfigurationTrait class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webhooks
 * @license https://github.com/belisoful/prado-webhooks/blob/main/LICENSE
 */

namespace Belisoful\Prado\Web\Webhooks;

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
 * <service id="webhooks" class="Belisoful\Prado\Web\Webhooks\TWebhookService">
 *		<webhook id="github">
 *			<signature class="Belisoful\Prado\Web\Webhooks\Signature\THmacWebhookSignature"
 *				Secret="..." Header="X-Hub-Signature-256" Prefix="sha256=" />
 *		</webhook>
 * </service>
 * ```
 *
 * ```php
 * 'services' => [
 *		'webhooks' => [
 *			'class' => TWebhookService::class,
 *			'webhook' => [
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
	 * @throws \Prado\Exceptions\TConfigurationException when an XML child declares no id.
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
				$children[$id] = $child;
			}
		} elseif (is_array($config) && is_array($config[$tag] ?? null)) {
			foreach ($config[$tag] as $id => $child) {
				$children[(string) $id] = is_array($child) ? $child : [];
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
			foreach ($config[$tag] as $child) {
				$children[] = is_array($child) ? $child : [];
			}
		}

		return $children;
	}

	/**
	 * Returns the single child configuration of one tag, or null when there is none.
	 * @param mixed $config this component's own configuration.
	 * @param string $tag the child element name, or array key, to read.
	 * @return null|array<string, mixed>|\Prado\Xml\TXmlElement the child configuration.
	 */
	protected function childConfiguration(mixed $config, string $tag): null|array|TXmlElement
	{
		if ($config instanceof TXmlElement) {
			return $config->getElementByTagName($tag);
		}
		if (is_array($config) && is_array($config[$tag] ?? null)) {
			return $config[$tag];
		}

		return null;
	}

	/**
	 * Creates a component from a child configuration and applies its properties.
	 *
	 * @param null|array<string, mixed>|\Prado\Xml\TXmlElement $config the child configuration.
	 * @param string|string[] $type the type, or any one of the types, the result must be an
	 *   instance of.
	 * @param null|string $default the class to create when the configuration names none; null
	 *   makes `class` required.
	 * @throws \Prado\Exceptions\TConfigurationException when no class is named and there is no
	 *   default, or the created component is not a $type.
	 * @return object the configured component.
	 */
	protected function createConfigured(null|array|TXmlElement $config, string|array $type, ?string $default = null): object
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
		foreach ($properties as $name => $value) {
			if (strcasecmp((string) $name, 'id') === 0) {
				continue;
			}
			$component->setSubproperty((string) $name, $value);
		}

		return $component;
	}
}
