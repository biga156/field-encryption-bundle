<?php

declare(strict_types=1);

namespace Biga\FieldEncryptionBundle\Service;

use Biga\FieldEncryptionBundle\Attribute\Encrypted;
use Biga\FieldEncryptionBundle\Attribute\EncryptedEntity;
use ReflectionClass;
use ReflectionProperty;

/**
 * Resolves encrypted field mappings from entity classes.
 *
 * This service analyzes entity classes to find properties marked with the #[Encrypted]
 * attribute and builds a mapping structure for the encryption listener.
 *
 * It supports both:
 * - Attribute-based configuration (#[Encrypted] on properties)
 * - YAML-based configuration (from bundle configuration)
 *
 * @author Bíró Gábor (biga156)
 */
class FieldMappingResolver
{
    /**
     * @var array<string, array<string, FieldMapping>> Cached mappings per entity class
     */
    private array $cache = [];

    /**
     * @var array<string, array{id_property?: string, fields?: array<string, array{encrypted_property?: string, plain_property?: string, hash_field?: bool, hash_property?: string}>}>
     */
    private array $yamlConfig;

    /**
     * @param array<string, array{id_property?: string, fields?: array<string, array{encrypted_property?: string, plain_property?: string, hash_field?: bool, hash_property?: string}>}> $yamlConfig YAML configuration for entity field mappings
     */
    public function __construct(array $yamlConfig = [])
    {
        $this->yamlConfig = $yamlConfig;
    }

    /**
     * Get all encrypted field mappings for an entity.
     *
     * @param object $entity The entity to analyze
     *
     * @return array<string, FieldMapping> Array of field mappings keyed by source property name
     */
    public function getMappings(object $entity): array
    {
        $className = $entity::class;

        if (isset($this->cache[$className])) {
            return $this->cache[$className];
        }

        $mappings = [];

        // First, check YAML configuration
        if (isset($this->yamlConfig[$className]['fields'])) {
            foreach ($this->yamlConfig[$className]['fields'] as $propertyName => $config) {
                $mappings[$propertyName] = $this->createMappingFromConfig($propertyName, $config);
            }
        }

        // Then, check attributes (attributes override YAML config)
        $reflection = new ReflectionClass($entity);
        $idMethod   = $this->resolveIdMethod($reflection, $className);

        foreach ($reflection->getProperties() as $property) {
            $attributes = $property->getAttributes(Encrypted::class);

            if (empty($attributes)) {
                continue;
            }

            /** @var Encrypted $encrypted */
            $encrypted = $attributes[0]->newInstance();

            $mappings[$property->getName()] = $this->createMappingFromAttribute($property, $encrypted);
        }

        // Store the ID method in mappings
        foreach ($mappings as $mapping) {
            $mapping->idMethod = $idMethod;
        }

        $this->cache[$className] = $mappings;

        return $mappings;
    }

    /**
     * Check if an entity has any encrypted fields.
     *
     * @param object $entity The entity to check
     *
     * @return bool True if the entity has encrypted fields
     */
    public function hasEncryptedFields(object $entity): bool
    {
        return !empty($this->getMappings($entity));
    }

    /**
     * Get the ID method name for an entity.
     *
     * @param object $entity The entity
     *
     * @return string The ID method name
     */
    public function getIdMethod(object $entity): string
    {
        $mappings = $this->getMappings($entity);

        return !empty($mappings) ? reset($mappings)->idMethod : 'getId';
    }

    /**
     * Resolves the ID method from YAML config, EncryptedEntity attribute, or defaults to 'getId'.
     *
     * Priority:
     * 1. YAML configuration (id_property)
     * 2. EncryptedEntity attribute (idMethod)
     * 3. Default 'getId'
     */
    private function resolveIdMethod(ReflectionClass $reflection, string $className): string
    {
        // First, check YAML configuration
        if (isset($this->yamlConfig[$className]['id_property'])) {
            $idProperty = $this->yamlConfig[$className]['id_property'];
            return 'get' . ucfirst($idProperty);
        }

        // Then, check EncryptedEntity attribute
        $attributes = $reflection->getAttributes(EncryptedEntity::class);

        if (!empty($attributes)) {
            /** @var EncryptedEntity $encryptedEntity */
            $encryptedEntity = $attributes[0]->newInstance();

            return $encryptedEntity->idMethod;
        }

        return 'getId';
    }

    /**
     * Creates a FieldMapping from an Encrypted attribute.
     */
    private function createMappingFromAttribute(ReflectionProperty $property, Encrypted $encrypted): FieldMapping
    {
        $propertyName = $property->getName();

        return new FieldMapping(
            sourceProperty: $propertyName,
            encryptedProperty: $encrypted->encryptedProperty ?? 'encrypted' . ucfirst($propertyName),
            plainProperty: $encrypted->plainProperty ?? 'plain' . ucfirst($propertyName),
            hashField: $encrypted->hashField,
            hashProperty: $encrypted->hashProperty ?? ($encrypted->hashField ? $propertyName . 'Hash' : null),
        );
    }

    /**
     * Creates a FieldMapping from YAML configuration.
     *
     * @param string $propertyName The source property name
     * @param array{encrypted_property?: string, plain_property?: string, hash_field?: bool, hash_property?: string} $config
     */
    private function createMappingFromConfig(string $propertyName, array $config): FieldMapping
    {
        return new FieldMapping(
            sourceProperty: $propertyName,
            encryptedProperty: $config['encrypted_property'] ?? 'encrypted' . ucfirst($propertyName),
            plainProperty: $config['plain_property'] ?? 'plain' . ucfirst($propertyName),
            hashField: $config['hash_field'] ?? false,
            hashProperty: $config['hash_property'] ?? (($config['hash_field'] ?? false) ? $propertyName . 'Hash' : null),
        );
    }
}
