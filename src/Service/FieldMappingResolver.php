<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Service;

use Caeligo\FieldEncryptionBundle\Attribute\Encrypted;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedEntity;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedFile;
use Caeligo\FieldEncryptionBundle\Exception\PropertyNotFoundException;
use ReflectionClass;
use ReflectionProperty;

/**
 * Resolves encrypted field mappings from entity classes.
 *
 * This service analyzes entity classes to find properties marked with the #[Encrypted]
 * or #[EncryptedFile] attributes and builds a mapping structure for the encryption listener.
 *
 * It supports both:
 * - Attribute-based configuration (#[Encrypted] and #[EncryptedFile] on properties)
 * - YAML-based configuration (from bundle configuration)
 *
 * @author Bíró Gábor (biga156)
 */
class FieldMappingResolver
{
    /**
     * @var array<string, array<string, FieldMapping>> Cached string field mappings per entity class
     */
    private array $cache = [];

    /**
     * @var array<string, array<string, FileFieldMapping>> Cached file field mappings per entity class
     */
    private array $fileCache = [];

    /**
     * @var array<string, bool> Cache for property validation results
     */
    private array $validatedClasses = [];

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
     * Get all encrypted string field mappings for an entity.
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
     * Get all encrypted file field mappings for an entity.
     *
     * @param object $entity The entity to analyze
     *
     * @return array<string, FileFieldMapping> Array of file field mappings keyed by source property name
     *
     * @throws PropertyNotFoundException If a configured metadata property does not exist
     */
    public function getFileMappings(object $entity): array
    {
        $className = $entity::class;

        if (isset($this->fileCache[$className])) {
            return $this->fileCache[$className];
        }

        $mappings = [];
        $reflection = new ReflectionClass($entity);
        $idMethod = $this->resolveIdMethod($reflection, $className);

        foreach ($reflection->getProperties() as $property) {
            $attributes = $property->getAttributes(EncryptedFile::class);

            if (empty($attributes)) {
                continue;
            }

            /** @var EncryptedFile $encryptedFile */
            $encryptedFile = $attributes[0]->newInstance();

            $mapping = $this->createFileMappingFromAttribute($property, $encryptedFile);
            $mapping->idMethod = $idMethod;

            // Validate metadata properties exist
            $this->validateFileMappingProperties($reflection, $mapping, $className);

            $mappings[$property->getName()] = $mapping;
        }

        $this->fileCache[$className] = $mappings;

        return $mappings;
    }

    /**
     * Check if an entity has any encrypted fields (string or file).
     *
     * @param object $entity The entity to check
     *
     * @return bool True if the entity has encrypted fields
     */
    public function hasEncryptedFields(object $entity): bool
    {
        return !empty($this->getMappings($entity)) || !empty($this->getFileMappings($entity));
    }

    /**
     * Check if an entity has any encrypted string fields.
     *
     * @param object $entity The entity to check
     *
     * @return bool True if the entity has encrypted string fields
     */
    public function hasEncryptedStringFields(object $entity): bool
    {
        return !empty($this->getMappings($entity));
    }

    /**
     * Check if an entity has any encrypted file fields.
     *
     * @param object $entity The entity to check
     *
     * @return bool True if the entity has encrypted file fields
     */
    public function hasEncryptedFileFields(object $entity): bool
    {
        return !empty($this->getFileMappings($entity));
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
        if (!empty($mappings)) {
            return reset($mappings)->idMethod;
        }

        $fileMappings = $this->getFileMappings($entity);
        if (!empty($fileMappings)) {
            return reset($fileMappings)->idMethod;
        }

        return 'getId';
    }

    /**
     * Get all entity classes that have encrypted fields from YAML config.
     *
     * @return array<string> List of entity class names
     */
    public function getConfiguredEntityClasses(): array
    {
        return array_keys($this->yamlConfig);
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
            encryptedProperty: $encrypted->encryptedProperty ?? $propertyName,
            plainProperty: $encrypted->plainProperty ?? 'plain' . ucfirst($propertyName),
            hashField: $encrypted->hashField,
            hashProperty: $encrypted->hashProperty ?? ($encrypted->hashField ? $propertyName . 'Hash' : null),
        );
    }

    /**
     * Creates a FileFieldMapping from an EncryptedFile attribute.
     */
    private function createFileMappingFromAttribute(ReflectionProperty $property, EncryptedFile $encryptedFile): FileFieldMapping
    {
        $propertyName = $property->getName();

        return new FileFieldMapping(
            sourceProperty: $propertyName,
            plainProperty: $encryptedFile->getPlainPropertyName($propertyName),
            plainType: $encryptedFile->plainType,
            mimeTypeProperty: $encryptedFile->mimeTypeProperty,
            originalNameProperty: $encryptedFile->originalNameProperty,
            originalSizeProperty: $encryptedFile->originalSizeProperty,
            compress: $encryptedFile->compress,
            maxSize: $encryptedFile->maxSize,
            chunkSize: $encryptedFile->chunkSize,
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

    /**
     * Validate that all configured metadata properties exist on the entity.
     *
     * @throws PropertyNotFoundException If a configured property does not exist
     */
    private function validateFileMappingProperties(
        ReflectionClass $reflection,
        FileFieldMapping $mapping,
        string $className,
    ): void {
        // Skip if already validated
        $cacheKey = $className . '::' . $mapping->sourceProperty;
        if (isset($this->validatedClasses[$cacheKey])) {
            return;
        }

        // Validate plain property exists
        if (!$reflection->hasProperty($mapping->plainProperty)) {
            throw new PropertyNotFoundException($mapping->plainProperty, $className);
        }

        // Validate metadata properties if configured
        if ($mapping->mimeTypeProperty !== null && !$reflection->hasProperty($mapping->mimeTypeProperty)) {
            throw PropertyNotFoundException::metadataProperty(
                $mapping->mimeTypeProperty,
                $className,
                'mimeTypeProperty'
            );
        }

        if ($mapping->originalNameProperty !== null && !$reflection->hasProperty($mapping->originalNameProperty)) {
            throw PropertyNotFoundException::metadataProperty(
                $mapping->originalNameProperty,
                $className,
                'originalNameProperty'
            );
        }

        if ($mapping->originalSizeProperty !== null && !$reflection->hasProperty($mapping->originalSizeProperty)) {
            throw PropertyNotFoundException::metadataProperty(
                $mapping->originalSizeProperty,
                $className,
                'originalSizeProperty'
            );
        }

        $this->validatedClasses[$cacheKey] = true;
    }
}
