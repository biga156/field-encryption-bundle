<?php

declare(strict_types=1);

namespace Biga\FieldEncryptionBundle\EventListener;

use Biga\FieldEncryptionBundle\Service\FieldEncryptionService;
use Biga\FieldEncryptionBundle\Service\FieldMapping;
use Biga\FieldEncryptionBundle\Service\FieldMappingResolver;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Events;
use Doctrine\Persistence\Event\LifecycleEventArgs;
use ReflectionClass;
use Symfony\Component\Uid\Ulid;
use Symfony\Component\Uid\Uuid;

/**
 * Doctrine event subscriber that automatically encrypts and decrypts entity fields
 * marked with the #[Encrypted] attribute or configured via YAML.
 *
 * This listener integrates with {@see FieldEncryptionService} to ensure that
 * marked fields are stored in encrypted form in the database, while
 * transparently decrypting them when entities are loaded.
 *
 * Registered for the following Doctrine lifecycle events:
 * - {@see Events::prePersist}: Encrypts fields before the entity is first persisted.
 * - {@see Events::preUpdate}: Encrypts fields before updates and recomputes the change set.
 * - {@see Events::postLoad}: Decrypts fields after the entity is loaded from the database.
 *
 * @author Bíró Gábor (biga156)
 */
class FieldEncryptionListener
{
    public function __construct(
        private FieldEncryptionService $encryptionService,
        private FieldMappingResolver $mappingResolver,
    ) {
    }

    /**
     * Handles the prePersist event.
     *
     * Encrypts all marked fields before the entity is initially persisted.
     *
     * @param object             $entity The entity being persisted
     * @param LifecycleEventArgs $args   Event arguments
     *
     * @phpstan-ignore missingType.generics
     */
    public function prePersist(object $entity, LifecycleEventArgs $args): void
    {
        if (!$this->mappingResolver->hasEncryptedFields($entity)) {
            return;
        }

        $this->processEncryption($entity);
    }

    /**
     * Handles the preUpdate event.
     *
     * Encrypts all marked fields before the entity is updated, then recomputes
     * the Doctrine change set to ensure the updated encrypted values are persisted.
     *
     * @param object             $entity The entity being updated
     * @param PreUpdateEventArgs $args   Event arguments
     */
    public function preUpdate(object $entity, PreUpdateEventArgs $args): void
    {
        if (!$this->mappingResolver->hasEncryptedFields($entity)) {
            return;
        }

        $this->processEncryption($entity);

        /** @var EntityManagerInterface $em */
        $em  = $args->getObjectManager();
        $uow = $em->getUnitOfWork();
        $uow->recomputeSingleEntityChangeSet(
            $em->getClassMetadata($entity::class),
            $entity
        );
    }

    /**
     * Handles the postLoad event.
     *
     * Decrypts all encrypted fields after the entity is loaded from the database
     * and sets them into the corresponding plain properties.
     *
     * @param object             $entity The entity that was loaded
     * @param LifecycleEventArgs $args   Event arguments
     *
     * @phpstan-ignore missingType.generics
     */
    public function postLoad(object $entity, LifecycleEventArgs $args): void
    {
        if (!$this->mappingResolver->hasEncryptedFields($entity)) {
            return;
        }

        $entityId = $this->getEntityId($entity);

        if (null === $entityId) {
            return;
        }

        $mappings   = $this->mappingResolver->getMappings($entity);
        $reflection = new ReflectionClass($entity);

        foreach ($mappings as $mapping) {
            $this->decryptField($entity, $reflection, $mapping, $entityId);
        }
    }

    /**
     * Encrypts all marked fields on the entity.
     *
     * @param object $entity The entity to process
     */
    private function processEncryption(object $entity): void
    {
        $entityId = $this->getEntityId($entity);

        if (null === $entityId) {
            return;
        }

        $mappings   = $this->mappingResolver->getMappings($entity);
        $reflection = new ReflectionClass($entity);

        foreach ($mappings as $mapping) {
            $this->encryptField($entity, $reflection, $mapping, $entityId);
        }
    }

    /**
     * Encrypts a single field.
     *
     * @param object          $entity     The entity
     * @param ReflectionClass $reflection The reflection class
     * @param FieldMapping    $mapping    The field mapping
     * @param string          $entityId   The entity ID for key derivation
     */
    private function encryptField(
        object $entity,
        ReflectionClass $reflection,
        FieldMapping $mapping,
        string $entityId,
    ): void {
        // Get the plain value from the source property
        $plainValue = $this->getPropertyValue($entity, $reflection, $mapping->sourceProperty);

        if (null === $plainValue || '' === $plainValue) {
            return;
        }

        // Encrypt and set the encrypted value
        $encryptedValue = $this->encryptionService->encrypt($plainValue, $entityId);
        $this->setPropertyValue($entity, $reflection, $mapping->encryptedProperty, $encryptedValue);

        // Set hash if configured
        if ($mapping->hashField && null !== $mapping->hashProperty) {
            $hash = $this->encryptionService->hash($plainValue);
            $this->setPropertyValue($entity, $reflection, $mapping->hashProperty, $hash);
        }
    }

    /**
     * Decrypts a single field.
     *
     * @param object          $entity     The entity
     * @param ReflectionClass $reflection The reflection class
     * @param FieldMapping    $mapping    The field mapping
     * @param string          $entityId   The entity ID for key derivation
     */
    private function decryptField(
        object $entity,
        ReflectionClass $reflection,
        FieldMapping $mapping,
        string $entityId,
    ): void {
        // Get the encrypted value
        $encryptedValue = $this->getPropertyValue($entity, $reflection, $mapping->encryptedProperty);

        if (null === $encryptedValue) {
            return;
        }

        // Decrypt and set the plain value
        $plainValue = $this->encryptionService->decrypt($encryptedValue, $entityId);

        if (null !== $plainValue) {
            $this->setPropertyValue($entity, $reflection, $mapping->plainProperty, $plainValue);
        }
    }

    /**
     * Gets the entity ID as a string for key derivation.
     *
     * @param object $entity The entity
     *
     * @return string|null The entity ID as string, or null if not available
     */
    private function getEntityId(object $entity): ?string
    {
        $idMethod = $this->mappingResolver->getIdMethod($entity);

        if (!method_exists($entity, $idMethod)) {
            return null;
        }

        $id = $entity->{$idMethod}();

        if (null === $id) {
            return null;
        }

        // Handle Symfony UID components
        if ($id instanceof Ulid || $id instanceof Uuid) {
            return $id->toRfc4122();
        }

        // Handle stringable objects
        if (\is_object($id) && method_exists($id, '__toString')) {
            return (string) $id;
        }

        // Handle scalars
        if (\is_scalar($id)) {
            return (string) $id;
        }

        return null;
    }

    /**
     * Gets a property value from an entity using reflection.
     *
     * @param object          $entity       The entity
     * @param ReflectionClass $reflection   The reflection class
     * @param string          $propertyName The property name
     *
     * @return mixed The property value
     */
    private function getPropertyValue(object $entity, ReflectionClass $reflection, string $propertyName): mixed
    {
        // Try getter method first
        $getterMethod = 'get' . ucfirst($propertyName);

        if ($reflection->hasMethod($getterMethod)) {
            $method = $reflection->getMethod($getterMethod);
            if ($method->isPublic()) {
                return $method->invoke($entity);
            }
        }

        // Fall back to direct property access
        if ($reflection->hasProperty($propertyName)) {
            $property = $reflection->getProperty($propertyName);
            $property->setAccessible(true);

            return $property->getValue($entity);
        }

        return null;
    }

    /**
     * Sets a property value on an entity using reflection.
     *
     * @param object          $entity       The entity
     * @param ReflectionClass $reflection   The reflection class
     * @param string          $propertyName The property name
     * @param mixed           $value        The value to set
     */
    private function setPropertyValue(object $entity, ReflectionClass $reflection, string $propertyName, mixed $value): void
    {
        // Try setter method first
        $setterMethod = 'set' . ucfirst($propertyName);

        if ($reflection->hasMethod($setterMethod)) {
            $method = $reflection->getMethod($setterMethod);
            if ($method->isPublic()) {
                $method->invoke($entity, $value);

                return;
            }
        }

        // Fall back to direct property access
        if ($reflection->hasProperty($propertyName)) {
            $property = $reflection->getProperty($propertyName);
            $property->setAccessible(true);
            $property->setValue($entity, $value);
        }
    }
}
