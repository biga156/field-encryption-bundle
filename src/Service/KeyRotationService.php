<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Service;

use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use ReflectionClass;
use Symfony\Component\Uid\Ulid;
use Symfony\Component\Uid\Uuid;

/**
 * Service for rotating encryption keys across all encrypted entities.
 *
 * This service handles the re-encryption of all data when the master key changes,
 * supporting both string fields (#[Encrypted]) and file fields (#[EncryptedFile]).
 *
 * Features:
 * - Batch processing to handle large datasets
 * - Progress tracking for resumable operations
 * - Memory-efficient processing with EntityManager::clear()
 * - Support for both string and binary field encryption
 *
 * @author Bíró Gábor (biga156)
 */
class KeyRotationService
{
    private const PROGRESS_FILE = 'var/field_encryption_rotation_progress.json';

    public function __construct(
        private FieldEncryptionService $encryptionService,
        private BinaryEncryptionService $binaryEncryptionService,
        private FieldMappingResolver $mappingResolver,
        private LoggerInterface $logger = new NullLogger(),
    ) {
    }

    /**
     * Rotate encryption keys for all entities of a given class.
     *
     * @param EntityManagerInterface $em          The entity manager
     * @param string                 $entityClass The entity class name
     * @param int                    $batchSize   Number of entities to process per batch
     * @param callable|null          $progressCallback Callback for progress updates: function(int $processed, int $total)
     * @param string|null            $projectDir  Project directory for progress file
     *
     * @return array{processed: int, skipped: int, errors: int} Statistics
     */
    public function rotateKeysForEntity(
        EntityManagerInterface $em,
        string $entityClass,
        int $batchSize = 100,
        ?callable $progressCallback = null,
        ?string $projectDir = null,
    ): array {
        $stats = ['processed' => 0, 'skipped' => 0, 'errors' => 0];

        // Get total count
        $qb = $em->createQueryBuilder();
        $totalCount = (int) $qb->select('COUNT(e.id)')
            ->from($entityClass, 'e')
            ->getQuery()
            ->getSingleScalarResult();

        if ($totalCount === 0) {
            return $stats;
        }

        // Load progress if continuing
        $lastProcessedId = $this->loadProgress($entityClass, $projectDir);

        $this->logger->info('Starting key rotation', [
            'entity' => $entityClass,
            'total' => $totalCount,
            'batchSize' => $batchSize,
            'continuingFrom' => $lastProcessedId,
        ]);

        $offset = 0;
        $processed = 0;

        do {
            $query = $em->createQueryBuilder()
                ->select('e')
                ->from($entityClass, 'e')
                ->orderBy('e.id', 'ASC')
                ->setMaxResults($batchSize);

            if ($lastProcessedId !== null) {
                $query->where('e.id > :lastId')
                    ->setParameter('lastId', $lastProcessedId);
            }

            $entities = $query->getQuery()->getResult();

            if (empty($entities)) {
                break;
            }

            foreach ($entities as $entity) {
                try {
                    $rotated = $this->rotateEntityKeys($entity, $em);

                    if ($rotated) {
                        $stats['processed']++;
                    } else {
                        $stats['skipped']++;
                    }

                    $lastProcessedId = $this->getEntityId($entity);
                    $processed++;

                    if ($progressCallback !== null) {
                        $progressCallback($processed, $totalCount);
                    }
                } catch (\Exception $e) {
                    $stats['errors']++;
                    $this->logger->error('Failed to rotate keys for entity', [
                        'entity' => $entityClass,
                        'id' => $this->getEntityId($entity),
                        'error' => $e->getMessage(),
                    ]);
                }
            }

            // Flush changes
            $em->flush();

            // Save progress
            $this->saveProgress($entityClass, $lastProcessedId, $projectDir);

            // Clear entity manager to free memory
            $em->clear();

            $offset += $batchSize;

        } while (count($entities) === $batchSize);

        // Clear progress file on completion
        $this->clearProgress($entityClass, $projectDir);

        $this->logger->info('Key rotation completed', [
            'entity' => $entityClass,
            'stats' => $stats,
        ]);

        return $stats;
    }

    /**
     * Rotate encryption keys for a single entity.
     *
     * @param object                 $entity The entity to process
     * @param EntityManagerInterface $em     The entity manager
     *
     * @return bool True if any fields were rotated
     */
    public function rotateEntityKeys(object $entity, EntityManagerInterface $em): bool
    {
        $entityId = $this->getEntityId($entity);
        if ($entityId === null) {
            return false;
        }

        $rotated = false;
        $reflection = new ReflectionClass($entity);

        // Rotate string fields
        $stringMappings = $this->mappingResolver->getMappings($entity);
        foreach ($stringMappings as $mapping) {
            if ($this->rotateStringField($entity, $reflection, $mapping, $entityId)) {
                $rotated = true;
            }
        }

        // Rotate file fields
        $fileMappings = $this->mappingResolver->getFileMappings($entity);
        foreach ($fileMappings as $mapping) {
            if ($this->rotateFileField($entity, $reflection, $mapping, $entityId)) {
                $rotated = true;
            }
        }

        return $rotated;
    }

    /**
     * Rotate a string field encryption.
     */
    private function rotateStringField(
        object $entity,
        ReflectionClass $reflection,
        FieldMapping $mapping,
        string $entityId,
    ): bool {
        $property = $reflection->getProperty($mapping->encryptedProperty);
        $property->setAccessible(true);
        $encryptedValue = $property->getValue($entity);

        if ($encryptedValue === null) {
            return false;
        }

        // Decrypt with old/current key
        $plainValue = $this->encryptionService->decrypt($encryptedValue, $entityId);
        if ($plainValue === null) {
            return false;
        }

        // Re-encrypt with current key (which is now the new key)
        $newEncryptedValue = $this->encryptionService->encrypt($plainValue, $entityId);
        $property->setValue($entity, $newEncryptedValue);

        return true;
    }

    /**
     * Rotate a file field encryption.
     */
    private function rotateFileField(
        object $entity,
        ReflectionClass $reflection,
        FileFieldMapping $mapping,
        string $entityId,
    ): bool {
        $property = $reflection->getProperty($mapping->sourceProperty);
        $property->setAccessible(true);
        $encryptedValue = $property->getValue($entity);

        if ($encryptedValue === null) {
            return false;
        }

        // Handle resource type (BLOB)
        if (is_resource($encryptedValue)) {
            $encryptedValue = stream_get_contents($encryptedValue);
            if ($encryptedValue === false) {
                return false;
            }
        }

        // Check if already using current key version
        if ($this->binaryEncryptionService->isCurrentKeyVersion($encryptedValue)) {
            return false;
        }

        // Re-encrypt with current key
        $newEncryptedValue = $this->binaryEncryptionService->reEncrypt($encryptedValue, $entityId);
        $property->setValue($entity, $newEncryptedValue);

        return true;
    }

    /**
     * Get entity ID as string.
     */
    private function getEntityId(object $entity): ?string
    {
        $idMethod = $this->mappingResolver->getIdMethod($entity);

        if (!method_exists($entity, $idMethod)) {
            return null;
        }

        $id = $entity->{$idMethod}();

        if ($id === null) {
            return null;
        }

        if ($id instanceof Ulid || $id instanceof Uuid) {
            return $id->toRfc4122();
        }

        if (is_object($id) && method_exists($id, '__toString')) {
            return (string) $id;
        }

        if (is_scalar($id)) {
            return (string) $id;
        }

        return null;
    }

    /**
     * Load progress from file.
     */
    private function loadProgress(string $entityClass, ?string $projectDir): ?string
    {
        $progressFile = $this->getProgressFilePath($projectDir);

        if (!file_exists($progressFile)) {
            return null;
        }

        $data = json_decode(file_get_contents($progressFile), true);

        return $data[$entityClass] ?? null;
    }

    /**
     * Save progress to file.
     */
    private function saveProgress(string $entityClass, ?string $lastProcessedId, ?string $projectDir): void
    {
        $progressFile = $this->getProgressFilePath($projectDir);

        $data = [];
        if (file_exists($progressFile)) {
            $data = json_decode(file_get_contents($progressFile), true) ?? [];
        }

        $data[$entityClass] = $lastProcessedId;

        $dir = dirname($progressFile);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($progressFile, json_encode($data, JSON_PRETTY_PRINT));
    }

    /**
     * Clear progress for an entity class.
     */
    private function clearProgress(string $entityClass, ?string $projectDir): void
    {
        $progressFile = $this->getProgressFilePath($projectDir);

        if (!file_exists($progressFile)) {
            return;
        }

        $data = json_decode(file_get_contents($progressFile), true) ?? [];
        unset($data[$entityClass]);

        if (empty($data)) {
            unlink($progressFile);
        } else {
            file_put_contents($progressFile, json_encode($data, JSON_PRETTY_PRINT));
        }
    }

    /**
     * Get progress file path.
     */
    private function getProgressFilePath(?string $projectDir): string
    {
        $base = $projectDir ?? getcwd();

        return $base . '/' . self::PROGRESS_FILE;
    }

    /**
     * Check if there is pending progress for any entity.
     *
     * @return array<string, string> Map of entity class to last processed ID
     */
    public function getPendingProgress(?string $projectDir = null): array
    {
        $progressFile = $this->getProgressFilePath($projectDir);

        if (!file_exists($progressFile)) {
            return [];
        }

        return json_decode(file_get_contents($progressFile), true) ?? [];
    }

    /**
     * Get all entity classes that have encrypted fields.
     *
     * @param EntityManagerInterface $em The entity manager
     *
     * @return array<string> List of entity class names
     */
    public function getEncryptedEntityClasses(EntityManagerInterface $em): array
    {
        $classes = [];
        $metadata = $em->getMetadataFactory()->getAllMetadata();

        foreach ($metadata as $classMetadata) {
            $className = $classMetadata->getName();

            // Create a dummy instance to check for encrypted fields
            $reflectionClass = new ReflectionClass($className);

            if ($reflectionClass->isAbstract()) {
                continue;
            }

            // Check if class has Encrypted or EncryptedFile attributes on any property
            foreach ($reflectionClass->getProperties() as $property) {
                $encryptedAttrs = $property->getAttributes(\Caeligo\FieldEncryptionBundle\Attribute\Encrypted::class);
                $fileAttrs = $property->getAttributes(\Caeligo\FieldEncryptionBundle\Attribute\EncryptedFile::class);

                if (!empty($encryptedAttrs) || !empty($fileAttrs)) {
                    $classes[] = $className;
                    break;
                }
            }
        }

        // Also include classes from YAML config
        $yamlClasses = $this->mappingResolver->getConfiguredEntityClasses();
        $classes = array_unique(array_merge($classes, $yamlClasses));

        return $classes;
    }
}
