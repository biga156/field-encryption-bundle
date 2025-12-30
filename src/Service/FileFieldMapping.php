<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Service;

use Caeligo\FieldEncryptionBundle\Attribute\EncryptedFile;

/**
 * Represents the mapping configuration for a single encrypted file field.
 *
 * @author Bíró Gábor (biga156)
 */
class FileFieldMapping
{
    /**
     * @param string      $sourceProperty         The property name that stores the encrypted BLOB
     * @param string      $plainProperty          The property name that stores the decrypted value (DTO or string)
     * @param string      $plainType              The type of plain property: 'string' or 'dto'
     * @param string|null $mimeTypeProperty       Property for MIME type (optional)
     * @param string|null $originalNameProperty   Property for original filename (optional)
     * @param string|null $originalSizeProperty   Property for original file size (optional)
     * @param bool|null   $compress               Whether to compress (null = use default)
     * @param int|null    $maxSize                Maximum file size (null = use default)
     * @param int|null    $chunkSize              Chunk size (null = use default)
     * @param string      $idMethod               The method name to get the entity's unique identifier
     */
    public function __construct(
        public readonly string $sourceProperty,
        public readonly string $plainProperty,
        public readonly string $plainType = EncryptedFile::PLAIN_TYPE_DTO,
        public readonly ?string $mimeTypeProperty = null,
        public readonly ?string $originalNameProperty = null,
        public readonly ?string $originalSizeProperty = null,
        public readonly ?bool $compress = null,
        public readonly ?int $maxSize = null,
        public readonly ?int $chunkSize = null,
        public string $idMethod = 'getId',
    ) {
    }

    /**
     * Check if the plain type is DTO.
     */
    public function isDtoType(): bool
    {
        return $this->plainType === EncryptedFile::PLAIN_TYPE_DTO;
    }

    /**
     * Check if the plain type is string.
     */
    public function isStringType(): bool
    {
        return $this->plainType === EncryptedFile::PLAIN_TYPE_STRING;
    }

    /**
     * Check if any metadata property is configured.
     */
    public function hasMetadataProperties(): bool
    {
        return $this->mimeTypeProperty !== null
            || $this->originalNameProperty !== null
            || $this->originalSizeProperty !== null;
    }

    /**
     * Get all configured metadata property names.
     *
     * @return array<string, string> Map of metadata type to property name
     */
    public function getMetadataProperties(): array
    {
        $properties = [];

        if ($this->mimeTypeProperty !== null) {
            $properties['mimeType'] = $this->mimeTypeProperty;
        }
        if ($this->originalNameProperty !== null) {
            $properties['originalName'] = $this->originalNameProperty;
        }
        if ($this->originalSizeProperty !== null) {
            $properties['originalSize'] = $this->originalSizeProperty;
        }

        return $properties;
    }
}
