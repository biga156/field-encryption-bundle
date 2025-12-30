<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Attribute;

use Attribute;
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;

/**
 * Marks an entity property for automatic binary file encryption/decryption.
 *
 * This attribute is designed for BLOB fields that store encrypted binary data
 * such as documents, images, or other files.
 *
 * Features:
 * - Automatic encryption on persist/update
 * - Automatic decryption on load
 * - Optional metadata properties (mimeType, originalName, originalSize)
 * - Support for both raw string and DTO plain types
 * - Configurable compression
 * - Chunk-based encryption for memory efficiency
 *
 * Usage with DTO (recommended):
 * ```php
 * #[ORM\Entity]
 * #[EncryptedEntity]
 * class Document
 * {
 *     #[ORM\Column(type: Types::BLOB, nullable: true)]
 *     #[EncryptedFile(
 *         mimeTypeProperty: 'mimeType',
 *         originalNameProperty: 'originalName',
 *         originalSizeProperty: 'originalSize',
 *     )]
 *     private $encryptedContent;
 *
 *     #[ORM\Column(type: Types::STRING, length: 100, nullable: true)]
 *     private ?string $mimeType = null;
 *
 *     #[ORM\Column(type: Types::STRING, length: 255, nullable: true)]
 *     private ?string $originalName = null;
 *
 *     #[ORM\Column(type: Types::INTEGER, nullable: true)]
 *     private ?int $originalSize = null;
 *
 *     private ?EncryptedFileData $plainContent = null;
 *
 *     public function getPlainContent(): ?EncryptedFileData
 *     {
 *         return $this->plainContent;
 *     }
 *
 *     public function setPlainContent(?EncryptedFileData $content): self
 *     {
 *         $this->plainContent = $content;
 *         return $this;
 *     }
 * }
 * ```
 *
 * Usage with raw string:
 * ```php
 * #[ORM\Column(type: Types::BLOB, nullable: true)]
 * #[EncryptedFile(plainType: 'string')]
 * private $encryptedContent;
 *
 * private ?string $plainContent = null;
 * ```
 *
 * @author Bíró Gábor (biga156)
 */
#[Attribute(Attribute::TARGET_PROPERTY)]
class EncryptedFile
{
    public const PLAIN_TYPE_STRING = 'string';
    public const PLAIN_TYPE_DTO = 'dto';

    /**
     * @param string      $plainType            The type of the plain property: 'string' for raw binary, 'dto' for EncryptedFileData
     * @param string|null $plainProperty        The property name for decrypted content. Defaults to 'plain' + ucfirst(propertyName)
     * @param string|null $mimeTypeProperty     Property name to store MIME type (optional, creates searchable column)
     * @param string|null $originalNameProperty Property name to store original filename (optional)
     * @param string|null $originalSizeProperty Property name to store original file size (optional)
     * @param bool|null   $compress             Whether to gzip compress before encryption. Null = use bundle default
     * @param int|null    $maxSize              Maximum file size in bytes. Null = use bundle default (5MB)
     * @param int|null    $chunkSize            Encryption chunk size in bytes. Null = use bundle default (160KB)
     */
    public function __construct(
        public readonly string $plainType = self::PLAIN_TYPE_DTO,
        public readonly ?string $plainProperty = null,
        public readonly ?string $mimeTypeProperty = null,
        public readonly ?string $originalNameProperty = null,
        public readonly ?string $originalSizeProperty = null,
        public readonly ?bool $compress = null,
        public readonly ?int $maxSize = null,
        public readonly ?int $chunkSize = null,
    ) {
    }

    /**
     * Check if the plain type is DTO.
     */
    public function isDtoType(): bool
    {
        return $this->plainType === self::PLAIN_TYPE_DTO;
    }

    /**
     * Check if the plain type is string.
     */
    public function isStringType(): bool
    {
        return $this->plainType === self::PLAIN_TYPE_STRING;
    }

    /**
     * Get the plain property name, resolving the default if not specified.
     *
     * @param string $encryptedPropertyName The name of the encrypted property
     */
    public function getPlainPropertyName(string $encryptedPropertyName): string
    {
        return $this->plainProperty ?? 'plain' . ucfirst($encryptedPropertyName);
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
