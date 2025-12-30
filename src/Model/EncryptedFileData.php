<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Model;

use Symfony\Component\HttpFoundation\File\UploadedFile;

/**
 * Data Transfer Object for encrypted file data.
 *
 * This DTO encapsulates the binary content along with its metadata,
 * providing a convenient way to work with encrypted files in entities.
 *
 * Usage in entity:
 * ```php
 * #[ORM\Column(type: Types::BLOB, nullable: true)]
 * #[EncryptedFile(plainType: 'dto')]
 * private $encryptedContent;
 *
 * private ?EncryptedFileData $plainContent = null;
 *
 * public function setPlainContent(?EncryptedFileData $content): self
 * {
 *     $this->plainContent = $content;
 *     return $this;
 * }
 *
 * public function getPlainContent(): ?EncryptedFileData
 * {
 *     return $this->plainContent;
 * }
 * ```
 *
 * @author Bíró Gábor (biga156)
 */
class EncryptedFileData
{
    /**
     * @param string      $content      The binary content of the file
     * @param string|null $mimeType     The MIME type (e.g., 'application/pdf')
     * @param string|null $originalName The original filename
     * @param int|null    $size         The original file size in bytes (before encryption)
     */
    public function __construct(
        private string $content,
        private ?string $mimeType = null,
        private ?string $originalName = null,
        private ?int $size = null,
    ) {
        // If size not provided, calculate from content
        if ($this->size === null) {
            $this->size = strlen($this->content);
        }
    }

    /**
     * Create an EncryptedFileData instance from a Symfony UploadedFile.
     *
     * @param UploadedFile $file The uploaded file
     *
     * @return self
     */
    public static function fromUploadedFile(UploadedFile $file): self
    {
        return new self(
            content: $file->getContent(),
            mimeType: $file->getMimeType() ?? $file->getClientMimeType(),
            originalName: $file->getClientOriginalName(),
            size: $file->getSize(),
        );
    }

    /**
     * Create an EncryptedFileData instance from a file path.
     *
     * @param string      $path     The path to the file
     * @param string|null $mimeType Optional MIME type (auto-detected if not provided)
     *
     * @return self
     *
     * @throws \RuntimeException If the file cannot be read
     */
    public static function fromPath(string $path, ?string $mimeType = null): self
    {
        if (!is_readable($path)) {
            throw new \RuntimeException(sprintf('File "%s" is not readable', $path));
        }

        $content = file_get_contents($path);
        if ($content === false) {
            throw new \RuntimeException(sprintf('Failed to read file "%s"', $path));
        }

        if ($mimeType === null) {
            $finfo = new \finfo(FILEINFO_MIME_TYPE);
            $mimeType = $finfo->file($path) ?: null;
        }

        return new self(
            content: $content,
            mimeType: $mimeType,
            originalName: basename($path),
            size: strlen($content),
        );
    }

    /**
     * Create an EncryptedFileData instance from base64-encoded content.
     *
     * @param string      $base64       The base64-encoded content
     * @param string|null $mimeType     The MIME type
     * @param string|null $originalName The original filename
     *
     * @return self
     *
     * @throws \InvalidArgumentException If the base64 string is invalid
     */
    public static function fromBase64(string $base64, ?string $mimeType = null, ?string $originalName = null): self
    {
        $content = base64_decode($base64, true);
        if ($content === false) {
            throw new \InvalidArgumentException('Invalid base64 string');
        }

        return new self(
            content: $content,
            mimeType: $mimeType,
            originalName: $originalName,
            size: strlen($content),
        );
    }

    /**
     * Create an EncryptedFileData instance from a data URI.
     *
     * @param string      $dataUri      The data URI (e.g., 'data:image/png;base64,...')
     * @param string|null $originalName The original filename
     *
     * @return self
     *
     * @throws \InvalidArgumentException If the data URI is invalid
     */
    public static function fromDataUri(string $dataUri, ?string $originalName = null): self
    {
        if (!preg_match('/^data:([^;]+);base64,(.+)$/s', $dataUri, $matches)) {
            throw new \InvalidArgumentException('Invalid data URI format');
        }

        return self::fromBase64($matches[2], $matches[1], $originalName);
    }

    /**
     * Get the binary content.
     */
    public function getContent(): string
    {
        return $this->content;
    }

    /**
     * Get the MIME type.
     */
    public function getMimeType(): ?string
    {
        return $this->mimeType;
    }

    /**
     * Get the original filename.
     */
    public function getOriginalName(): ?string
    {
        return $this->originalName;
    }

    /**
     * Get the file size in bytes.
     */
    public function getSize(): ?int
    {
        return $this->size;
    }

    /**
     * Get the content as a base64-encoded string.
     */
    public function toBase64(): string
    {
        return base64_encode($this->content);
    }

    /**
     * Get the content as a data URI.
     *
     * @param string $fallbackMimeType MIME type to use if none is set (default: application/octet-stream)
     */
    public function toDataUri(string $fallbackMimeType = 'application/octet-stream'): string
    {
        $mimeType = $this->mimeType ?? $fallbackMimeType;

        return sprintf('data:%s;base64,%s', $mimeType, $this->toBase64());
    }

    /**
     * Save the content to a file.
     *
     * @param string $path The path to save to
     *
     * @return int The number of bytes written
     *
     * @throws \RuntimeException If the file cannot be written
     */
    public function saveTo(string $path): int
    {
        $directory = dirname($path);
        if (!is_dir($directory)) {
            if (!mkdir($directory, 0755, true) && !is_dir($directory)) {
                throw new \RuntimeException(sprintf('Directory "%s" could not be created', $directory));
            }
        }

        $bytes = file_put_contents($path, $this->content);
        if ($bytes === false) {
            throw new \RuntimeException(sprintf('Failed to write to file "%s"', $path));
        }

        return $bytes;
    }

    /**
     * Get the file extension based on MIME type.
     *
     * @return string|null The file extension without dot, or null if unknown
     */
    public function getExtension(): ?string
    {
        if ($this->mimeType === null) {
            return null;
        }

        $mimeToExtension = [
            'application/pdf' => 'pdf',
            'application/json' => 'json',
            'application/xml' => 'xml',
            'application/zip' => 'zip',
            'application/gzip' => 'gz',
            'application/msword' => 'doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
            'application/vnd.ms-excel' => 'xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
            'image/jpeg' => 'jpg',
            'image/png' => 'png',
            'image/gif' => 'gif',
            'image/webp' => 'webp',
            'image/svg+xml' => 'svg',
            'text/plain' => 'txt',
            'text/html' => 'html',
            'text/css' => 'css',
            'text/javascript' => 'js',
            'text/csv' => 'csv',
            'audio/mpeg' => 'mp3',
            'audio/ogg' => 'ogg',
            'video/mp4' => 'mp4',
            'video/webm' => 'webm',
        ];

        return $mimeToExtension[$this->mimeType] ?? null;
    }

    /**
     * Check if the file is an image based on MIME type.
     */
    public function isImage(): bool
    {
        return $this->mimeType !== null && str_starts_with($this->mimeType, 'image/');
    }

    /**
     * Get a hash of the content for integrity verification.
     *
     * @param string $algorithm The hashing algorithm (default: sha256)
     */
    public function getHash(string $algorithm = 'sha256'): string
    {
        return hash($algorithm, $this->content);
    }

    /**
     * Create a new instance with different metadata.
     */
    public function withMetadata(?string $mimeType = null, ?string $originalName = null): self
    {
        return new self(
            content: $this->content,
            mimeType: $mimeType ?? $this->mimeType,
            originalName: $originalName ?? $this->originalName,
            size: $this->size,
        );
    }

    /**
     * Get formatted file size string.
     */
    public function getFormattedSize(): string
    {
        $size = $this->size ?? 0;
        $units = ['B', 'KB', 'MB', 'GB'];
        $unitIndex = 0;
        $floatSize = (float) $size;

        while ($floatSize >= 1024 && $unitIndex < count($units) - 1) {
            $floatSize /= 1024;
            $unitIndex++;
        }

        return sprintf('%.2f %s', $floatSize, $units[$unitIndex]);
    }
}
