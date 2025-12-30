<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Exception;

/**
 * Exception thrown when a file exceeds the configured maximum size.
 *
 * @author Bíró Gábor (biga156)
 */
class FileTooLargeException extends EncryptionException
{
    private int $fileSize;
    private int $maxSize;

    public function __construct(int $fileSize, int $maxSize)
    {
        $this->fileSize = $fileSize;
        $this->maxSize = $maxSize;

        parent::__construct(sprintf(
            'File size (%s) exceeds maximum allowed size (%s)',
            self::formatBytes($fileSize),
            self::formatBytes($maxSize)
        ));
    }

    public function getFileSize(): int
    {
        return $this->fileSize;
    }

    public function getMaxSize(): int
    {
        return $this->maxSize;
    }

    /**
     * Format bytes to human-readable string.
     */
    private static function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $unitIndex = 0;
        $size = (float) $bytes;

        while ($size >= 1024 && $unitIndex < count($units) - 1) {
            $size /= 1024;
            $unitIndex++;
        }

        return sprintf('%.2f %s', $size, $units[$unitIndex]);
    }
}
