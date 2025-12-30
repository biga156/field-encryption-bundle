<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Exception;

/**
 * Exception thrown when an unsupported payload format version is encountered.
 *
 * @author Bíró Gábor (biga156)
 */
class UnsupportedVersionException extends EncryptionException
{
    private int $version;
    private array $supportedVersions;

    /**
     * @param int   $version           The unsupported version encountered
     * @param int[] $supportedVersions List of supported versions
     */
    public function __construct(int $version, array $supportedVersions = [1])
    {
        $this->version = $version;
        $this->supportedVersions = $supportedVersions;

        parent::__construct(sprintf(
            'Unsupported encryption format version: %d. Supported versions: %s. ' .
            'This may indicate data corruption or that a newer version of the bundle is required.',
            $version,
            implode(', ', $supportedVersions)
        ));
    }

    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * @return int[]
     */
    public function getSupportedVersions(): array
    {
        return $this->supportedVersions;
    }
}
