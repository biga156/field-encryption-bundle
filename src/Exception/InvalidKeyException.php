<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Exception;

/**
 * Exception thrown when an encryption key is invalid.
 *
 * @author Bíró Gábor (biga156)
 */
class InvalidKeyException extends EncryptionException
{
    /**
     * Create an exception for invalid key format.
     */
    public static function invalidFormat(string $reason = ''): self
    {
        $message = 'Invalid encryption key format';
        if ($reason !== '') {
            $message .= ': ' . $reason;
        }

        return new self($message);
    }

    /**
     * Create an exception for invalid key length.
     */
    public static function invalidLength(int $expected, int $actual): self
    {
        return new self(sprintf(
            'Invalid encryption key length. Expected %d characters, got %d',
            $expected,
            $actual
        ));
    }

    /**
     * Create an exception for unknown key version.
     */
    public static function unknownKeyVersion(int $version): self
    {
        return new self(sprintf(
            'Unknown key version: %d. The data may have been encrypted with a key that is no longer available.',
            $version
        ));
    }
}
