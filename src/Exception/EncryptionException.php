<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Exception;

use RuntimeException;

/**
 * Base exception for all encryption-related errors in the FieldEncryptionBundle.
 *
 * @author Bíró Gábor (biga156)
 */
class EncryptionException extends RuntimeException
{
    /**
     * Create an exception for encryption failure.
     */
    public static function encryptionFailed(string $reason = ''): self
    {
        $message = 'Encryption failed';
        if ($reason !== '') {
            $message .= ': ' . $reason;
        }

        return new self($message);
    }

    /**
     * Create an exception for missing encryption key.
     */
    public static function missingKey(): self
    {
        return new self('Encryption key is not configured. Please set FIELD_ENCRYPTION_KEY environment variable.');
    }
}
