<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Exception;

/**
 * Exception thrown when decryption fails.
 *
 * @author Bíró Gábor (biga156)
 */
class DecryptionException extends EncryptionException
{
    /**
     * Create an exception for decryption failure.
     */
    public static function decryptionFailed(string $reason = ''): self
    {
        $message = 'Decryption failed';
        if ($reason !== '') {
            $message .= ': ' . $reason;
        }

        return new self($message);
    }

    /**
     * Create an exception for invalid payload format.
     */
    public static function invalidPayload(): self
    {
        return new self('Decryption failed: Invalid encrypted payload format');
    }

    /**
     * Create an exception for authentication failure (GCM tag mismatch).
     */
    public static function authenticationFailed(): self
    {
        return new self('Decryption failed: Authentication tag verification failed. Data may have been tampered with.');
    }
}
