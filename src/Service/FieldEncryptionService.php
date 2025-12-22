<?php

declare(strict_types=1);

namespace Biga\FieldEncryptionBundle\Service;

/**
 * Service for symmetric encryption and decryption using the AES-256-CBC algorithm.
 *
 * The encryption key is derived from a given entity identifier and the configured
 * encryption key using HMAC-SHA256.
 *
 * Features:
 * - Generates a unique Initialization Vector (IV) for each encryption operation.
 * - Stores the IV and encrypted value in a Base64-encoded JSON payload.
 * - Requires the same entity identifier for both encryption and decryption.
 * - Uses a dedicated encryption key (not kernel.secret) for better security separation.
 *
 * Security considerations:
 * - The strength of the encryption depends on the secrecy of the encryption key.
 * - A random IV ensures that identical inputs produce different outputs.
 * - This service is not intended for password hashing — use password_hash() for that purpose.
 *
 * @author Bíró Gábor (biga156)
 */
class FieldEncryptionService
{
    private const CIPHER = 'aes-256-cbc';

    private string $encryptionKey;

    /**
     * @param string $encryptionKey The encryption key from environment variable
     */
    public function __construct(string $encryptionKey)
    {
        $this->encryptionKey = $encryptionKey;
    }

    /**
     * Encrypts a string value using AES-256-CBC with a key derived from the entity ID and encryption key.
     *
     * Process:
     * 1. Derive a key using HMAC-SHA256: `hash_hmac('sha256', $entityId, $encryptionKey)`.
     * 2. Generate a random IV of the correct length for AES-256-CBC.
     * 3. Encrypt the value with the derived key and IV.
     * 4. Base64-encode the IV, package it with the encrypted value into a JSON array.
     * 5. Base64-encode the JSON payload for storage or transmission.
     *
     * @param string $value    The plaintext value to encrypt
     * @param string $entityId The unique entity identifier used in key derivation
     *
     * @return string The encrypted payload as a Base64-encoded JSON string
     */
    public function encrypt(string $value, string $entityId): string
    {
        $key       = $this->deriveKey($entityId);
        $ivLength  = openssl_cipher_iv_length(self::CIPHER);
        $iv        = random_bytes($ivLength);
        $encrypted = openssl_encrypt($value, self::CIPHER, $key, 0, $iv);

        $payload = [
            'iv'    => base64_encode($iv),
            'value' => $encrypted,
        ];

        return base64_encode(json_encode($payload));
    }

    /**
     * Decrypts a previously encrypted payload using AES-256-CBC with a key derived from the entity ID.
     *
     * Process:
     * 1. If the payload is null, return null.
     * 2. Base64-decode the payload and parse the JSON into an array.
     * 3. Validate that both `iv` and `value` keys exist.
     * 4. Derive the same key used during encryption.
     * 5. Base64-decode the IV and decrypt the value.
     *
     * @param string|null $encodedPayload The Base64-encoded JSON payload containing `iv` and `value`
     * @param string      $entityId       The unique entity identifier used in key derivation
     *
     * @return string|null The decrypted plaintext value, or null if decryption fails or input is invalid
     */
    public function decrypt(?string $encodedPayload, string $entityId): ?string
    {
        if (null === $encodedPayload || '' === $encodedPayload) {
            return null;
        }

        $decoded = json_decode(base64_decode($encodedPayload, true), true);

        if (!\is_array($decoded) || !isset($decoded['iv'], $decoded['value'])) {
            return null;
        }

        $key = $this->deriveKey($entityId);
        $iv  = base64_decode($decoded['iv'], true);

        $decrypted = openssl_decrypt($decoded['value'], self::CIPHER, $key, 0, $iv);

        return false === $decrypted ? null : $decrypted;
    }

    /**
     * Creates a hash of the given value for searchability.
     *
     * This allows searching/matching on encrypted fields without exposing the actual value.
     * Uses SHA-256 with the encryption key as additional entropy.
     *
     * @param string $value The value to hash
     *
     * @return string The hex-encoded hash
     */
    public function hash(string $value): string
    {
        return hash_hmac('sha256', mb_strtolower(trim($value)), $this->encryptionKey);
    }

    /**
     * Derives the encryption key from the entity ID and the master encryption key.
     *
     * @param string $entityId The unique entity identifier
     *
     * @return string The derived key for AES-256-CBC (32 bytes)
     */
    private function deriveKey(string $entityId): string
    {
        return hash_hmac('sha256', $entityId, $this->encryptionKey);
    }

    /**
     * Generates a cryptographically secure encryption key.
     *
     * @return string A hex-encoded 32-byte key suitable for AES-256
     */
    public static function generateKey(): string
    {
        return bin2hex(random_bytes(32));
    }
}
