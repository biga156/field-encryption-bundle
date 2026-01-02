<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Service;

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

    /**
     * HKDF info constants for key derivation purposes.
     */
    private const HKDF_PURPOSE_ENCRYPTION = 'field-encryption-v1';
    private const HKDF_PURPOSE_HASHING = 'field-hashing-v1';

    private string $encryptionKey;
    private ?string $hashPepper;

    /**
     * Derived keys (cached for performance).
     */
    private ?string $derivedHashKey = null;

    /**
     * @param string      $encryptionKey The encryption key from environment variable
     * @param string|null $hashPepper    Optional separate pepper for hashing (defaults to encryption key)
     */
    public function __construct(string $encryptionKey, ?string $hashPepper = null)
    {
        $this->encryptionKey = $encryptionKey;
        $this->hashPepper = $hashPepper;
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

        $base64Decoded = base64_decode($encodedPayload, true);
        if ($base64Decoded === false) {
            return null;
        }

        $decoded = json_decode($base64Decoded, true);

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
     * Uses plain SHA-256 hash with normalized (lowercase, trimmed) input for backward
     * compatibility with existing databases.
     *
     * Note: For new projects requiring higher security, consider using secureHash()
     * which uses HMAC-SHA256 with a derived key.
     *
     * @param string $value The value to hash
     *
     * @return string The hex-encoded hash
     */
    public function hash(string $value): string
    {
        return hash('sha256', mb_strtolower(trim($value)));
    }

    /**
     * Creates a keyed hash of the given value using HMAC-SHA256.
     *
     * This is more secure than plain hash() as it requires the secret key to generate
     * the same hash. Use this for new projects where backward compatibility with
     * existing plain SHA-256 hashes is not required.
     *
     * Security features:
     * - Uses HMAC instead of plain hash (requires secret key)
     * - Derives hash key using HKDF for key separation
     * - Uses separate pepper if configured
     * - Deterministic output for searchability
     *
     * @param string $value The value to hash
     *
     * @return string The hex-encoded HMAC hash
     */
    public function secureHash(string $value): string
    {
        $key = $this->getDerivedHashKey();
        $normalizedValue = mb_strtolower(trim($value));

        return hash_hmac('sha256', $normalizedValue, $key);
    }

    /**
     * Securely compare two hashes using constant-time comparison.
     *
     * This prevents timing attacks when comparing hash values.
     *
     * @param string $hash1 First hash to compare
     * @param string $hash2 Second hash to compare
     *
     * @return bool True if hashes match
     */
    public function hashEquals(string $hash1, string $hash2): bool
    {
        return hash_equals($hash1, $hash2);
    }

    /**
     * Verify that a value matches a stored hash (plain SHA-256).
     *
     * @param string $value      The plaintext value to verify
     * @param string $storedHash The stored hash to compare against
     *
     * @return bool True if the value matches the hash
     */
    public function verifyHash(string $value, string $storedHash): bool
    {
        return hash_equals($storedHash, $this->hash($value));
    }

    /**
     * Verify that a value matches a stored secure hash (HMAC-SHA256).
     *
     * @param string $value      The plaintext value to verify
     * @param string $storedHash The stored HMAC hash to compare against
     *
     * @return bool True if the value matches the hash
     */
    public function verifySecureHash(string $value, string $storedHash): bool
    {
        return hash_equals($storedHash, $this->secureHash($value));
    }

    /**
     * Get the derived key for hashing operations.
     *
     * Uses HKDF to derive a separate key for hashing from the master key or pepper.
     *
     * @return string The derived hash key
     */
    private function getDerivedHashKey(): string
    {
        if ($this->derivedHashKey === null) {
            $sourceKey = $this->hashPepper ?? $this->encryptionKey;
            $this->derivedHashKey = hash_hkdf('sha256', $sourceKey, 32, self::HKDF_PURPOSE_HASHING);
        }

        return $this->derivedHashKey;
    }

    /**
     * Derives the encryption key from the entity ID and the master encryption key.
     *
     * Uses HKDF (HMAC-based Key Derivation Function) for secure key derivation:
     * 1. First derives a purpose-specific key from the master key
     * 2. Then derives an entity-specific key for actual encryption
     *
     * @param string $entityId The unique entity identifier
     *
     * @return string The derived key for AES-256-CBC (32 bytes)
     */
    private function deriveKey(string $entityId): string
    {
        // Derive purpose-specific key using HKDF
        $purposeKey = hash_hkdf('sha256', $this->encryptionKey, 32, self::HKDF_PURPOSE_ENCRYPTION);

        // Derive entity-specific key
        return hash_hmac('sha256', $entityId, $purposeKey);
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
