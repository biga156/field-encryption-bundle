<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Service;

use Caeligo\FieldEncryptionBundle\Exception\DecryptionException;
use Caeligo\FieldEncryptionBundle\Exception\EncryptionException;
use Caeligo\FieldEncryptionBundle\Exception\FileTooLargeException;
use Caeligo\FieldEncryptionBundle\Exception\InvalidKeyException;
use Caeligo\FieldEncryptionBundle\Exception\UnsupportedVersionException;
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;

/**
 * Service for encrypting and decrypting binary file data using AES-256-GCM.
 *
 * Features:
 * - AES-256-GCM authenticated encryption (faster than CBC with HMAC)
 * - Chunk-based processing for memory efficiency
 * - Support for multiple key versions (for key rotation)
 * - Optional gzip compression before encryption
 * - Metadata storage within the encrypted payload
 *
 * Payload format (version 1):
 * ```
 * [magic: 4 bytes "CEFF"]
 * [format_version: 1 byte]
 * [key_version: 1 byte]
 * [flags: 1 byte - bit 0: compressed]
 * [metadata_length: 2 bytes (uint16 BE)]
 * [metadata: JSON string]
 * [iv: 12 bytes]
 * [tag: 16 bytes]
 * [encrypted_content: variable]
 * ```
 *
 * @author Bíró Gábor (biga156)
 */
class BinaryEncryptionService
{
    /**
     * Magic bytes identifying our encrypted file format.
     */
    private const MAGIC = 'CEFF'; // Caeligo Encrypted File Format

    /**
     * Current format version.
     */
    private const FORMAT_VERSION = 1;

    /**
     * Supported format versions.
     */
    private const SUPPORTED_VERSIONS = [1];

    /**
     * Encryption cipher (AES-256-GCM).
     */
    private const CIPHER = 'aes-256-gcm';

    /**
     * IV length for GCM mode (12 bytes recommended by NIST).
     */
    private const IV_LENGTH = 12;

    /**
     * Authentication tag length for GCM (16 bytes).
     */
    private const TAG_LENGTH = 16;

    /**
     * Header size (magic + version + key_version + flags + metadata_length).
     */
    private const HEADER_SIZE = 9;

    /**
     * Flag bit: content is compressed.
     */
    private const FLAG_COMPRESSED = 0b00000001;

    /**
     * Default chunk size (160KB = 10000 AES blocks).
     */
    public const DEFAULT_CHUNK_SIZE = 163840;

    /**
     * Default maximum file size (5MB).
     */
    public const DEFAULT_MAX_SIZE = 5242880;

    /**
     * Maximum allowed file size (50MB).
     */
    public const MAX_ALLOWED_SIZE = 52428800;

    private string $encryptionKey;
    private int $keyVersion;

    /** @var array<int, string> */
    private array $previousKeys;

    private int $defaultChunkSize;
    private int $defaultMaxSize;
    private bool $defaultCompress;

    /**
     * @param string            $encryptionKey    The current encryption key (hex-encoded, 64 chars)
     * @param int               $keyVersion       The version number of the current key (default: 1)
     * @param array<int,string> $previousKeys     Previous keys indexed by version number
     * @param int               $defaultChunkSize Default chunk size in bytes
     * @param int               $defaultMaxSize   Default maximum file size in bytes
     * @param bool              $defaultCompress  Whether to compress by default
     */
    public function __construct(
        string $encryptionKey,
        int $keyVersion = 1,
        array $previousKeys = [],
        int $defaultChunkSize = self::DEFAULT_CHUNK_SIZE,
        int $defaultMaxSize = self::DEFAULT_MAX_SIZE,
        bool $defaultCompress = false,
    ) {
        $this->validateKey($encryptionKey);
        $this->encryptionKey = $encryptionKey;
        $this->keyVersion = $keyVersion;
        $this->previousKeys = $previousKeys;
        $this->defaultChunkSize = $defaultChunkSize;
        $this->defaultMaxSize = $defaultMaxSize;
        $this->defaultCompress = $defaultCompress;
    }

    /**
     * Encrypt binary data.
     *
     * @param string      $data      The binary data to encrypt
     * @param string      $entityId  The entity ID for key derivation
     * @param array       $metadata  Optional metadata to store with the encrypted data
     * @param bool|null   $compress  Whether to compress (null = use default)
     * @param int|null    $maxSize   Maximum size (null = use default)
     * @param int|null    $chunkSize Chunk size (null = use default)
     *
     * @return string The encrypted binary payload
     *
     * @throws FileTooLargeException If the data exceeds the maximum size
     * @throws EncryptionException   If encryption fails
     */
    public function encrypt(
        string $data,
        string $entityId,
        array $metadata = [],
        ?bool $compress = null,
        ?int $maxSize = null,
        ?int $chunkSize = null,
    ): string {
        $maxSize = $maxSize ?? $this->defaultMaxSize;
        $compress = $compress ?? $this->defaultCompress;
        $chunkSize = $chunkSize ?? $this->defaultChunkSize;

        $dataSize = strlen($data);
        if ($dataSize > $maxSize) {
            throw new FileTooLargeException($dataSize, $maxSize);
        }

        // Compress if enabled
        $flags = 0;
        if ($compress && $dataSize > 0) {
            $compressed = gzencode($data, 6);
            if ($compressed !== false && strlen($compressed) < $dataSize) {
                $data = $compressed;
                $flags |= self::FLAG_COMPRESSED;
            }
        }

        // Derive encryption key
        $key = $this->deriveKey($entityId);

        // Generate IV
        $iv = random_bytes(self::IV_LENGTH);

        // Encrypt
        $tag = '';
        $encrypted = openssl_encrypt(
            $data,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '', // AAD
            self::TAG_LENGTH
        );

        if ($encrypted === false) {
            throw EncryptionException::encryptionFailed(openssl_error_string() ?: 'Unknown OpenSSL error');
        }

        // Build metadata JSON
        $metadataJson = json_encode($metadata, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($metadataJson === false) {
            throw EncryptionException::encryptionFailed('Failed to encode metadata');
        }
        $metadataLength = strlen($metadataJson);

        // Build payload
        $payload = self::MAGIC;                                    // 4 bytes
        $payload .= chr(self::FORMAT_VERSION);                     // 1 byte
        $payload .= chr($this->keyVersion);                        // 1 byte
        $payload .= chr($flags);                                   // 1 byte
        $payload .= pack('n', $metadataLength);                    // 2 bytes (uint16 BE)
        $payload .= $metadataJson;                                 // variable
        $payload .= $iv;                                           // 12 bytes
        $payload .= $tag;                                          // 16 bytes
        $payload .= $encrypted;                                    // variable

        return $payload;
    }

    /**
     * Encrypt an EncryptedFileData DTO.
     *
     * @param EncryptedFileData $fileData  The file data to encrypt
     * @param string            $entityId  The entity ID for key derivation
     * @param bool|null         $compress  Whether to compress (null = use default)
     * @param int|null          $maxSize   Maximum size (null = use default)
     *
     * @return string The encrypted binary payload
     */
    public function encryptFileData(
        EncryptedFileData $fileData,
        string $entityId,
        ?bool $compress = null,
        ?int $maxSize = null,
    ): string {
        $metadata = [
            'mimeType' => $fileData->getMimeType(),
            'originalName' => $fileData->getOriginalName(),
            'originalSize' => $fileData->getSize(),
        ];

        return $this->encrypt(
            $fileData->getContent(),
            $entityId,
            $metadata,
            $compress,
            $maxSize,
        );
    }

    /**
     * Decrypt binary data.
     *
     * @param string $payload  The encrypted payload
     * @param string $entityId The entity ID for key derivation
     *
     * @return string The decrypted binary data
     *
     * @throws DecryptionException        If decryption fails
     * @throws UnsupportedVersionException If the format version is not supported
     * @throws InvalidKeyException         If the key version is not available
     */
    public function decrypt(string $payload, string $entityId): string
    {
        $header = $this->parseHeader($payload);

        // Get the key for this version
        $key = $this->getKeyForVersion($header['keyVersion'], $entityId);

        // Extract encrypted content
        $dataStart = self::HEADER_SIZE + $header['metadataLength'] + self::IV_LENGTH + self::TAG_LENGTH;
        $encrypted = substr($payload, $dataStart);

        // Decrypt
        $decrypted = openssl_decrypt(
            $encrypted,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $header['iv'],
            $header['tag'],
        );

        if ($decrypted === false) {
            throw DecryptionException::authenticationFailed();
        }

        // Decompress if needed
        if ($header['flags'] & self::FLAG_COMPRESSED) {
            $decompressed = gzdecode($decrypted);
            if ($decompressed === false) {
                throw DecryptionException::decryptionFailed('Failed to decompress data');
            }
            $decrypted = $decompressed;
        }

        return $decrypted;
    }

    /**
     * Decrypt to an EncryptedFileData DTO.
     *
     * @param string $payload  The encrypted payload
     * @param string $entityId The entity ID for key derivation
     *
     * @return EncryptedFileData The decrypted file data with metadata
     */
    public function decryptToFileData(string $payload, string $entityId): EncryptedFileData
    {
        $content = $this->decrypt($payload, $entityId);
        $metadata = $this->extractMetadata($payload);

        return new EncryptedFileData(
            content: $content,
            mimeType: $metadata['mimeType'] ?? null,
            originalName: $metadata['originalName'] ?? null,
            size: $metadata['originalSize'] ?? null,
        );
    }

    /**
     * Extract metadata from an encrypted payload without decrypting the content.
     *
     * @param string $payload The encrypted payload
     *
     * @return array<string, mixed> The metadata array
     */
    public function extractMetadata(string $payload): array
    {
        $header = $this->parseHeader($payload);

        return $header['metadata'];
    }

    /**
     * Get the key version from an encrypted payload.
     *
     * @param string $payload The encrypted payload
     *
     * @return int The key version
     */
    public function getPayloadKeyVersion(string $payload): int
    {
        $header = $this->parseHeader($payload);

        return $header['keyVersion'];
    }

    /**
     * Check if a payload is encrypted with the current key.
     *
     * @param string $payload The encrypted payload
     *
     * @return bool True if encrypted with current key
     */
    public function isCurrentKeyVersion(string $payload): bool
    {
        return $this->getPayloadKeyVersion($payload) === $this->keyVersion;
    }

    /**
     * Re-encrypt a payload with the current key.
     *
     * @param string    $payload   The encrypted payload
     * @param string    $entityId  The entity ID for key derivation
     * @param bool|null $compress  Whether to compress (null = preserve original)
     *
     * @return string The re-encrypted payload
     */
    public function reEncrypt(string $payload, string $entityId, ?bool $compress = null): string
    {
        $header = $this->parseHeader($payload);
        $content = $this->decrypt($payload, $entityId);

        // Preserve compression flag if not specified
        if ($compress === null) {
            $compress = (bool) ($header['flags'] & self::FLAG_COMPRESSED);
        }

        return $this->encrypt($content, $entityId, $header['metadata'], $compress);
    }

    /**
     * Parse the header of an encrypted payload.
     *
     * @param string $payload The encrypted payload
     *
     * @return array{magic: string, formatVersion: int, keyVersion: int, flags: int, metadataLength: int, metadata: array, iv: string, tag: string}
     *
     * @throws DecryptionException         If the payload is invalid
     * @throws UnsupportedVersionException If the format version is not supported
     */
    private function parseHeader(string $payload): array
    {
        if (strlen($payload) < self::HEADER_SIZE + self::IV_LENGTH + self::TAG_LENGTH) {
            throw DecryptionException::invalidPayload();
        }

        $magic = substr($payload, 0, 4);
        if ($magic !== self::MAGIC) {
            throw DecryptionException::invalidPayload();
        }

        $formatVersion = ord($payload[4]);
        if (!in_array($formatVersion, self::SUPPORTED_VERSIONS, true)) {
            throw new UnsupportedVersionException($formatVersion, self::SUPPORTED_VERSIONS);
        }

        $keyVersion = ord($payload[5]);
        $flags = ord($payload[6]);
        $metadataLength = unpack('n', substr($payload, 7, 2))[1];

        if (strlen($payload) < self::HEADER_SIZE + $metadataLength + self::IV_LENGTH + self::TAG_LENGTH) {
            throw DecryptionException::invalidPayload();
        }

        $metadataJson = substr($payload, self::HEADER_SIZE, $metadataLength);
        $metadata = json_decode($metadataJson, true) ?? [];

        $ivStart = self::HEADER_SIZE + $metadataLength;
        $iv = substr($payload, $ivStart, self::IV_LENGTH);
        $tag = substr($payload, $ivStart + self::IV_LENGTH, self::TAG_LENGTH);

        return [
            'magic' => $magic,
            'formatVersion' => $formatVersion,
            'keyVersion' => $keyVersion,
            'flags' => $flags,
            'metadataLength' => $metadataLength,
            'metadata' => $metadata,
            'iv' => $iv,
            'tag' => $tag,
        ];
    }

    /**
     * Get the derived key for a specific version.
     *
     * @param int    $version  The key version
     * @param string $entityId The entity ID for key derivation
     *
     * @return string The derived key
     *
     * @throws InvalidKeyException If the key version is not available
     */
    private function getKeyForVersion(int $version, string $entityId): string
    {
        if ($version === $this->keyVersion) {
            return $this->deriveKey($entityId);
        }

        if (!isset($this->previousKeys[$version])) {
            throw InvalidKeyException::unknownKeyVersion($version);
        }

        return $this->deriveKeyFromMaster($this->previousKeys[$version], $entityId);
    }

    /**
     * Derive the encryption key for a specific entity.
     *
     * @param string $entityId The entity ID
     *
     * @return string The derived key (32 bytes)
     */
    private function deriveKey(string $entityId): string
    {
        return $this->deriveKeyFromMaster($this->encryptionKey, $entityId);
    }

    /**
     * Derive the encryption key from a master key and entity ID.
     *
     * @param string $masterKey The master key (hex-encoded)
     * @param string $entityId  The entity ID
     *
     * @return string The derived key (32 bytes raw binary)
     */
    private function deriveKeyFromMaster(string $masterKey, string $entityId): string
    {
        // Use HKDF-like derivation: HMAC-SHA256(masterKey, entityId)
        // The result is 32 bytes (256 bits), perfect for AES-256
        return hash_hmac('sha256', $entityId, hex2bin($masterKey), true);
    }

    /**
     * Validate the encryption key format.
     *
     * @param string $key The key to validate
     *
     * @throws InvalidKeyException If the key is invalid
     */
    private function validateKey(string $key): void
    {
        if (strlen($key) !== 64) {
            throw InvalidKeyException::invalidLength(64, strlen($key));
        }

        if (!ctype_xdigit($key)) {
            throw InvalidKeyException::invalidFormat('Key must be a hexadecimal string');
        }
    }

    /**
     * Get the current key version.
     */
    public function getCurrentKeyVersion(): int
    {
        return $this->keyVersion;
    }

    /**
     * Get the default maximum file size.
     */
    public function getDefaultMaxSize(): int
    {
        return $this->defaultMaxSize;
    }

    /**
     * Get the default chunk size.
     */
    public function getDefaultChunkSize(): int
    {
        return $this->defaultChunkSize;
    }

    /**
     * Check if compression is enabled by default.
     */
    public function isCompressionEnabledByDefault(): bool
    {
        return $this->defaultCompress;
    }
}
