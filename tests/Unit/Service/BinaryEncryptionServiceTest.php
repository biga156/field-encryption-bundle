<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Tests\Unit\Service;

use Caeligo\FieldEncryptionBundle\Exception\DecryptionException;
use Caeligo\FieldEncryptionBundle\Exception\FileTooLargeException;
use Caeligo\FieldEncryptionBundle\Exception\InvalidKeyException;
use Caeligo\FieldEncryptionBundle\Exception\UnsupportedVersionException;
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;
use Caeligo\FieldEncryptionBundle\Service\BinaryEncryptionService;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for BinaryEncryptionService.
 */
class BinaryEncryptionServiceTest extends TestCase
{
    private const TEST_KEY = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
    private BinaryEncryptionService $service;

    protected function setUp(): void
    {
        $this->service = new BinaryEncryptionService(self::TEST_KEY);
    }

    public function testEncryptDecryptBinaryData(): void
    {
        $data = random_bytes(1024); // 1KB random binary
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($data, $entityId);

        $this->assertNotEquals($data, $encrypted);
        $this->assertStringStartsWith('CEFF', $encrypted); // Magic bytes

        $decrypted = $this->service->decrypt($encrypted, $entityId);

        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptDecryptEmptyData(): void
    {
        $data = '';
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($data, $entityId);
        $decrypted = $this->service->decrypt($encrypted, $entityId);

        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptDecryptLargeBinaryData(): void
    {
        $data = random_bytes(1024 * 1024); // 1MB
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($data, $entityId);
        $decrypted = $this->service->decrypt($encrypted, $entityId);

        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptWithCompression(): void
    {
        // Compressible data (repeated pattern)
        $data = str_repeat('AAAA', 10000); // 40KB highly compressible
        $entityId = 'test-entity-123';

        $encryptedWithCompression = $this->service->encrypt($data, $entityId, [], true);
        $encryptedWithoutCompression = $this->service->encrypt($data, $entityId, [], false);

        // Compressed should be smaller
        $this->assertLessThan(strlen($encryptedWithoutCompression), strlen($encryptedWithCompression));

        // Both should decrypt correctly
        $this->assertEquals($data, $this->service->decrypt($encryptedWithCompression, $entityId));
        $this->assertEquals($data, $this->service->decrypt($encryptedWithoutCompression, $entityId));
    }

    public function testEncryptRejectsFileTooLarge(): void
    {
        $this->expectException(FileTooLargeException::class);

        $data = random_bytes(1024); // 1KB
        $entityId = 'test-entity-123';

        // Set max size to 512 bytes
        $this->service->encrypt($data, $entityId, [], false, 512);
    }

    public function testEncryptWithMetadata(): void
    {
        $data = 'PDF content here';
        $entityId = 'test-entity-123';
        $metadata = [
            'mimeType' => 'application/pdf',
            'originalName' => 'document.pdf',
            'originalSize' => 16,
        ];

        $encrypted = $this->service->encrypt($data, $entityId, $metadata);
        $extractedMetadata = $this->service->extractMetadata($encrypted);

        $this->assertEquals($metadata, $extractedMetadata);
    }

    public function testEncryptFileData(): void
    {
        $fileData = new EncryptedFileData(
            content: 'Test file content',
            mimeType: 'text/plain',
            originalName: 'test.txt',
            size: 17,
        );
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encryptFileData($fileData, $entityId);
        $decrypted = $this->service->decryptToFileData($encrypted, $entityId);

        $this->assertEquals($fileData->getContent(), $decrypted->getContent());
        $this->assertEquals($fileData->getMimeType(), $decrypted->getMimeType());
        $this->assertEquals($fileData->getOriginalName(), $decrypted->getOriginalName());
        $this->assertEquals($fileData->getSize(), $decrypted->getSize());
    }

    public function testDecryptWithWrongEntityIdFails(): void
    {
        $this->expectException(DecryptionException::class);

        $data = 'secret data';
        $encrypted = $this->service->encrypt($data, 'correct-entity-id');

        $this->service->decrypt($encrypted, 'wrong-entity-id');
    }

    public function testDecryptInvalidPayloadThrowsException(): void
    {
        $this->expectException(DecryptionException::class);

        $this->service->decrypt('not-valid-encrypted-data', 'test-entity');
    }

    public function testDecryptInvalidMagicBytesThrowsException(): void
    {
        $this->expectException(DecryptionException::class);

        $invalidPayload = 'XXXX' . str_repeat("\x00", 100);
        $this->service->decrypt($invalidPayload, 'test-entity');
    }

    public function testDecryptUnsupportedVersionThrowsException(): void
    {
        $this->expectException(UnsupportedVersionException::class);

        // Create payload with invalid version
        $payload = 'CEFF' . chr(99) . str_repeat("\x00", 100); // Version 99
        $this->service->decrypt($payload, 'test-entity');
    }

    public function testPayloadContainsKeyVersion(): void
    {
        $data = 'test data';
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($data, $entityId);
        $keyVersion = $this->service->getPayloadKeyVersion($encrypted);

        $this->assertEquals(1, $keyVersion); // Default key version
    }

    public function testIsCurrentKeyVersion(): void
    {
        $data = 'test data';
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($data, $entityId);

        $this->assertTrue($this->service->isCurrentKeyVersion($encrypted));
    }

    public function testReEncrypt(): void
    {
        $data = 'test data';
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($data, $entityId);
        $reEncrypted = $this->service->reEncrypt($encrypted, $entityId);

        // Should be different (new IV)
        $this->assertNotEquals($encrypted, $reEncrypted);

        // Should decrypt to same value
        $this->assertEquals($data, $this->service->decrypt($reEncrypted, $entityId));
    }

    public function testPreviousKeySupport(): void
    {
        $oldKey = 'b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6b1b2';
        $newKey = 'c1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6c1c2';

        // Encrypt with old key (version 1)
        $oldService = new BinaryEncryptionService($oldKey, 1);
        $data = 'secret data';
        $entityId = 'test-entity-123';
        $encrypted = $oldService->encrypt($data, $entityId);

        // Create new service with new key and old key in previous_keys
        $newService = new BinaryEncryptionService($newKey, 2, [1 => $oldKey]);

        // Should be able to decrypt data encrypted with old key
        $decrypted = $newService->decrypt($encrypted, $entityId);
        $this->assertEquals($data, $decrypted);
    }

    public function testInvalidKeyFormatThrowsException(): void
    {
        $this->expectException(InvalidKeyException::class);

        new BinaryEncryptionService('too-short-key');
    }

    public function testInvalidKeyLengthThrowsException(): void
    {
        $this->expectException(InvalidKeyException::class);

        new BinaryEncryptionService('not-a-hex-key-with-correct-length-but-invalid-chars!!!!!!!!!!!!!');
    }

    public function testGetCurrentKeyVersion(): void
    {
        $service = new BinaryEncryptionService(self::TEST_KEY, 5);

        $this->assertEquals(5, $service->getCurrentKeyVersion());
    }

    public function testGetDefaultMaxSize(): void
    {
        $this->assertEquals(BinaryEncryptionService::DEFAULT_MAX_SIZE, $this->service->getDefaultMaxSize());
    }

    public function testGetDefaultChunkSize(): void
    {
        $this->assertEquals(BinaryEncryptionService::DEFAULT_CHUNK_SIZE, $this->service->getDefaultChunkSize());
    }

    public function testDifferentEntityIdsProduceDifferentCiphertexts(): void
    {
        $data = 'same data';

        $encrypted1 = $this->service->encrypt($data, 'entity-1');
        $encrypted2 = $this->service->encrypt($data, 'entity-2');

        $this->assertNotEquals($encrypted1, $encrypted2);
    }

    public function testExtractMetadataWithoutDecrypting(): void
    {
        $data = 'test data';
        $metadata = ['key' => 'value', 'number' => 42];
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($data, $entityId, $metadata);

        // Should be able to extract metadata without knowing entity ID
        $extracted = $this->service->extractMetadata($encrypted);

        $this->assertEquals($metadata, $extracted);
    }
}
