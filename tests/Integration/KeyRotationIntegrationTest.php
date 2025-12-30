<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Tests\Integration;

use Caeligo\FieldEncryptionBundle\Service\BinaryEncryptionService;
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for key rotation functionality.
 */
class KeyRotationIntegrationTest extends TestCase
{
    private const OLD_KEY = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
    private const NEW_KEY = 'b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6b1b2';

    public function testKeyRotationWorkflow(): void
    {
        $entityId = 'test-entity-123';
        $content = 'Secret document content';
        $fileData = new EncryptedFileData($content, 'text/plain', 'secret.txt');

        // Step 1: Encrypt with old key (version 1)
        $oldService = new BinaryEncryptionService(self::OLD_KEY, 1);
        $encryptedWithOldKey = $oldService->encryptFileData($fileData, $entityId);

        // Verify it was encrypted with key version 1
        $this->assertEquals(1, $oldService->getPayloadKeyVersion($encryptedWithOldKey));
        $this->assertTrue($oldService->isCurrentKeyVersion($encryptedWithOldKey));

        // Step 2: Create new service with rotated key (version 2) and old key in previous keys
        $newService = new BinaryEncryptionService(
            self::NEW_KEY,
            2,
            [1 => self::OLD_KEY] // Previous keys for backward compatibility
        );

        // Verify the new service can decrypt data encrypted with old key
        $decrypted = $newService->decryptToFileData($encryptedWithOldKey, $entityId);
        $this->assertEquals($content, $decrypted->getContent());
        $this->assertEquals('text/plain', $decrypted->getMimeType());

        // Step 3: Re-encrypt with new key
        $encryptedWithNewKey = $newService->reEncrypt($encryptedWithOldKey, $entityId);

        // Verify it's now encrypted with key version 2
        $this->assertEquals(2, $newService->getPayloadKeyVersion($encryptedWithNewKey));
        $this->assertTrue($newService->isCurrentKeyVersion($encryptedWithNewKey));

        // Verify content is preserved
        $decryptedNew = $newService->decryptToFileData($encryptedWithNewKey, $entityId);
        $this->assertEquals($content, $decryptedNew->getContent());

        // Step 4: The old service cannot decrypt data encrypted with new key
        // (because it doesn't have the new key)
        $this->expectException(\Caeligo\FieldEncryptionBundle\Exception\InvalidKeyException::class);
        $oldService->decrypt($encryptedWithNewKey, $entityId);
    }

    public function testMultipleKeyVersionMigration(): void
    {
        $entityId = 'test-entity-456';
        $content = 'Important document';
        $fileData = new EncryptedFileData($content, 'application/pdf', 'important.pdf');

        // Start with key version 1
        $key1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
        $key2 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
        $key3 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

        // Encrypt with version 1
        $service1 = new BinaryEncryptionService($key1, 1);
        $encrypted1 = $service1->encryptFileData($fileData, $entityId);

        // Migrate to version 2 (keeping version 1 in previous keys)
        $service2 = new BinaryEncryptionService($key2, 2, [1 => $key1]);
        $encrypted2 = $service2->reEncrypt($encrypted1, $entityId);

        // Migrate to version 3 (keeping both previous versions)
        $service3 = new BinaryEncryptionService($key3, 3, [1 => $key1, 2 => $key2]);

        // Service 3 should be able to decrypt any version
        $decrypted1 = $service3->decrypt($encrypted1, $entityId);
        $decrypted2 = $service3->decrypt($encrypted2, $entityId);

        $this->assertEquals($content, $decrypted1);
        $this->assertEquals($content, $decrypted2);

        // Re-encrypt to version 3
        $encrypted3 = $service3->reEncrypt($encrypted1, $entityId);
        $this->assertEquals(3, $service3->getPayloadKeyVersion($encrypted3));
    }

    public function testMetadataPreservedDuringKeyRotation(): void
    {
        $entityId = 'test-entity-789';
        $content = 'Binary data here';
        $fileData = new EncryptedFileData(
            content: $content,
            mimeType: 'image/png',
            originalName: 'photo.png',
            size: 16
        );

        // Encrypt with old key
        $oldService = new BinaryEncryptionService(self::OLD_KEY, 1);
        $encrypted = $oldService->encryptFileData($fileData, $entityId);

        // Extract metadata before rotation
        $metadataBefore = $oldService->extractMetadata($encrypted);

        // Rotate key
        $newService = new BinaryEncryptionService(self::NEW_KEY, 2, [1 => self::OLD_KEY]);
        $rotated = $newService->reEncrypt($encrypted, $entityId);

        // Extract metadata after rotation
        $metadataAfter = $newService->extractMetadata($rotated);

        // Metadata should be preserved
        $this->assertEquals($metadataBefore, $metadataAfter);
        $this->assertEquals('image/png', $metadataAfter['mimeType']);
        $this->assertEquals('photo.png', $metadataAfter['originalName']);
        $this->assertEquals(16, $metadataAfter['originalSize']);
    }

    public function testCompressionFlagPreservedDuringKeyRotation(): void
    {
        $entityId = 'test-entity-compression';
        $content = str_repeat('Compressible data ', 1000);
        $fileData = new EncryptedFileData($content, 'text/plain');

        // Encrypt with compression
        $oldService = new BinaryEncryptionService(self::OLD_KEY, 1);
        $encryptedCompressed = $oldService->encrypt(
            $content,
            $entityId,
            ['compressed' => true],
            true // compress
        );

        // Rotate key (should preserve compression)
        $newService = new BinaryEncryptionService(self::NEW_KEY, 2, [1 => self::OLD_KEY]);
        $rotated = $newService->reEncrypt($encryptedCompressed, $entityId);

        // Verify content is preserved
        $decrypted = $newService->decrypt($rotated, $entityId);
        $this->assertEquals($content, $decrypted);
    }

    public function testCannotDecryptWithWrongKey(): void
    {
        $entityId = 'test-entity-wrong-key';
        $content = 'Secret data';
        $fileData = new EncryptedFileData($content, 'text/plain');

        // Encrypt with one key
        $service1 = new BinaryEncryptionService(self::OLD_KEY, 1);
        $encrypted = $service1->encryptFileData($fileData, $entityId);

        // Try to decrypt with different key (not in previous keys)
        $wrongKeyService = new BinaryEncryptionService(self::NEW_KEY, 2); // No previous keys!

        $this->expectException(\Caeligo\FieldEncryptionBundle\Exception\InvalidKeyException::class);
        $wrongKeyService->decrypt($encrypted, $entityId);
    }
}
