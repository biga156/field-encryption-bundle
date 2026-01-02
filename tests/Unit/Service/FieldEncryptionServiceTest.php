<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Tests\Unit\Service;

use Caeligo\FieldEncryptionBundle\Service\FieldEncryptionService;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for FieldEncryptionService.
 */
class FieldEncryptionServiceTest extends TestCase
{
    private const TEST_KEY = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
    private FieldEncryptionService $service;

    protected function setUp(): void
    {
        $this->service = new FieldEncryptionService(self::TEST_KEY);
    }

    public function testEncryptDecryptString(): void
    {
        $plaintext = 'Hello, World!';
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($plaintext, $entityId);

        $this->assertNotEquals($plaintext, $encrypted);
        $this->assertNotEmpty($encrypted);

        $decrypted = $this->service->decrypt($encrypted, $entityId);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptDecryptEmptyString(): void
    {
        $plaintext = '';
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($plaintext, $entityId);
        $decrypted = $this->service->decrypt($encrypted, $entityId);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptDecryptUnicodeString(): void
    {
        $plaintext = 'Héllo, 世界! 🌍';
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($plaintext, $entityId);
        $decrypted = $this->service->decrypt($encrypted, $entityId);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptDecryptLongString(): void
    {
        $plaintext = str_repeat('Lorem ipsum dolor sit amet, consectetur adipiscing elit. ', 1000);
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($plaintext, $entityId);
        $decrypted = $this->service->decrypt($encrypted, $entityId);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testDifferentEntityIdsProduceDifferentCiphertexts(): void
    {
        $plaintext = 'Hello, World!';

        $encrypted1 = $this->service->encrypt($plaintext, 'entity-1');
        $encrypted2 = $this->service->encrypt($plaintext, 'entity-2');

        $this->assertNotEquals($encrypted1, $encrypted2);
    }

    public function testSameInputProducesDifferentCiphertexts(): void
    {
        $plaintext = 'Hello, World!';
        $entityId = 'test-entity-123';

        $encrypted1 = $this->service->encrypt($plaintext, $entityId);
        $encrypted2 = $this->service->encrypt($plaintext, $entityId);

        // Should be different due to random IV
        $this->assertNotEquals($encrypted1, $encrypted2);

        // But both should decrypt to the same value
        $this->assertEquals($plaintext, $this->service->decrypt($encrypted1, $entityId));
        $this->assertEquals($plaintext, $this->service->decrypt($encrypted2, $entityId));
    }

    public function testDecryptWithWrongEntityIdReturnsNull(): void
    {
        $plaintext = 'Hello, World!';
        $encrypted = $this->service->encrypt($plaintext, 'correct-entity-id');

        $decrypted = $this->service->decrypt($encrypted, 'wrong-entity-id');

        // Should return null or garbage (depending on implementation)
        $this->assertNotEquals($plaintext, $decrypted);
    }

    public function testDecryptNullReturnsNull(): void
    {
        $result = $this->service->decrypt(null, 'test-entity');

        $this->assertNull($result);
    }

    public function testDecryptEmptyStringReturnsNull(): void
    {
        $result = $this->service->decrypt('', 'test-entity');

        $this->assertNull($result);
    }

    public function testDecryptInvalidPayloadReturnsNull(): void
    {
        $result = $this->service->decrypt('not-valid-encrypted-data', 'test-entity');

        $this->assertNull($result);
    }

    public function testHash(): void
    {
        $value = 'test@example.com';

        $hash1 = $this->service->hash($value);
        $hash2 = $this->service->hash($value);

        // Same input should produce same hash
        $this->assertEquals($hash1, $hash2);

        // Hash should be SHA-256 (64 chars hex)
        $this->assertEquals(64, strlen($hash1));
        $this->assertTrue(ctype_xdigit($hash1));
    }

    public function testHashNormalizesInput(): void
    {
        $hash1 = $this->service->hash('Test@Example.com');
        $hash2 = $this->service->hash('test@example.com');
        $hash3 = $this->service->hash('  test@example.com  ');

        // Should all produce the same hash due to normalization
        $this->assertEquals($hash1, $hash2);
        $this->assertEquals($hash2, $hash3);
    }

    public function testHashDifferentValuesProduceDifferentHashes(): void
    {
        $hash1 = $this->service->hash('value1');
        $hash2 = $this->service->hash('value2');

        $this->assertNotEquals($hash1, $hash2);
    }

    public function testGenerateKey(): void
    {
        $key1 = FieldEncryptionService::generateKey();
        $key2 = FieldEncryptionService::generateKey();

        // Should be 64 character hex strings
        $this->assertEquals(64, strlen($key1));
        $this->assertEquals(64, strlen($key2));
        $this->assertTrue(ctype_xdigit($key1));
        $this->assertTrue(ctype_xdigit($key2));

        // Should be different (random)
        $this->assertNotEquals($key1, $key2);
    }

    public function testEncryptedPayloadFormat(): void
    {
        $plaintext = 'Hello, World!';
        $entityId = 'test-entity-123';

        $encrypted = $this->service->encrypt($plaintext, $entityId);

        // Should be base64 encoded
        $decoded = base64_decode($encrypted, true);
        $this->assertNotFalse($decoded);

        // Should be valid JSON
        $json = json_decode($decoded, true);
        $this->assertIsArray($json);

        // Should have 'iv' and 'value' keys
        $this->assertArrayHasKey('iv', $json);
        $this->assertArrayHasKey('value', $json);
    }

    public function testHashEqualsWithMatchingHashes(): void
    {
        $hash1 = $this->service->hash('test@example.com');
        $hash2 = $this->service->hash('test@example.com');

        $this->assertTrue($this->service->hashEquals($hash1, $hash2));
    }

    public function testHashEqualsWithDifferentHashes(): void
    {
        $hash1 = $this->service->hash('test1@example.com');
        $hash2 = $this->service->hash('test2@example.com');

        $this->assertFalse($this->service->hashEquals($hash1, $hash2));
    }

    public function testVerifyHashWithCorrectValue(): void
    {
        $value = 'test@example.com';
        $hash = $this->service->hash($value);

        $this->assertTrue($this->service->verifyHash($value, $hash));
    }

    public function testVerifyHashWithIncorrectValue(): void
    {
        $hash = $this->service->hash('correct@example.com');

        $this->assertFalse($this->service->verifyHash('wrong@example.com', $hash));
    }

    public function testVerifyHashNormalizesInput(): void
    {
        $hash = $this->service->hash('test@example.com');

        // Should match with different cases and whitespace
        $this->assertTrue($this->service->verifyHash('TEST@EXAMPLE.COM', $hash));
        $this->assertTrue($this->service->verifyHash('  test@example.com  ', $hash));
    }

    public function testHashWithPepperProducesDifferentResults(): void
    {
        $serviceWithoutPepper = new FieldEncryptionService(self::TEST_KEY);
        $serviceWithPepper = new FieldEncryptionService(self::TEST_KEY, 'custom-pepper-key');

        $hash1 = $serviceWithoutPepper->hash('test@example.com');
        $hash2 = $serviceWithPepper->hash('test@example.com');

        // Different pepper should produce different hashes
        $this->assertNotEquals($hash1, $hash2);
    }

    public function testHashWithSamePepperProducesSameResults(): void
    {
        $service1 = new FieldEncryptionService(self::TEST_KEY, 'same-pepper');
        $service2 = new FieldEncryptionService(self::TEST_KEY, 'same-pepper');

        $hash1 = $service1->hash('test@example.com');
        $hash2 = $service2->hash('test@example.com');

        // Same pepper should produce same hashes
        $this->assertEquals($hash1, $hash2);
    }

    public function testHkdfKeyDerivationIsDeterministic(): void
    {
        // Same key and entity ID should always produce the same encrypted result
        // when using the same IV (we can't test this directly, but we can verify
        // that decryption works consistently)
        $service1 = new FieldEncryptionService(self::TEST_KEY);
        $service2 = new FieldEncryptionService(self::TEST_KEY);

        $plaintext = 'Test message';
        $entityId = 'entity-123';

        $encrypted = $service1->encrypt($plaintext, $entityId);

        // Service2 should be able to decrypt what service1 encrypted
        $decrypted = $service2->decrypt($encrypted, $entityId);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testDifferentKeysProduceDifferentEncryption(): void
    {
        $key1 = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
        $key2 = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3';

        $service1 = new FieldEncryptionService($key1);
        $service2 = new FieldEncryptionService($key2);

        $plaintext = 'Test message';
        $entityId = 'entity-123';

        $encrypted1 = $service1->encrypt($plaintext, $entityId);

        // Service2 should NOT be able to decrypt what service1 encrypted
        $decrypted = $service2->decrypt($encrypted1, $entityId);

        $this->assertNotEquals($plaintext, $decrypted);
    }
}
