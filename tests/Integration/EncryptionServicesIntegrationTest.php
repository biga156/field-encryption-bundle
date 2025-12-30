<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Tests\Integration;

use Caeligo\FieldEncryptionBundle\Attribute\Encrypted;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedFile;
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;
use Caeligo\FieldEncryptionBundle\Service\BinaryEncryptionService;
use Caeligo\FieldEncryptionBundle\Service\FieldEncryptionService;
use Caeligo\FieldEncryptionBundle\Service\FieldMappingResolver;
use Caeligo\FieldEncryptionBundle\EventListener\FieldEncryptionListener;
use PHPUnit\Framework\TestCase;

/**
 * Test entity for integration tests.
 */
class TestDocument
{
    private ?int $id = null;

    #[Encrypted(hashField: true, hashProperty: 'emailHash')]
    private ?string $email = null;

    private ?string $plainEmail = null;

    private ?string $emailHash = null;

    #[EncryptedFile(
        mimeTypeProperty: 'documentMimeType',
        originalNameProperty: 'documentName',
        originalSizeProperty: 'documentSize'
    )]
    private $document = null;

    private ?EncryptedFileData $plainDocument = null;

    private ?string $documentMimeType = null;
    private ?string $documentName = null;
    private ?int $documentSize = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setId(?int $id): self
    {
        $this->id = $id;
        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(?string $email): self
    {
        $this->email = $email;
        return $this;
    }

    public function getPlainEmail(): ?string
    {
        return $this->plainEmail;
    }

    public function setPlainEmail(?string $plainEmail): self
    {
        $this->plainEmail = $plainEmail;
        return $this;
    }

    public function getEmailHash(): ?string
    {
        return $this->emailHash;
    }

    public function setEmailHash(?string $emailHash): self
    {
        $this->emailHash = $emailHash;
        return $this;
    }

    public function getDocument()
    {
        return $this->document;
    }

    public function setDocument($document): self
    {
        $this->document = $document;
        return $this;
    }

    public function getPlainDocument(): ?EncryptedFileData
    {
        return $this->plainDocument;
    }

    public function setPlainDocument(?EncryptedFileData $plainDocument): self
    {
        $this->plainDocument = $plainDocument;
        return $this;
    }

    public function getDocumentMimeType(): ?string
    {
        return $this->documentMimeType;
    }

    public function setDocumentMimeType(?string $documentMimeType): self
    {
        $this->documentMimeType = $documentMimeType;
        return $this;
    }

    public function getDocumentName(): ?string
    {
        return $this->documentName;
    }

    public function setDocumentName(?string $documentName): self
    {
        $this->documentName = $documentName;
        return $this;
    }

    public function getDocumentSize(): ?int
    {
        return $this->documentSize;
    }

    public function setDocumentSize(?int $documentSize): self
    {
        $this->documentSize = $documentSize;
        return $this;
    }
}

/**
 * Integration tests for the encryption services working together.
 */
class EncryptionServicesIntegrationTest extends TestCase
{
    private const TEST_KEY = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

    private FieldEncryptionService $fieldEncryptionService;
    private BinaryEncryptionService $binaryEncryptionService;
    private FieldMappingResolver $resolver;

    protected function setUp(): void
    {
        $this->fieldEncryptionService = new FieldEncryptionService(self::TEST_KEY);
        $this->binaryEncryptionService = new BinaryEncryptionService(self::TEST_KEY);
        $this->resolver = new FieldMappingResolver();
    }

    public function testStringFieldEncryptionDecryptionCycle(): void
    {
        $entity = new TestDocument();
        $entity->setId(1);
        $entity->setPlainEmail('test@example.com');

        // Get the entity ID for encryption
        $entityId = (string) $entity->getId();

        // Encrypt
        $encrypted = $this->fieldEncryptionService->encrypt($entity->getPlainEmail(), $entityId);
        $entity->setEmail($encrypted);

        // Verify encrypted
        $this->assertNotEquals('test@example.com', $entity->getEmail());

        // Decrypt
        $decrypted = $this->fieldEncryptionService->decrypt($entity->getEmail(), $entityId);
        $entity->setPlainEmail($decrypted);

        $this->assertEquals('test@example.com', $entity->getPlainEmail());
    }

    public function testBinaryFieldEncryptionDecryptionCycle(): void
    {
        $entity = new TestDocument();
        $entity->setId(1);

        $fileData = new EncryptedFileData(
            content: 'PDF content here',
            mimeType: 'application/pdf',
            originalName: 'document.pdf',
            size: 16
        );
        $entity->setPlainDocument($fileData);

        // Get the entity ID for encryption
        $entityId = (string) $entity->getId();

        // Encrypt
        $encrypted = $this->binaryEncryptionService->encryptFileData($entity->getPlainDocument(), $entityId);
        $entity->setDocument($encrypted);

        // Verify encrypted
        $this->assertStringStartsWith('CEFF', $entity->getDocument());

        // Decrypt
        $decrypted = $this->binaryEncryptionService->decryptToFileData($entity->getDocument(), $entityId);
        $entity->setPlainDocument($decrypted);

        $this->assertEquals('PDF content here', $entity->getPlainDocument()->getContent());
        $this->assertEquals('application/pdf', $entity->getPlainDocument()->getMimeType());
        $this->assertEquals('document.pdf', $entity->getPlainDocument()->getOriginalName());
    }

    public function testMetadataIsExtractableWithoutDecryption(): void
    {
        $entity = new TestDocument();
        $entity->setId(1);

        $fileData = new EncryptedFileData(
            content: 'Secret document content',
            mimeType: 'text/plain',
            originalName: 'secret.txt',
            size: 23
        );

        $entityId = (string) $entity->getId();
        $encrypted = $this->binaryEncryptionService->encryptFileData($fileData, $entityId);

        // Extract metadata without knowing the entity ID
        $metadata = $this->binaryEncryptionService->extractMetadata($encrypted);

        $this->assertEquals('text/plain', $metadata['mimeType']);
        $this->assertEquals('secret.txt', $metadata['originalName']);
        $this->assertEquals(23, $metadata['originalSize']);
    }

    public function testFieldMappingResolverIdentifiesAllFields(): void
    {
        $entity = new TestDocument();

        $stringMappings = $this->resolver->getMappings($entity);
        $fileMappings = $this->resolver->getFileMappings($entity);

        $this->assertArrayHasKey('email', $stringMappings);
        $this->assertTrue($stringMappings['email']->hashField);
        $this->assertEquals('emailHash', $stringMappings['email']->hashProperty);

        $this->assertArrayHasKey('document', $fileMappings);
        $this->assertEquals('documentMimeType', $fileMappings['document']->mimeTypeProperty);
        $this->assertEquals('documentName', $fileMappings['document']->originalNameProperty);
        $this->assertEquals('documentSize', $fileMappings['document']->originalSizeProperty);
    }

    public function testHashFieldsForSearchability(): void
    {
        $entity = new TestDocument();
        $entity->setId(1);

        // Hash the email for searchability
        $hash = $this->fieldEncryptionService->hash('test@example.com');
        $entity->setEmailHash($hash);

        // Same value should produce same hash
        $hash2 = $this->fieldEncryptionService->hash('test@example.com');
        $this->assertEquals($hash, $hash2);

        // Different value should produce different hash
        $hash3 = $this->fieldEncryptionService->hash('other@example.com');
        $this->assertNotEquals($hash, $hash3);
    }

    public function testCompressedEncryption(): void
    {
        $entity = new TestDocument();
        $entity->setId(1);

        // Create highly compressible content
        $content = str_repeat('AAAA', 10000);
        $fileData = new EncryptedFileData(
            content: $content,
            mimeType: 'text/plain',
            originalName: 'compressible.txt'
        );

        $entityId = (string) $entity->getId();

        // Encrypt with compression
        $encryptedCompressed = $this->binaryEncryptionService->encryptFileData(
            $fileData,
            $entityId,
            true // compress
        );

        // Encrypt without compression
        $encryptedUncompressed = $this->binaryEncryptionService->encryptFileData(
            $fileData,
            $entityId,
            false // don't compress
        );

        // Compressed should be smaller
        $this->assertLessThan(strlen($encryptedUncompressed), strlen($encryptedCompressed));

        // Both should decrypt correctly
        $decrypted1 = $this->binaryEncryptionService->decryptToFileData($encryptedCompressed, $entityId);
        $decrypted2 = $this->binaryEncryptionService->decryptToFileData($encryptedUncompressed, $entityId);

        $this->assertEquals($content, $decrypted1->getContent());
        $this->assertEquals($content, $decrypted2->getContent());
    }

    public function testKeyVersionTracking(): void
    {
        $entity = new TestDocument();
        $entity->setId(1);

        $fileData = new EncryptedFileData(
            content: 'test content',
            mimeType: 'text/plain'
        );

        $entityId = (string) $entity->getId();
        $encrypted = $this->binaryEncryptionService->encryptFileData($fileData, $entityId);

        // Verify key version is tracked
        $keyVersion = $this->binaryEncryptionService->getPayloadKeyVersion($encrypted);
        $this->assertEquals(1, $keyVersion);
        $this->assertTrue($this->binaryEncryptionService->isCurrentKeyVersion($encrypted));
    }

    public function testReEncryptionWithSameKey(): void
    {
        $entity = new TestDocument();
        $entity->setId(1);

        $fileData = new EncryptedFileData(
            content: 'original content',
            mimeType: 'text/plain'
        );

        $entityId = (string) $entity->getId();
        $encrypted1 = $this->binaryEncryptionService->encryptFileData($fileData, $entityId);

        // Re-encrypt
        $encrypted2 = $this->binaryEncryptionService->reEncrypt($encrypted1, $entityId);

        // Should be different (new IV)
        $this->assertNotEquals($encrypted1, $encrypted2);

        // Both should decrypt to same content
        $decrypted1 = $this->binaryEncryptionService->decryptToFileData($encrypted1, $entityId);
        $decrypted2 = $this->binaryEncryptionService->decryptToFileData($encrypted2, $entityId);

        $this->assertEquals($decrypted1->getContent(), $decrypted2->getContent());
    }

    public function testMultipleEntityIdsIsolation(): void
    {
        // Create two entities with different IDs
        $entity1 = new TestDocument();
        $entity1->setId(1);

        $entity2 = new TestDocument();
        $entity2->setId(2);

        $plainText = 'Shared secret data';

        // Encrypt with different entity IDs
        $encrypted1 = $this->fieldEncryptionService->encrypt($plainText, (string) $entity1->getId());
        $encrypted2 = $this->fieldEncryptionService->encrypt($plainText, (string) $entity2->getId());

        // Encrypted values should be different
        $this->assertNotEquals($encrypted1, $encrypted2);

        // Each can only decrypt with its own entity ID
        $decrypted1 = $this->fieldEncryptionService->decrypt($encrypted1, (string) $entity1->getId());
        $decrypted2 = $this->fieldEncryptionService->decrypt($encrypted2, (string) $entity2->getId());

        $this->assertEquals($plainText, $decrypted1);
        $this->assertEquals($plainText, $decrypted2);

        // Cross-decryption should fail
        $wrongDecrypt = $this->fieldEncryptionService->decrypt($encrypted1, (string) $entity2->getId());
        $this->assertNotEquals($plainText, $wrongDecrypt);
    }
}
