<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Tests\Unit\Service;

use Caeligo\FieldEncryptionBundle\Attribute\Encrypted;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedFile;
use Caeligo\FieldEncryptionBundle\Exception\PropertyNotFoundException;
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;
use Caeligo\FieldEncryptionBundle\Service\FieldMapping;
use Caeligo\FieldEncryptionBundle\Service\FieldMappingResolver;
use Caeligo\FieldEncryptionBundle\Service\FileFieldMapping;
use PHPUnit\Framework\TestCase;

/**
 * Test entity with encrypted fields.
 */
class TestEntityForResolver
{
    private ?int $id = null;

    #[Encrypted(hashField: true, hashProperty: 'emailHash')]
    private ?string $email = null;

    private ?string $plainEmail = null;

    private ?string $emailHash = null;

    #[Encrypted]
    private ?string $secret = null;

    private ?string $plainSecret = null;

    #[EncryptedFile(mimeTypeProperty: 'documentMimeType', originalNameProperty: 'documentName')]
    private $document = null;

    private ?EncryptedFileData $plainDocument = null;

    private ?string $documentMimeType = null;
    private ?string $documentName = null;

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

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    public function setSecret(?string $secret): self
    {
        $this->secret = $secret;
        return $this;
    }

    public function getPlainSecret(): ?string
    {
        return $this->plainSecret;
    }

    public function setPlainSecret(?string $plainSecret): self
    {
        $this->plainSecret = $plainSecret;
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
}

/**
 * Entity without encrypted fields.
 */
class PlainEntity
{
    private ?int $id = null;
    private ?string $name = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getName(): ?string
    {
        return $this->name;
    }
}

/**
 * Unit tests for FieldMappingResolver.
 */
class FieldMappingResolverTest extends TestCase
{
    private FieldMappingResolver $resolver;

    protected function setUp(): void
    {
        $this->resolver = new FieldMappingResolver();
    }

    public function testGetMappingsReturnsEncryptedFields(): void
    {
        $entity = new TestEntityForResolver();
        $mappings = $this->resolver->getMappings($entity);

        $this->assertIsArray($mappings);
        $this->assertNotEmpty($mappings);
        $this->assertArrayHasKey('email', $mappings);
        $this->assertArrayHasKey('secret', $mappings);
    }

    public function testGetMappingsReturnsFieldMappingInstances(): void
    {
        $entity = new TestEntityForResolver();
        $mappings = $this->resolver->getMappings($entity);

        foreach ($mappings as $mapping) {
            $this->assertInstanceOf(FieldMapping::class, $mapping);
        }
    }

    public function testGetMappingsCachesResults(): void
    {
        $entity = new TestEntityForResolver();
        $mappings1 = $this->resolver->getMappings($entity);
        $mappings2 = $this->resolver->getMappings($entity);

        $this->assertSame($mappings1, $mappings2);
    }

    public function testGetFileMappingsReturnsEncryptedFileFields(): void
    {
        $entity = new TestEntityForResolver();
        $mappings = $this->resolver->getFileMappings($entity);

        $this->assertIsArray($mappings);
        $this->assertArrayHasKey('document', $mappings);
    }

    public function testGetFileMappingsReturnsFileFieldMappingInstances(): void
    {
        $entity = new TestEntityForResolver();
        $mappings = $this->resolver->getFileMappings($entity);

        foreach ($mappings as $mapping) {
            $this->assertInstanceOf(FileFieldMapping::class, $mapping);
        }
    }

    public function testHasEncryptedFieldsReturnsTrueForEntityWithEncryptedFields(): void
    {
        $entity = new TestEntityForResolver();
        $hasFields = $this->resolver->hasEncryptedFields($entity);

        $this->assertTrue($hasFields);
    }

    public function testHasEncryptedFieldsReturnsFalseForEntityWithoutEncryptedFields(): void
    {
        $entity = new PlainEntity();
        $hasFields = $this->resolver->hasEncryptedFields($entity);

        $this->assertFalse($hasFields);
    }

    public function testHasEncryptedStringFields(): void
    {
        $entity = new TestEntityForResolver();
        $hasStringFields = $this->resolver->hasEncryptedStringFields($entity);

        $this->assertTrue($hasStringFields);
    }

    public function testHasEncryptedFileFields(): void
    {
        $entity = new TestEntityForResolver();
        $hasFileFields = $this->resolver->hasEncryptedFileFields($entity);

        $this->assertTrue($hasFileFields);
    }

    public function testFieldMappingContainsHashFieldFlag(): void
    {
        $entity = new TestEntityForResolver();
        $mappings = $this->resolver->getMappings($entity);

        $this->assertTrue($mappings['email']->hashField);
        $this->assertFalse($mappings['secret']->hashField);
    }

    public function testPropertyNotFoundException(): void
    {
        $exception = new PropertyNotFoundException('nonExistent', TestEntityForResolver::class);

        $this->assertEquals('nonExistent', $exception->getPropertyName());
        $this->assertEquals(TestEntityForResolver::class, $exception->getEntityClass());
        $this->assertStringContainsString('nonExistent', $exception->getMessage());
    }

    public function testPropertyNotFoundExceptionMetadataFactory(): void
    {
        $exception = PropertyNotFoundException::metadataProperty(
            'missingProp',
            TestEntityForResolver::class,
            'mimeTypeProperty'
        );

        $this->assertEquals('missingProp', $exception->getPropertyName());
        $this->assertStringContainsString('mimeTypeProperty', $exception->getMessage());
    }
}
