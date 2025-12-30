# Binary File Encryption

This document covers the encryption of binary files (documents, images, etc.) stored in BLOB fields using AES-256-GCM.

## Overview

Binary file encryption is designed for larger binary data like PDFs, images, documents, etc. The bundle uses:

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key derivation**: HMAC-SHA256(entity_id, master_key)
- **Features**: Optional compression, metadata storage, chunk-based processing

## Basic Usage

### 1. Mark Your Entity

```php
<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedEntity;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedFile;
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;

#[ORM\Entity]
#[EncryptedEntity]
class Document
{
    #[ORM\Id]
    #[ORM\Column(type: 'ulid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: UlidGenerator::class)]
    private ?Ulid $id = null;

    #[ORM\Column(type: Types::BLOB, nullable: true)]
    #[EncryptedFile(
        mimeTypeProperty: 'mimeType',
        originalNameProperty: 'originalName',
        originalSizeProperty: 'originalSize',
    )]
    private $content;

    #[ORM\Column(type: Types::STRING, length: 100, nullable: true)]
    private ?string $mimeType = null;

    #[ORM\Column(type: Types::STRING, length: 255, nullable: true)]
    private ?string $originalName = null;

    #[ORM\Column(type: Types::INTEGER, nullable: true)]
    private ?int $originalSize = null;

    private ?EncryptedFileData $plainContent = null;

    public function getPlainContent(): ?EncryptedFileData
    {
        return $this->plainContent;
    }

    public function setPlainContent(?EncryptedFileData $content): self
    {
        $this->plainContent = $content;
        return $this;
    }

    public function getMimeType(): ?string
    {
        return $this->mimeType;
    }

    public function getOriginalName(): ?string
    {
        return $this->originalName;
    }

    public function getOriginalSize(): ?int
    {
        return $this->originalSize;
    }
}
```

## Attribute Reference

### `#[EncryptedFile]`

```php
#[EncryptedFile(
    plainType: 'dto',              // 'dto' (EncryptedFileData) or 'string' (raw binary)
    plainProperty: 'plainContent', // Default: 'plain' + PropertyName
    mimeTypeProperty: 'mimeType',  // Property to store MIME type (optional)
    originalNameProperty: 'name',  // Property to store filename (optional)
    originalSizeProperty: 'size',  // Property to store file size (optional)
    compress: true,                // Enable gzip compression (optional)
    maxSize: 5242880,              // Max file size in bytes (default: 5MB)
    chunkSize: 163840,             // Encryption chunk size (default: 160KB)
)]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `plainType` | string | `'dto'` | Type of plain property: `'dto'` or `'string'` |
| `plainProperty` | string\|null | Auto | Transient property name for decrypted data |
| `mimeTypeProperty` | string\|null | null | Property to store MIME type |
| `originalNameProperty` | string\|null | null | Property to store original filename |
| `originalSizeProperty` | string\|null | null | Property to store original file size |
| `compress` | bool\|null | null | Compress before encryption (null = bundle default) |
| `maxSize` | int\|null | 5MB | Maximum allowed file size |
| `chunkSize` | int\|null | 160KB | Chunk size for processing |

## Working with EncryptedFileData

The `EncryptedFileData` DTO provides convenient methods for working with file data.

### Creating Instances

```php
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;

// From Symfony UploadedFile (most common)
$fileData = EncryptedFileData::fromUploadedFile($uploadedFile);

// From file path
$fileData = EncryptedFileData::fromPath('/path/to/document.pdf');

// From base64 string
$fileData = EncryptedFileData::fromBase64($base64Content, 'application/pdf', 'document.pdf');

// From data URI
$fileData = EncryptedFileData::fromDataUri('data:image/png;base64,...', 'image.png');

// Manual construction
$fileData = new EncryptedFileData(
    content: $binaryContent,
    mimeType: 'application/pdf',
    originalName: 'document.pdf',
    size: strlen($binaryContent)
);
```

### Using the DTO

```php
// Set on entity
$document->setPlainContent($fileData);
$entityManager->persist($document);
$entityManager->flush();

// Retrieve and use
$fileData = $document->getPlainContent();

// Access content
$content = $fileData->getContent();          // Raw binary
$base64 = $fileData->toBase64();             // Base64 string
$dataUri = $fileData->toDataUri();           // Data URI for embedding in HTML

// Access metadata
$mimeType = $fileData->getMimeType();        // e.g., 'application/pdf'
$name = $fileData->getOriginalName();        // e.g., 'document.pdf'
$size = $fileData->getSize();                // Size in bytes
$formatted = $fileData->getFormattedSize();  // e.g., '1.50 MB'

// Utility methods
$extension = $fileData->getExtension();      // e.g., 'pdf'
$isImage = $fileData->isImage();             // true if image/* MIME type
$hash = $fileData->getHash();                // SHA-256 hash of content

// Save to file
$fileData->saveTo('/path/to/save.pdf');

// Create modified copy
$newFileData = $fileData->withMetadata('application/pdf', 'renamed.pdf');
```

## Metadata Storage

The bundle supports two ways to store file metadata:

### 1. In Separate Columns (Recommended)

Metadata is stored in dedicated database columns, allowing you to:
- Query files by MIME type, name, or size
- Display file info without decryption
- Build file listings efficiently

```php
#[EncryptedFile(
    mimeTypeProperty: 'mimeType',
    originalNameProperty: 'originalName',
    originalSizeProperty: 'originalSize',
)]
private $content;

#[ORM\Column(type: Types::STRING, length: 100, nullable: true)]
private ?string $mimeType = null;
```

### 2. In Encrypted Payload Only

Metadata is stored inside the encrypted payload. Useful when you don't need to query by metadata.

```php
#[EncryptedFile]  // No metadata properties specified
private $content;
```

Metadata can still be extracted without full decryption using `BinaryEncryptionService::extractMetadata()`.

## Compression

Enable compression for text-based files to reduce storage:

```php
#[EncryptedFile(compress: true)]
private $content;
```

**Best practices:**
- ✅ Enable for: Text files, XML, JSON, HTML, uncompressed formats
- ❌ Disable for: Images (JPEG, PNG), videos, ZIP files, already-compressed data

## Payload Format

Binary encrypted data uses the following format:

```
[magic: 4 bytes "CEFF"]       - Identifies encrypted file format
[format_version: 1 byte]      - Format version (currently 1)
[key_version: 1 byte]         - Which key version was used
[flags: 1 byte]               - Bit flags (bit 0 = compressed)
[metadata_length: 2 bytes]    - Length of metadata JSON
[metadata: variable]          - JSON with mimeType, originalName, originalSize
[iv: 12 bytes]                - Initialization vector
[tag: 16 bytes]               - GCM authentication tag
[encrypted_content: variable] - The encrypted file data
```

This format allows:
- Detection of encrypted data via magic bytes ("CEFF")
- Key version tracking for rotation
- Metadata extraction without decryption
- Integrity verification via GCM tag

## Size Limits

| Setting | Default | Maximum |
|---------|---------|---------|
| `maxSize` | 5 MB | 50 MB |
| `chunkSize` | 160 KB | - |

Configure globally or per-field:

```yaml
# config/packages/field_encryption.yaml
field_encryption:
    file_encryption:
        max_size: 10485760    # 10MB
        chunk_size: 163840    # 160KB
        compression: false
```

```php
// Per-field override
#[EncryptedFile(maxSize: 20971520)]  // 20MB for this field
private $largeDocument;
```

## Raw String Mode

For simpler use cases where you don't need the DTO:

```php
#[ORM\Column(type: Types::BLOB, nullable: true)]
#[EncryptedFile(plainType: 'string')]
private $content;

private ?string $plainContent = null;  // Raw binary string

public function getPlainContent(): ?string
{
    return $this->plainContent;
}

public function setPlainContent(?string $content): self
{
    $this->plainContent = $content;
    return $this;
}
```

## Controller Example

```php
#[Route('/document/{id}/download')]
public function download(Document $document): Response
{
    $fileData = $document->getPlainContent();
    
    if (!$fileData) {
        throw $this->createNotFoundException();
    }
    
    $response = new Response($fileData->getContent());
    $response->headers->set('Content-Type', $fileData->getMimeType());
    $response->headers->set(
        'Content-Disposition',
        'attachment; filename="' . $fileData->getOriginalName() . '"'
    );
    
    return $response;
}

#[Route('/document/{id}/preview')]
public function preview(Document $document): Response
{
    $fileData = $document->getPlainContent();
    
    if (!$fileData || !$fileData->isImage()) {
        throw $this->createNotFoundException();
    }
    
    // Return as inline image
    return new Response($fileData->getContent(), 200, [
        'Content-Type' => $fileData->getMimeType(),
    ]);
}
```

## Twig Integration

```twig
{# Embed image directly #}
<img src="{{ document.plainContent.toDataUri() }}" alt="{{ document.originalName }}">

{# Display file info #}
<p>
    File: {{ document.originalName }}<br>
    Type: {{ document.mimeType }}<br>
    Size: {{ document.plainContent.formattedSize }}
</p>
```
