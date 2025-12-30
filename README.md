# FieldEncryptionBundle

A Symfony bundle for transparent Doctrine entity field encryption using AES-256-CBC for string fields and AES-256-GCM for binary files.

[![PHP](https://img.shields.io/badge/PHP-8.2%2B-blue.svg)](https://php.net)
[![Symfony](https://img.shields.io/badge/Symfony-6.4%20%7C%207.x-black.svg)](https://symfony.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- 🔐 **Automatic encryption/decryption** - Transparent for your application code
- 📝 **String field encryption** - AES-256-CBC with optional SHA-256 hash for searching
- 📁 **Binary file encryption** - AES-256-GCM for documents, images, etc.
- 🏷️ **Attribute-based configuration** - Simple `#[Encrypted]` and `#[EncryptedFile]` attributes
- 🔄 **Key rotation support** - Safely rotate keys with progress tracking
- 🗜️ **Optional compression** - Gzip compression for binary files
- 📋 **Metadata storage** - Store MIME type, filename, size alongside encrypted content
- 🛠️ **Console commands** - Key generation, rotation wizard, data migration

## Requirements

- PHP 8.2+
- Symfony 6.4+ or 7.x
- Doctrine ORM 2.14+ or 3.x

## Installation

```bash
composer require caeligo/field-encryption-bundle
```

Register the bundle in `config/bundles.php`:

```php
return [
    // ...
    Caeligo\FieldEncryptionBundle\FieldEncryptionBundle::class => ['all' => true],
];
```

## Quick Start

### 1. Generate Encryption Key

```bash
php bin/console field-encryption:generate-key --append-to-env
```

### 2. Configure the Bundle

```yaml
# config/packages/field_encryption.yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
```

### 3. Add Attributes to Your Entity

```php
use Caeligo\FieldEncryptionBundle\Attribute\Encrypted;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedEntity;

#[ORM\Entity]
#[EncryptedEntity]
class User
{
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted(hashField: true, hashProperty: 'emailHash')]
    private ?string $email = null;

    #[ORM\Column(type: Types::TEXT, nullable: true, unique: true)]
    private ?string $emailHash = null;

    private ?string $plainEmail = null;  // Transient, auto-populated

    public function getEmail(): ?string
    {
        return $this->plainEmail;
    }

    public function setEmail(?string $email): self
    {
        $this->plainEmail = $email;
        return $this;
    }
}
```

**That's it!** The bundle automatically encrypts on save and decrypts on load.

## Documentation

| Document | Description |
|----------|-------------|
| [String Encryption](docs/string-encryption.md) | Encrypting text fields (emails, names, etc.) |
| [File Encryption](docs/file-encryption.md) | Encrypting binary files (documents, images) |
| [Console Commands](docs/commands.md) | Key generation, rotation, migration commands |
| [Key Rotation](docs/key-rotation.md) | Safely rotating encryption keys |
| [Configuration](docs/configuration.md) | Complete configuration reference |

## Basic Examples

### Encrypted String Field

```php
#[Encrypted(hashField: true)]
private ?string $email = null;

private ?string $plainEmail = null;
private ?string $emailHash = null;
```

### Encrypted File Field

```php
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedFile;
use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;

#[EncryptedFile(mimeTypeProperty: 'mimeType', originalNameProperty: 'fileName')]
private $document;

private ?EncryptedFileData $plainDocument = null;
private ?string $mimeType = null;
private ?string $fileName = null;
```

### Working with Files

```php
// From upload
$fileData = EncryptedFileData::fromUploadedFile($uploadedFile);
$entity->setPlainDocument($fileData);

// To download
$content = $entity->getPlainDocument()->getContent();
$mimeType = $entity->getPlainDocument()->getMimeType();
```

## Console Commands

```bash
# Generate new encryption key
php bin/console field-encryption:generate-key

# Rotate encryption keys (interactive wizard)
php bin/console field-encryption:rotate-keys --wizard

# Encrypt existing unencrypted data
php bin/console field-encryption:encrypt-existing --dry-run
```

## Security Considerations

- ⚠️ **Never commit encryption keys** - Use environment variables
- 💾 **Backup your keys** - Key loss = data loss
- 🔄 **Plan key rotation** - Use the wizard for safe rotation
- 🔍 **Use hashes for search** - Enable `hashField` for searchable fields
- 🆔 **Use ULID/UUID** - Don't use sequential integers for key derivation

## License

MIT License - see [LICENSE](LICENSE)

## Author

Bíró Gábor ([@biga156](https://github.com/biga156))

## Repository

- **GitHub**: https://github.com/biga156/field-encryption-bundle
- **Packagist**: https://packagist.org/packages/caeligo/field-encryption-bundle
