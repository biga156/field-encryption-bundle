# FieldEncryptionBundle

A reusable Symfony bundle for transparent Doctrine entity field encryption using AES-256-CBC.

## Features

- **Automatic encryption/decryption** - Fields are encrypted before persist/update and decrypted after load
- **Attribute-based configuration** - Mark fields with `#[Encrypted]` attribute (recommended)
- **YAML-based configuration** - Alternative configuration via `config/packages/field_encryption.yaml`
- **Per-entity key derivation** - Uses entity ID + master key for unique encryption keys
- **Configurable ID property** - Support for entities with integer IDs that have a separate ULID/UUID property
- **Searchable hash support** - Optional SHA-256 hash for field searching
- **Console key generator** - Secure key generation command

## Requirements

- PHP 8.2+
- Symfony 7.0+
- Doctrine ORM 3.0+

## Installation

### Via Composer (Private Git Repository)

Add the Gitea repository to your project's `composer.json`:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://gitea.caeligo.com/CAELIGO/FieldEncryptionBundle.git"
        }
    ],
    "require": {
        "caeligo/field-encryption-bundle": "^1.0"
    }
}
```

Then run:

```bash
composer update caeligo/field-encryption-bundle
```

> **Note:** You need access to the private repository. Configure your credentials via:
> - SSH key authentication, or
> - HTTPS with token: `composer config --global http-basic.gitea.caeligo.com <username> <token>`

## Quick Start

### 1. Register the Bundle

In `config/bundles.php`:

```php
return [
    // ... other bundles
    Caeligo\FieldEncryptionBundle\FieldEncryptionBundle::class => ['all' => true],
];
```

### 2. Generate Encryption Key

```bash
php bin/console field-encryption:generate-key --append-to-env
```

### 3. Create Minimal Configuration

Create `config/packages/field_encryption.yaml`:

```yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
```

### 4. Add Attributes to Your Entity

```php
<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Caeligo\FieldEncryptionBundle\Attribute\Encrypted;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedEntity;

#[ORM\Entity]
#[EncryptedEntity]  // Optional: defaults to getId() for key derivation
class User
{
    #[ORM\Id]
    #[ORM\Column(type: 'ulid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: UlidGenerator::class)]
    private ?Ulid $id = null;

    // Encrypted field with hash for searching
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted(hashField: true, hashProperty: 'emailHash')]
    private ?string $email = null;

    #[ORM\Column(type: Types::TEXT, nullable: true, unique: true)]
    private ?string $emailHash = null;

    private ?string $plainEmail = null;  // Transient, auto-populated

    // Encrypted field without hash
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted]
    private ?string $firstName = null;

    private ?string $plainFirstName = null;  // Transient, auto-populated

    // Getters/setters use plain* properties
    public function getEmail(): ?string
    {
        return $this->plainEmail;
    }

    public function setEmail(?string $email): self
    {
        $this->plainEmail = $email;
        return $this;
    }

    public function getFirstName(): ?string
    {
        return $this->plainFirstName;
    }

    public function setFirstName(?string $firstName): self
    {
        $this->plainFirstName = $firstName;
        return $this;
    }
}
```

**That's it!** The bundle automatically encrypts values before saving and decrypts after loading.

## Attribute Reference

### `#[EncryptedEntity]`

Class-level attribute to configure entity-wide encryption settings.

```php
#[EncryptedEntity]  // Uses 'id' property by default
class User { ... }
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `idProperty` | string | `'id'` | Property name containing the ULID/UUID for key derivation |

### `#[Encrypted]`

Property-level attribute to mark a field for encryption.

```php
#[Encrypted(
    encryptedProperty: 'email',      // Optional: defaults to property name
    plainProperty: 'plainEmail',     // Optional: defaults to 'plain' + PropertyName
    hashField: true,                 // Optional: create searchable hash
    hashProperty: 'emailHash'        // Optional: property for the hash
)]
private ?string $email = null;
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `encryptedProperty` | string\|null | Same as property name | DB column storing encrypted value |
| `plainProperty` | string\|null | `'plain' + ucfirst(name)` | Transient property for decrypted value |
| `hashField` | bool | `false` | Whether to compute SHA-256 hash |
| `hashProperty` | string\|null | `name + 'Hash'` | Property storing the hash |

## Entity Structure

For each encrypted field, your entity needs:

| Component | ORM Mapping | Description |
|-----------|-------------|-------------|
| Encrypted property | `@Column` | Stores encrypted data in database |
| Plain property | None (transient) | Used by your application code |
| Hash property (optional) | `@Column` | SHA-256 hash for searching |

### Naming Conventions

If you follow these conventions, you can use `#[Encrypted]` without parameters:

```php
#[ORM\Column(type: Types::TEXT, nullable: true)]
#[Encrypted]  // Uses defaults
private ?string $email = null;          // encryptedProperty: 'email'

private ?string $plainEmail = null;     // plainProperty: 'plainEmail' (auto-detected)

#[ORM\Column(type: Types::TEXT, nullable: true)]
private ?string $emailHash = null;      // hashProperty: 'emailHash' (if hashField: true)
```

### Complete Entity Example

```php
<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Ulid;
use Doctrine\ORM\Mapping\CustomIdGenerator;
use Symfony\Bridge\Doctrine\IdGenerator\UlidGenerator;
use Caeligo\FieldEncryptionBundle\Attribute\Encrypted;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedEntity;

#[ORM\Entity]
#[EncryptedEntity]
class User
{
    #[ORM\Id]
    #[ORM\Column(type: 'ulid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[CustomIdGenerator(class: UlidGenerator::class)]
    private ?Ulid $id = null;

    #[ORM\Column(length: 180, unique: true)]
    private ?string $username = null;

    // ==================== ENCRYPTED: email ====================
    /** @var string|null Encrypted email (persisted) */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted(hashField: true, hashProperty: 'emailHash')]
    private ?string $email = null;

    /** @var string|null Hash for searching (persisted) */
    #[ORM\Column(type: Types::TEXT, nullable: true, unique: true)]
    private ?string $emailHash = null;

    /** @var string|null Plain email (transient - not persisted) */
    private ?string $plainEmail = null;

    // ==================== ENCRYPTED: firstName ====================
    /** @var string|null Encrypted first name (persisted) */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted]
    private ?string $firstName = null;

    /** @var string|null Plain first name (transient - not persisted) */
    private ?string $plainFirstName = null;

    // ==================== ENCRYPTED: lastName ====================
    /** @var string|null Encrypted last name (persisted) */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted]
    private ?string $lastName = null;

    /** @var string|null Plain last name (transient - not persisted) */
    private ?string $plainLastName = null;

    // ==================== ID ====================
    public function getId(): ?Ulid
    {
        return $this->id;
    }

    // ==================== EMAIL ====================
    public function getEmail(): ?string
    {
        return $this->plainEmail;
    }

    public function setEmail(?string $email): self
    {
        $this->plainEmail = $email;
        return $this;
    }

    public function getEmailHash(): ?string
    {
        return $this->emailHash;
    }

    // Internal methods for encryption listener
    public function getEncryptedEmail(): ?string
    {
        return $this->email;
    }

    public function setEncryptedEmail(?string $value): void
    {
        $this->email = $value;
    }

    public function setEmailHash(?string $hash): void
    {
        $this->emailHash = $hash;
    }

    public function getPlainEmail(): ?string
    {
        return $this->plainEmail;
    }

    public function setPlainEmail(?string $value): void
    {
        $this->plainEmail = $value;
    }

    // ==================== FIRST NAME ====================
    public function getFirstName(): ?string
    {
        return $this->plainFirstName;
    }

    public function setFirstName(?string $firstName): self
    {
        $this->plainFirstName = $firstName;
        return $this;
    }

    public function getEncryptedFirstName(): ?string
    {
        return $this->firstName;
    }

    public function setEncryptedFirstName(?string $value): void
    {
        $this->firstName = $value;
    }

    public function getPlainFirstName(): ?string
    {
        return $this->plainFirstName;
    }

    public function setPlainFirstName(?string $value): void
    {
        $this->plainFirstName = $value;
    }

    // ==================== LAST NAME ====================
    public function getLastName(): ?string
    {
        return $this->plainLastName;
    }

    public function setLastName(?string $lastName): self
    {
        $this->plainLastName = $lastName;
        return $this;
    }

    public function getEncryptedLastName(): ?string
    {
        return $this->lastName;
    }

    public function setEncryptedLastName(?string $value): void
    {
        $this->lastName = $value;
    }

    public function getPlainLastName(): ?string
    {
        return $this->plainLastName;
    }

    public function setPlainLastName(?string $value): void
    {
        $this->plainLastName = $value;
    }
}
```

## Entities with Integer IDs

If your entity uses auto-increment integer as primary key, you need a separate ULID/UUID property for key derivation:

```php
#[ORM\Entity]
#[EncryptedEntity(idProperty: 'ulid')]  // Use getUlid() instead of getId()
class Customer
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;              // Integer primary key

    #[ORM\Column(type: 'ulid', unique: true)]
    private ?Ulid $ulid = null;           // ULID for encryption key derivation

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted(hashField: true)]
    private ?string $phone = null;

    private ?string $plainPhone = null;

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $phoneHash = null;

    public function __construct()
    {
        $this->ulid = new Ulid();
    }

    public function getUlid(): ?Ulid
    {
        return $this->ulid;
    }

    // ... other methods
}
```

## Alternative: YAML Configuration

If you prefer YAML over attributes, you can configure everything in `config/packages/field_encryption.yaml`:

```yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
    entities:
        App\Entity\User:
            id_property: id
            fields:
                email:
                    encrypted_property: email
                    plain_property: plainEmail
                    hash_field: true
                    hash_property: emailHash
                firstName:
                    encrypted_property: firstName
                    plain_property: plainFirstName
        App\Entity\Customer:
            id_property: ulid
            fields:
                phone:
                    encrypted_property: phone
                    plain_property: plainPhone
                    hash_field: true
                    hash_property: phoneHash
```

**Note:** Attributes take priority over YAML configuration. You can mix both approaches.

## Console Commands

### Generate Encryption Key

```bash
# Display a new key
php bin/console field-encryption:generate-key

# Output in .env format
php bin/console field-encryption:generate-key --env-format

# Append to .env.local file
php bin/console field-encryption:generate-key --append-to-env
```

## How It Works

1. **On persist/update**: The listener reads the `plain*` property, encrypts it with AES-256-CBC using a derived key, and stores it in the encrypted property
2. **On load**: The listener reads the encrypted property, decrypts it, and populates the `plain*` property
3. **Encryption payload**: Base64-encoded JSON containing IV and encrypted value
4. **Key derivation**: `HMAC-SHA256(entity_ulid, master_key)` ensures unique keys per entity
5. **Hash computation**: `SHA-256(lowercase(trim(value)))` for searchable hash

## Security Considerations

1. **Never commit encryption keys** - Store in `.env.local` or environment variables
2. **Back up your keys** - Losing the key = losing access to encrypted data
3. **Key rotation** - Not currently supported; plan carefully before implementing
4. **Hash for searching** - Use `hashField: true` if you need to search/query encrypted fields
5. **Use ULID/UUID for ID property** - Don't use sequential integers for key derivation

## Configuration Priority

When determining how to encrypt a field, the bundle uses this priority:

1. **Attributes on entity** - Highest priority
2. **YAML configuration** - Fallback
3. **Defaults** - If neither specifies a setting

## License

MIT License

## Author

Bíró Gábor (biga156)

## Repository

- **Private Git**: https://gitea.caeligo.com/CAELIGO/FieldEncryptionBundle
