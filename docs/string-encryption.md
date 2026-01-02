# String Field Encryption

This document covers the encryption of text/string fields in Doctrine entities using AES-256-CBC.

## Overview

String field encryption is designed for sensitive text data like emails, names, phone numbers, etc. The bundle uses:

- **Algorithm**: AES-256-CBC
- **Key derivation**: HKDF-SHA256 for purpose separation, then HMAC-SHA256(entity_id, derived_key)
- **Hash algorithm**: HMAC-SHA256 with dedicated hash key (derived via HKDF)
- **Storage format**: Base64-encoded JSON containing IV and encrypted value

## Security Features

### HKDF Key Derivation

The bundle uses HKDF (HMAC-based Key Derivation Function) to derive separate keys for different purposes:

```
Master Key
    ├── HKDF("field-encryption-v1") → Encryption Purpose Key
    │       └── HMAC(entity_id) → Entity-specific Encryption Key
    │
    └── HKDF("field-hashing-v1") → Hashing Purpose Key
            └── HMAC(value) → Searchable Hash
```

This provides **cryptographic separation** - compromising one derived key doesn't compromise others.

### Timing-Safe Hash Comparison

The bundle provides timing-safe hash comparison to prevent timing attacks:

```php
// In your code
$encryptionService = $this->container->get(FieldEncryptionService::class);

// Verify a value against a stored hash (timing-safe)
if ($encryptionService->verifyHash($userInput, $storedHash)) {
    // Value matches
}

// Or compare two hashes directly
if ($encryptionService->hashEquals($hash1, $hash2)) {
    // Hashes match
}
```

### Plain vs Secure Hash

The bundle provides two hashing methods:

| Method | Algorithm | Key Required | Use Case |
|--------|-----------|--------------|----------|
| `hash()` | SHA-256 | No | Backward compatible, existing databases |
| `secureHash()` | HMAC-SHA256 | Yes (derived) | New projects, higher security |

```php
// Plain SHA-256 (default, backward compatible)
$hash = $encryptionService->hash($email);

// HMAC-SHA256 (more secure, requires same key to verify)
$secureHash = $encryptionService->secureHash($email);

// Verification
$encryptionService->verifyHash($email, $hash);           // for hash()
$encryptionService->verifySecureHash($email, $secureHash); // for secureHash()
```

## Basic Usage

### 1. Mark Your Entity

```php
<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Caeligo\FieldEncryptionBundle\Attribute\Encrypted;
use Caeligo\FieldEncryptionBundle\Attribute\EncryptedEntity;

#[ORM\Entity]
#[EncryptedEntity]
class User
{
    #[ORM\Id]
    #[ORM\Column(type: 'ulid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: UlidGenerator::class)]
    private ?Ulid $id = null;

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

### 2. Entity Structure

For each encrypted field, your entity needs:

| Component | ORM Mapping | Description |
|-----------|-------------|-------------|
| Encrypted property | `@Column` | Stores encrypted data in database |
| Plain property | None (transient) | Used by your application code |
| Hash property (optional) | `@Column` | SHA-256 hash for searching |

## Attribute Reference

### `#[EncryptedEntity]`

Class-level attribute to configure entity-wide encryption settings.

```php
#[EncryptedEntity]  // Uses 'id' property by default
class User { ... }

#[EncryptedEntity(idProperty: 'ulid')]  // Custom ID property
class Customer { ... }
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

## Naming Conventions

If you follow these conventions, you can use `#[Encrypted]` without parameters:

```php
#[ORM\Column(type: Types::TEXT, nullable: true)]
#[Encrypted]  // Uses defaults
private ?string $email = null;          // encryptedProperty: 'email'

private ?string $plainEmail = null;     // plainProperty: 'plainEmail' (auto-detected)

#[ORM\Column(type: Types::TEXT, nullable: true)]
private ?string $emailHash = null;      // hashProperty: 'emailHash' (if hashField: true)
```

## Searchable Hash

When `hashField: true` is set, the bundle creates a SHA-256 hash of the normalized value (lowercase, trimmed). This allows you to:

- Search for exact matches without decrypting
- Create unique constraints on encrypted fields
- Build indexes for faster lookups

```php
// In your repository
public function findByEmail(string $email): ?User
{
    $hash = hash('sha256', mb_strtolower(trim($email)));
    
    return $this->findOneBy(['emailHash' => $hash]);
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
}
```

## Complete Entity Example

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
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted(hashField: true, hashProperty: 'emailHash')]
    private ?string $email = null;

    #[ORM\Column(type: Types::TEXT, nullable: true, unique: true)]
    private ?string $emailHash = null;

    private ?string $plainEmail = null;

    // ==================== ENCRYPTED: firstName ====================
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    #[Encrypted]
    private ?string $firstName = null;

    private ?string $plainFirstName = null;

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
}
```

## How It Works

1. **On persist/update**: The listener reads the `plain*` property, encrypts it with AES-256-CBC using a derived key, and stores it in the encrypted property
2. **On load**: The listener reads the encrypted property, decrypts it, and populates the `plain*` property
3. **Encryption payload**: Base64-encoded JSON containing IV and encrypted value:
   ```json
   {"iv": "base64...", "value": "encrypted..."}
   ```
4. **Key derivation**: `HMAC-SHA256(entity_ulid, master_key)` ensures unique keys per entity
5. **Hash computation**: `SHA-256(lowercase(trim(value)))` for searchable hash
