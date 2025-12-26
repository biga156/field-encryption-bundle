# FieldEncryptionBundle

A reusable Symfony bundle for transparent Doctrine entity field encryption using AES-256-CBC.

## Features

- **Automatic encryption/decryption** - Fields are encrypted before persist/update and decrypted after load
- **Attribute-based configuration** - Mark fields with `#[Encrypted]` attribute
- **YAML-based configuration** - Configure entity fields via `config/packages/field_encryption.yaml`
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
            "url": "https://gitea.caeligo.com/biga/FieldEncryptionBundle.git"
        }
    ],
    "require": {
        "biga/field-encryption-bundle": "^1.0"
    }
}
```

Then run:

```bash
composer update biga/field-encryption-bundle
```

> **Note:** You need access to the private repository. Configure your credentials via:
> - SSH key authentication, or
> - HTTPS with token: `composer config --global http-basic.gitea.caeligo.com <username> <token>`

### Via Composer (Packagist - Future)

Once published to Packagist, installation will be simplified to:

```bash
composer require biga/field-encryption-bundle
```

### Via Composer (Local Path - Development)

For local development, symlink the bundle:

```json
{
    "repositories": [
        {
            "type": "path",
            "url": "../field-encryption-bundle",
            "options": {
                "symlink": true
            }
        }
    ],
    "require": {
        "biga/field-encryption-bundle": "@dev"
    }
}
```

## About the Namespace

The `Biga\FieldEncryptionBundle` namespace follows Composer/PSR-4 conventions where `Biga` is the **vendor name** (publisher/author identifier), similar to how Symfony uses `Symfony\`, Doctrine uses `Doctrine\`, etc.

This namespace works regardless of where the package is installed - Composer's autoloader handles the mapping between namespace and filesystem location automatically. You can install this bundle in any project, in any directory structure.

## Configuration

### 1. Register the Bundle

In `config/bundles.php`:

```php
return [
    // ... other bundles
    Biga\FieldEncryptionBundle\FieldEncryptionBundle::class => ['all' => true],
];
```

### 2. Generate Encryption Key

```bash
php bin/console field-encryption:generate-key --append-to-env
```

Or manually add to `.env.local`:

```dotenv
FIELD_ENCRYPTION_KEY=your_64_character_hex_key_here
```

### 3. Configure Encrypted Fields

Create `config/packages/field_encryption.yaml`:

```yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
    entities:
        App\Entity\User:
            id_property: id                         # Property for key derivation (default: 'id')
            fields:
                email:
                    encrypted_property: email       # Database column for encrypted value
                    plain_property: plainEmail      # Property for decrypted value (transient)
                    hash_field: true                # Create searchable hash
                    hash_property: emailHash        # Property for the hash
        App\Entity\Customer:
            id_property: ulid                       # Use 'ulid' property for entities with integer IDs
            fields:
                phone:
                    encrypted_property: encryptedPhone
                    plain_property: plainPhone
                creditCard:
                    encrypted_property: encryptedCreditCard
                    hash_field: true
```

### The `id_property` Option

The `id_property` setting specifies which property contains the ULID/UUID used for encryption key derivation. This is essential for per-entity unique encryption.

| Scenario | Configuration |
|----------|--------------|
| Entity uses ULID as primary key | `id_property: id` (default) |
| Entity has integer ID + separate `ulid` property | `id_property: ulid` |
| Entity has integer ID + `publicId` (UUID) property | `id_property: publicId` |

**Why is this important?**

The encryption key is derived from: `HMAC-SHA256(entity_id, master_key)`

If your entity uses an auto-increment integer as the primary key, you need a separate ULID/UUID property for key derivation to ensure cryptographic uniqueness. Sequential integers don't provide enough entropy.

Example for an entity with integer ID:

```php
#[ORM\Entity]
class Customer
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;              // Integer primary key
    
    #[ORM\Column(type: 'ulid', unique: true)]
    private ?Ulid $ulid = null;           // ULID for encryption key derivation
    
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $encryptedPhone = null;
    
    private ?string $plainPhone = null;   // Transient
    
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

### Alternative: Attribute-Based Configuration

You can also use PHP attributes directly on entity properties:

```php
use Biga\FieldEncryptionBundle\Attribute\Encrypted;
use Biga\FieldEncryptionBundle\Attribute\EncryptedEntity;

#[EncryptedEntity(idMethod: 'getId')]  // or 'getUlid' for entities with integer IDs
class User
{
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $email = null;  // Stores encrypted value
    
    #[Encrypted(
        encryptedProperty: 'email',
        plainProperty: 'plainEmail',
        hashField: true,
        hashProperty: 'emailHash'
    )]
    private ?string $plainEmail = null;  // Transient, not persisted
    
    #[ORM\Column(type: Types::TEXT, nullable: true, unique: true)]
    private ?string $emailHash = null;  // For searching/uniqueness
}
```

## Entity Structure Requirements

For each encrypted field, your entity needs:

1. **Encrypted property** (persisted) - Stores the AES-256-CBC encrypted value
2. **Plain property** (transient) - Used by application code, not persisted
3. **Hash property** (optional, persisted) - SHA-256 hash for searching
4. **ID property** - ULID/UUID for key derivation (can be the primary key or a separate property)

Example implementation:

```php
class User
{
    #[ORM\Id]
    #[ORM\Column(type: 'ulid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: UlidGenerator::class)]
    private ?Ulid $id = null;
    
    // The actual DB column - stores encrypted data
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $email = null;
    
    // Transient property - the decrypted value for application use
    // NOT persisted - populated by postLoad, read by getEmail()
    private ?string $plainEmail = null;
    
    // Optional: for searching and unique constraints
    #[ORM\Column(type: Types::TEXT, nullable: true, unique: true)]
    private ?string $emailHash = null;
    
    public function getId(): ?Ulid
    {
        return $this->id;
    }
    
    // The getter returns plain (decrypted) value
    public function getEmail(): ?string
    {
        return $this->plainEmail;
    }
    
    // The setter sets plain value (which will be encrypted on persist)
    public function setEmail(?string $email): self
    {
        $this->plainEmail = $email;
        // Optionally compute hash here for validation
        if ($email !== null) {
            $this->emailHash = hash('sha256', mb_strtolower(trim($email)));
        }
        return $this;
    }
    
    // Used by the encryption listener
    public function getEncryptedEmail(): ?string
    {
        return $this->email;
    }
    
    public function setEncryptedEmail(?string $value): void
    {
        $this->email = $value;
    }
}
```

## Configuration Priority

When determining the ID property for key derivation, the bundle uses this priority:

1. **YAML configuration** (`id_property`) - Highest priority
2. **`#[EncryptedEntity]` attribute** (`idMethod` parameter)
3. **Default** `getId` method

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

## Security Considerations

1. **Never commit encryption keys** - Store in `.env.local` or environment variables
2. **Back up your keys** - Losing the key = losing access to encrypted data
3. **Key rotation** - Not currently supported; plan carefully before implementing
4. **Hash for searching** - Use `hash_field: true` if you need to search encrypted fields
5. **Use ULID/UUID for ID property** - Don't use sequential integers for key derivation

## How It Works

1. **On persist/update**: The listener reads the plain property value, encrypts it with AES-256-CBC using a key derived from (entity's `id_property` + master key), and stores it in the encrypted property
2. **On load**: The listener reads the encrypted property, decrypts it, and populates the plain property
3. **Encryption payload**: Base64-encoded JSON containing IV and encrypted value
4. **Key derivation**: `HMAC-SHA256(entity_ulid, master_key)` ensures unique keys per entity

## Upgrading from Previous Versions

If you're upgrading from a version that used the old YAML structure (without `id_property` and `fields`), update your configuration:

**Old format:**
```yaml
field_encryption:
    entities:
        App\Entity\User:
            email:
                encrypted_property: email
                plain_property: plainEmail
```

**New format:**
```yaml
field_encryption:
    entities:
        App\Entity\User:
            id_property: id              # NEW: specify ID property
            fields:                      # NEW: fields are now nested
                email:
                    encrypted_property: email
                    plain_property: plainEmail
```

## License

MIT License

## Author

Bíró Gábor (biga156)

## Repository

- **Private Git**: https://gitea.caeligo.com/biga/FieldEncryptionBundle
- **Packagist**: *(Coming soon)*
