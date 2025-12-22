# FieldEncryptionBundle

A reusable Symfony bundle for transparent Doctrine entity field encryption using AES-256-CBC.

## Features

- **Automatic encryption/decryption** - Fields are encrypted before persist/update and decrypted after load
- **Attribute-based configuration** - Mark fields with `#[Encrypted]` attribute
- **YAML-based configuration** - Configure entity fields via `config/packages/field_encryption.yaml`
- **Per-entity key derivation** - Uses entity ID + master key for unique encryption keys
- **Searchable hash support** - Optional SHA-256 hash for field searching
- **Console key generator** - Secure key generation command

## Requirements

- PHP 8.2+
- Symfony 7.0+
- Doctrine ORM 3.0+

## Installation

### Via Composer (Local Path - Development)

Add the repository to your project's `composer.json`:

```json
{
    "repositories": [
        {
            "type": "path",
            "url": "../field-encryption-bundle"
        }
    ],
    "require": {
        "biga/field-encryption-bundle": "@dev"
    }
}
```

Then run:

```bash
composer update biga/field-encryption-bundle
```

### Via Composer (Packagist - Production)

Once published to Packagist:

```bash
composer require biga/field-encryption-bundle
```

### Manual Installation

1. Copy the bundle to your project (e.g., `lib/field-encryption-bundle`)
2. Add to `composer.json`:

```json
{
    "autoload": {
        "psr-4": {
            "Biga\\FieldEncryptionBundle\\": "lib/field-encryption-bundle/src/"
        }
    }
}
```

3. Run `composer dump-autoload`

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
            email:
                encrypted_property: email           # Database column for encrypted value
                plain_property: plainEmail          # Property for decrypted value (transient)
                hash_field: true                    # Create searchable hash
                hash_property: emailHash            # Property for the hash
        App\Entity\Customer:
            phone:
                encrypted_property: encryptedPhone
                plain_property: plainPhone
            creditCard:
                encrypted_property: encryptedCreditCard
                hash_field: true
```

### Alternative: Attribute-Based Configuration

You can also use PHP attributes directly on entity properties:

```php
use Biga\FieldEncryptionBundle\Attribute\Encrypted;
use Biga\FieldEncryptionBundle\Attribute\EncryptedEntity;

#[EncryptedEntity(idMethod: 'getId')]
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

Example implementation:

```php
class User
{
    // The actual DB column - stores encrypted data
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $email = null;
    
    // Transient property - the decrypted value for application use
    // NOT persisted - populated by postLoad, read by getEmail()
    private ?string $plainEmail = null;
    
    // Optional: for searching and unique constraints
    #[ORM\Column(type: Types::TEXT, nullable: true, unique: true)]
    private ?string $emailHash = null;
    
    // The getter returns plain (decrypted) value
    public function getEmail(): ?string
    {
        return $this->plainEmail;
    }
    
    // The setter sets plain value (which will be encrypted on persist)
    public function setEmail(?string $email): self
    {
        $this->plainEmail = $email;
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

## How It Works

1. **On persist/update**: The listener reads the source property value, encrypts it with AES-256-CBC using a key derived from (entity ID + master key), and stores it in the encrypted property
2. **On load**: The listener reads the encrypted property, decrypts it, and populates the plain property
3. **Encryption payload**: Base64-encoded JSON containing IV and encrypted value

## License

MIT License

## Author

Bíró Gábor (biga156)
