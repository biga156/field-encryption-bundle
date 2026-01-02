# Configuration Reference

This document provides a complete reference for all configuration options.

## Full Configuration Example

```yaml
# config/packages/field_encryption.yaml
field_encryption:
    # Required: The encryption key (64-character hex string)
    encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
    
    # Optional: Separate pepper for hash operations (better key separation)
    hash_pepper: '%env(FIELD_ENCRYPTION_HASH_PEPPER)%'
    
    # Key version for rotation support (default: 1)
    key_version: 1
    
    # Previous keys for rotation (optional)
    previous_keys:
        - version: 1
          key: '%env(FIELD_ENCRYPTION_KEY_V1)%'
    
    # Binary file encryption settings
    file_encryption:
        max_size: 5242880      # 5MB default, max 50MB
        chunk_size: 163840     # 160KB default
        compression: false     # Default compression setting
    
    # Logging configuration
    logging:
        enabled: true
        channel: 'security'    # Monolog channel
        level: 'info'          # Log level
    
    # YAML-based entity configuration (alternative to attributes)
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
```

## Configuration Options

### `encryption_key`

**Required** | Type: `string`

The master encryption key. Must be a 64-character hexadecimal string (256 bits).

```yaml
encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
```

Generate with:
```bash
php bin/console field-encryption:generate-key
```

### `hash_pepper`

Type: `string` | Default: `null` (uses encryption_key)

Optional separate key for hash operations. Provides better key separation - if this pepper is ever compromised, it only affects hash verification, not decryption.

```yaml
hash_pepper: '%env(FIELD_ENCRYPTION_HASH_PEPPER)%'
```

**Security note:** Using a separate pepper means that even if someone obtains the encryption key, they cannot verify hashes without also obtaining the pepper.

### `key_version`

Type: `integer` | Default: `1`

The version number of the current encryption key. Increment when rotating keys.

```yaml
key_version: 2
```

### `previous_keys`

Type: `array` | Default: `[]`

List of previous encryption keys for backward compatibility during key rotation.

```yaml
previous_keys:
    - version: 1
      key: '%env(FIELD_ENCRYPTION_KEY_V1)%'
    - version: 2
      key: '%env(FIELD_ENCRYPTION_KEY_V2)%'
```

### `file_encryption`

Settings for binary file encryption.

#### `file_encryption.max_size`

Type: `integer` | Default: `5242880` (5MB) | Max: `52428800` (50MB)

Maximum file size in bytes.

```yaml
file_encryption:
    max_size: 10485760  # 10MB
```

#### `file_encryption.chunk_size`

Type: `integer` | Default: `163840` (160KB)

Chunk size for processing large files.

```yaml
file_encryption:
    chunk_size: 262144  # 256KB
```

#### `file_encryption.compression`

Type: `boolean` | Default: `false`

Whether to gzip compress files before encryption by default.

```yaml
file_encryption:
    compression: true
```

### `logging`

Settings for encryption operation logging.

#### `logging.enabled`

Type: `boolean` | Default: `false`

Enable logging of encryption/decryption operations.

```yaml
logging:
    enabled: true
```

#### `logging.channel`

Type: `string` | Default: `'security'`

Monolog channel for log messages.

```yaml
logging:
    channel: 'encryption'
```

#### `logging.level`

Type: `string` | Default: `'info'`

Log level. Options: `debug`, `info`, `notice`, `warning`, `error`

```yaml
logging:
    level: 'debug'
```

### `entities`

YAML-based entity field configuration. Alternative to using attributes.

```yaml
entities:
    App\Entity\User:
        id_property: id          # Property for key derivation
        fields:
            email:
                encrypted_property: email
                plain_property: plainEmail
                hash_field: true
                hash_property: emailHash
```

#### Entity Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `id_property` | string | `'id'` | Property name for key derivation |
| `fields` | array | `[]` | Field configurations |

#### Field Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `encrypted_property` | string | field name | Database column name |
| `plain_property` | string | `'plain' + Name` | Transient property name |
| `hash_field` | bool | `false` | Create searchable hash |
| `hash_property` | string | `name + 'Hash'` | Hash storage property |

## Environment Variables

### Required

```bash
# .env.local
FIELD_ENCRYPTION_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
```

### For Key Rotation

```bash
# .env.local
FIELD_ENCRYPTION_KEY_V1=old_key_here
FIELD_ENCRYPTION_KEY_V2=current_key_here
```

## Configuration Priority

When determining field encryption settings, the bundle uses this priority:

1. **Attributes on entity** - Highest priority
2. **YAML configuration** - Fallback
3. **Bundle defaults** - If neither specifies a setting

This allows mixing approaches:

```php
// Attribute overrides YAML config
#[Encrypted(hashField: true)]  // This takes priority
private ?string $email = null;
```

## Minimal Configuration

The absolute minimum configuration:

```yaml
# config/packages/field_encryption.yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
```

Everything else has sensible defaults.

## Development vs Production

### Development

```yaml
# config/packages/dev/field_encryption.yaml
field_encryption:
    logging:
        enabled: true
        level: 'debug'
```

### Production

```yaml
# config/packages/prod/field_encryption.yaml
field_encryption:
    logging:
        enabled: true
        level: 'warning'  # Only log issues
```

## Validation

The bundle validates configuration on container compilation:

- `encryption_key` must be exactly 64 hex characters
- `key_version` must be a positive integer
- `max_size` cannot exceed 50MB
- Referenced properties in `previous_keys` must exist

Invalid configuration will throw a clear exception during cache warmup.
