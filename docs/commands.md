# Console Commands

This document covers all console commands provided by the FieldEncryptionBundle.

## Generate Encryption Key

Generate a cryptographically secure encryption key.

```bash
php bin/console field-encryption:generate-key
```

### Options

| Option | Description |
|--------|-------------|
| `--env-format` | Output in .env format (FIELD_ENCRYPTION_KEY=...) |
| `--append-to-env` | Append the key to .env.local file |

### Examples

```bash
# Display a new key
php bin/console field-encryption:generate-key
# Output: a1b2c3d4e5f6...

# Output in .env format
php bin/console field-encryption:generate-key --env-format
# Output: FIELD_ENCRYPTION_KEY=a1b2c3d4e5f6...

# Append to .env.local file
php bin/console field-encryption:generate-key --append-to-env
# Appends: FIELD_ENCRYPTION_KEY=a1b2c3d4e5f6... to .env.local
```

### Security Notes

- Keys are 64-character hexadecimal strings (256 bits)
- Never commit keys to version control
- Store in `.env.local` or environment variables
- Back up your keys securely - losing them means losing data access

---

## Rotate Encryption Keys

Rotate encryption keys across all encrypted data. Use this when you need to replace your encryption key.

```bash
php bin/console field-encryption:rotate-keys
```

### Options

| Option | Description |
|--------|-------------|
| `--wizard` | Interactive wizard mode (recommended) |
| `--dry-run` | Show what would be rotated without making changes |
| `--entity=CLASS` | Rotate only a specific entity class |
| `--batch-size=N` | Number of entities per batch (default: 50) |
| `--continue` | Continue a previously interrupted rotation |

### Examples

```bash
# Interactive wizard (recommended for first-time use)
php bin/console field-encryption:rotate-keys --wizard

# Dry run to preview changes
php bin/console field-encryption:rotate-keys --dry-run

# Rotate specific entity only
php bin/console field-encryption:rotate-keys --entity="App\Entity\Document"

# Continue interrupted rotation
php bin/console field-encryption:rotate-keys --continue

# Custom batch size for memory optimization
php bin/console field-encryption:rotate-keys --batch-size=100
```

### Wizard Mode

The `--wizard` flag provides an interactive experience:

1. **Prerequisites check**: Verifies configuration is correct
2. **Progress display**: Shows real-time rotation progress
3. **Confirmation prompts**: Asks before making changes
4. **Resume capability**: Can continue if interrupted

### Before Rotating Keys

1. **Generate a new key**:
   ```bash
   php bin/console field-encryption:generate-key --env-format
   ```

2. **Update configuration**:
   ```yaml
   # config/packages/field_encryption.yaml
   field_encryption:
       encryption_key: '%env(FIELD_ENCRYPTION_KEY_V2)%'  # New key
       key_version: 2
       previous_keys:
           - version: 1
             key: '%env(FIELD_ENCRYPTION_KEY_V1)%'      # Old key
   ```

3. **Run the rotation**:
   ```bash
   php bin/console field-encryption:rotate-keys --wizard
   ```

### Progress Tracking

Rotation progress is saved to `var/field_encryption_rotation_progress.json`. This allows:

- Resuming interrupted rotations
- Tracking which entities have been processed
- Auditing rotation history

---

## Encrypt Existing Data

Encrypt data that was stored before encryption was enabled, or migrate unencrypted data to encrypted format.

```bash
php bin/console field-encryption:encrypt-existing
```

### Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Show what would be encrypted without making changes |
| `--entity=CLASS` | Process only a specific entity class |
| `--batch-size=N` | Number of entities per batch (default: 50) |
| `--force` | Skip confirmation prompts |

### Examples

```bash
# Preview what will be encrypted
php bin/console field-encryption:encrypt-existing --dry-run

# Encrypt all unencrypted data
php bin/console field-encryption:encrypt-existing

# Encrypt specific entity
php bin/console field-encryption:encrypt-existing --entity="App\Entity\User"

# Skip confirmation (for automation)
php bin/console field-encryption:encrypt-existing --force
```

### Use Cases

1. **Initial migration**: You've added encryption to existing entities with data
2. **New fields**: You've added new encrypted fields to existing entities
3. **Data import**: You've imported unencrypted data that needs encryption

### How It Works

1. Scans for entities with encrypted field attributes
2. Finds records where encrypted fields are empty but plain fields have data
3. Encrypts the plain values and stores in encrypted fields
4. Computes hashes if `hashField: true`

---

## Command Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Interrupted (can be resumed) |

---

## Automation & CI/CD

### Running in Non-Interactive Mode

```bash
# Key rotation with no prompts
php bin/console field-encryption:rotate-keys --no-interaction --batch-size=100

# Encrypt existing with force flag
php bin/console field-encryption:encrypt-existing --force
```

### Checking Rotation Status

```bash
# Check if rotation is needed (dry-run returns count)
php bin/console field-encryption:rotate-keys --dry-run 2>&1 | grep "entities need"
```

### Logging

Enable logging to track encryption operations:

```yaml
field_encryption:
    logging:
        enabled: true
        channel: 'security'
        level: 'info'
```

Logs are written to the configured Monolog channel.
