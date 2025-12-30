# Key Rotation

This document covers the key rotation process for safely replacing encryption keys.

## Overview

Key rotation is the process of replacing your encryption key while maintaining access to existing encrypted data. This is necessary when:

- Security policy requires periodic key rotation
- A key may have been compromised
- Compliance requirements mandate key changes
- Staff with key access have left the organization

## How It Works

1. **Multi-key support**: The bundle can decrypt data encrypted with any configured key version
2. **Version tracking**: Each encrypted payload includes the key version used
3. **Gradual migration**: Data is re-encrypted with the new key during rotation
4. **Backward compatibility**: Old keys remain available until rotation is complete

## Configuration

### Single Key (Default)

```yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
    key_version: 1
```

### Multiple Keys (During Rotation)

```yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY_V2)%'  # Current key
    key_version: 2
    previous_keys:
        - version: 1
          key: '%env(FIELD_ENCRYPTION_KEY_V1)%'      # Previous key
```

### After Rotation Complete

```yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY_V2)%'
    key_version: 2
    # previous_keys removed after confirming all data is migrated
```

## Step-by-Step Rotation Process

### Step 1: Generate New Key

```bash
php bin/console field-encryption:generate-key --env-format
```

Save the output to your environment:
```bash
# .env.local
FIELD_ENCRYPTION_KEY_V1=your_current_key_here
FIELD_ENCRYPTION_KEY_V2=newly_generated_key_here
```

### Step 2: Update Configuration

```yaml
# config/packages/field_encryption.yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY_V2)%'
    key_version: 2
    previous_keys:
        - version: 1
          key: '%env(FIELD_ENCRYPTION_KEY_V1)%'
```

### Step 3: Deploy Configuration

Deploy the updated configuration. At this point:
- New data is encrypted with key version 2
- Existing data can still be decrypted using key version 1
- No data is lost

### Step 4: Run Rotation

```bash
# Recommended: Use wizard mode
php bin/console field-encryption:rotate-keys --wizard

# Or: Dry run first
php bin/console field-encryption:rotate-keys --dry-run

# Then: Execute rotation
php bin/console field-encryption:rotate-keys
```

### Step 5: Verify Completion

```bash
# Check for any remaining old-version data
php bin/console field-encryption:rotate-keys --dry-run
# Should report: "0 entities need key rotation"
```

### Step 6: Remove Old Key

After confirming all data is migrated:

```yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY_V2)%'
    key_version: 2
    # previous_keys removed
```

Remove `FIELD_ENCRYPTION_KEY_V1` from your environment.

## Progress Tracking

### Progress File

Rotation progress is saved to:
```
var/field_encryption_rotation_progress.json
```

Example content:
```json
{
    "started_at": "2024-01-15T10:30:00+00:00",
    "entities": {
        "App\\Entity\\User": {
            "total": 1000,
            "processed": 750,
            "last_id": "01HQ1234567890ABCDEFGH"
        },
        "App\\Entity\\Document": {
            "total": 500,
            "processed": 500,
            "completed_at": "2024-01-15T10:45:00+00:00"
        }
    }
}
```

### Resuming Interrupted Rotation

If rotation is interrupted (server restart, timeout, etc.):

```bash
php bin/console field-encryption:rotate-keys --continue
```

The command will resume from the last processed entity.

## Best Practices

### 1. Always Test First

```bash
# Test in staging/development first
php bin/console field-encryption:rotate-keys --dry-run
```

### 2. Backup Before Rotation

```bash
# Database backup before rotation
mysqldump -u user -p database > backup_before_rotation.sql
```

### 3. Schedule During Low Traffic

Key rotation is I/O intensive. Schedule during maintenance windows.

### 4. Monitor Progress

Watch the progress output or check the progress file:
```bash
watch cat var/field_encryption_rotation_progress.json
```

### 5. Keep Old Keys Until Verified

Don't remove `previous_keys` until you've verified:
- Rotation completed successfully
- Application is working correctly
- No rollback is needed

### 6. Batch Size Optimization

For large datasets, adjust batch size:
```bash
# Smaller batches = less memory, more DB queries
php bin/console field-encryption:rotate-keys --batch-size=25

# Larger batches = more memory, fewer DB queries
php bin/console field-encryption:rotate-keys --batch-size=200
```

## Multiple Previous Keys

For environments with multiple key versions:

```yaml
field_encryption:
    encryption_key: '%env(FIELD_ENCRYPTION_KEY_V3)%'
    key_version: 3
    previous_keys:
        - version: 1
          key: '%env(FIELD_ENCRYPTION_KEY_V1)%'
        - version: 2
          key: '%env(FIELD_ENCRYPTION_KEY_V2)%'
```

The bundle will automatically use the correct key based on the version stored in each encrypted payload.

## Key Version in Payload

### String Fields (AES-256-CBC)

Currently, string fields don't include key version in the payload. Re-encryption happens when data is loaded and saved.

### Binary Fields (AES-256-GCM)

Binary fields include key version in the payload header:

```
[magic: "CEFF"]
[format_version: 1]
[key_version: N]      <-- Key version stored here
[flags: ...]
...
```

This allows:
- Identifying which key version was used
- Selecting the correct decryption key
- Tracking rotation progress

## Emergency Key Rotation

If a key is compromised:

1. **Generate new key immediately**:
   ```bash
   php bin/console field-encryption:generate-key --append-to-env
   ```

2. **Update configuration** with new key and increment version

3. **Deploy immediately**

4. **Run rotation with priority**:
   ```bash
   php bin/console field-encryption:rotate-keys --batch-size=200
   ```

5. **Remove compromised key** from all environments

## Troubleshooting

### "Unknown key version" Error

The data was encrypted with a key version not in your configuration.

**Solution**: Add the missing key to `previous_keys`.

### Rotation Takes Too Long

Large datasets may take hours.

**Solutions**:
- Increase batch size
- Run during off-peak hours
- Consider running in parallel for different entities

### Out of Memory

**Solution**: Decrease batch size:
```bash
php bin/console field-encryption:rotate-keys --batch-size=10
```

### Rotation Interrupted

**Solution**: Resume with:
```bash
php bin/console field-encryption:rotate-keys --continue
```
