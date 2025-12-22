<?php

declare(strict_types=1);

namespace Biga\FieldEncryptionBundle\Attribute;

use Attribute;

/**
 * Marks an entity property for automatic encryption/decryption.
 *
 * When applied to a property, the FieldEncryptionBundle will:
 * - Encrypt the value before persisting to the database
 * - Decrypt the value after loading from the database
 *
 * The property requires a corresponding "encrypted" storage field in the database
 * and optionally a "plain" property for the decrypted value.
 *
 * Usage:
 * ```php
 * #[Encrypted(encryptedProperty: 'encryptedEmail', plainProperty: 'plainEmail')]
 * private ?string $email = null;
 * ```
 *
 * Or with YAML configuration, the attribute can be used without parameters:
 * ```php
 * #[Encrypted]
 * private ?string $email = null;
 * ```
 *
 * @author Bíró Gábor (biga156)
 */
#[Attribute(Attribute::TARGET_PROPERTY)]
class Encrypted
{
    /**
     * @param string|null $encryptedProperty The property name that stores the encrypted value (database column).
     *                                       If null, defaults to 'encrypted' + ucfirst(propertyName).
     * @param string|null $plainProperty     The property name that stores the decrypted value (not persisted).
     *                                       If null, defaults to 'plain' + ucfirst(propertyName).
     * @param bool        $hashField         Whether to also create a hash of the value for searchability.
     * @param string|null $hashProperty      The property name that stores the hash (for unique constraints, etc.).
     *                                       If null and hashField is true, defaults to propertyName + 'Hash'.
     */
    public function __construct(
        public readonly ?string $encryptedProperty = null,
        public readonly ?string $plainProperty = null,
        public readonly bool $hashField = false,
        public readonly ?string $hashProperty = null,
    ) {
    }
}
