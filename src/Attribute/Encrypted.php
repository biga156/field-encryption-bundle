<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Attribute;

use Attribute;

/**
 * Marks an entity property for automatic encryption/decryption.
 *
 * When applied to a property, the FieldEncryptionBundle will:
 * - Encrypt the value before persisting to the database
 * - Decrypt the value after loading from the database
 *
 * The property where this attribute is placed stores the encrypted value in the database.
 * A corresponding "plain*" property is used for the decrypted value (transient, not persisted).
 *
 * Usage (simple - property stores encrypted value directly):
 * ```php
 * #[ORM\Column(type: Types::TEXT, nullable: true)]
 * #[Encrypted(hashField: true, hashProperty: 'emailHash')]
 * private ?string $email = null;  // Stores encrypted value
 *
 * private ?string $plainEmail = null;  // Transient, stores decrypted value
 * ```
 *
 * @author Bíró Gábor (biga156)
 */
#[Attribute(Attribute::TARGET_PROPERTY)]
class Encrypted
{
    /**
     * @param string|null $encryptedProperty The property name that stores the encrypted value (database column).
     *                                       If null, defaults to the property name where this attribute is placed.
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
