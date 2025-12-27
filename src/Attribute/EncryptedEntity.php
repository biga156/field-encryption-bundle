<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Attribute;

use Attribute;

/**
 * Marks an entity class as having encrypted fields and configures encryption key derivation.
 *
 * The encryption key for each entity instance is derived from:
 * - The master key (from FIELD_ENCRYPTION_KEY environment variable)
 * - The entity's unique identifier (ULID/UUID) specified by idProperty
 *
 * This ensures each entity has a unique encryption key, providing better security
 * than using a single key for all data.
 *
 * Usage with ULID as primary key (most common):
 * ```php
 * #[EncryptedEntity]  // Uses 'id' property by default
 * class User {
 *     #[ORM\Id]
 *     #[ORM\Column(type: 'ulid')]
 *     private ?Ulid $id = null;
 *
 *     #[Encrypted]
 *     private ?string $email = null;
 * }
 * ```
 *
 * Usage with integer ID and separate ULID property:
 * ```php
 * #[EncryptedEntity(idProperty: 'ulid')]
 * class Customer {
 *     #[ORM\Id]
 *     #[ORM\GeneratedValue]
 *     private ?int $id = null;
 *
 *     #[ORM\Column(type: 'ulid')]
 *     private ?Ulid $ulid = null;  // Used for key derivation
 *
 *     #[Encrypted]
 *     private ?string $phone = null;
 * }
 * ```
 *
 * @author Bíró Gábor (biga156)
 */
#[Attribute(Attribute::TARGET_CLASS)]
class EncryptedEntity
{
    /**
     * The getter method name, derived from idProperty.
     */
    public readonly string $idMethod;

    /**
     * @param string $idProperty The property name containing the ULID/UUID for key derivation.
     *                           Default is 'id'. The getter method will be 'get' + ucfirst(idProperty).
     *                           Example: 'ulid' -> getUlid(), 'publicId' -> getPublicId()
     */
    public function __construct(
        public readonly string $idProperty = 'id',
    ) {
        $this->idMethod = 'get' . ucfirst($this->idProperty);
    }
}
