<?php

declare(strict_types=1);

namespace Biga\FieldEncryptionBundle\Attribute;

use Attribute;

/**
 * Marks an entity class as having encrypted fields.
 *
 * This attribute is optional when using the #[Encrypted] attribute on individual properties,
 * but can be used to explicitly enable encryption processing for an entity and to configure
 * entity-level encryption settings.
 *
 * Usage:
 * ```php
 * #[EncryptedEntity(idMethod: 'getId')]
 * class User {
 *     #[Encrypted]
 *     private ?string $email = null;
 * }
 * ```
 *
 * @author Bíró Gábor (biga156)
 */
#[Attribute(Attribute::TARGET_CLASS)]
class EncryptedEntity
{
    /**
     * @param string $idMethod The method name to get the entity's unique identifier for key derivation.
     *                         Default is 'getId'. The method should return a Ulid, Uuid, or string.
     */
    public function __construct(
        public readonly string $idMethod = 'getId',
    ) {
    }
}
