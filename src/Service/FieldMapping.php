<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Service;

/**
 * Represents the mapping configuration for a single encrypted field.
 *
 * @author Bíró Gábor (biga156)
 */
class FieldMapping
{
    /**
     * @param string      $sourceProperty    The property name that holds the plain value (used in forms/getters)
     * @param string      $encryptedProperty The property name that stores the encrypted value (database column)
     * @param string      $plainProperty     The property name that stores the decrypted value (transient)
     * @param bool        $hashField         Whether to also create a hash of the value
     * @param string|null $hashProperty      The property name for the hash (if hashField is true)
     * @param string      $idMethod          The method name to get the entity's unique identifier
     */
    public function __construct(
        public readonly string $sourceProperty,
        public readonly string $encryptedProperty,
        public readonly string $plainProperty,
        public readonly bool $hashField = false,
        public readonly ?string $hashProperty = null,
        public string $idMethod = 'getId',
    ) {
    }
}
