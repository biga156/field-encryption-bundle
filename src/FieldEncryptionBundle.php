<?php

declare(strict_types=1);

namespace Biga\FieldEncryptionBundle;

use Biga\FieldEncryptionBundle\DependencyInjection\FieldEncryptionExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

/**
 * FieldEncryptionBundle - A reusable Symfony bundle for transparent entity field encryption.
 *
 * This bundle provides automatic AES-256-CBC encryption/decryption for Doctrine entity properties.
 * Fields can be marked for encryption using the #[Encrypted] attribute, and the bundle handles
 * encryption on persist/update and decryption on load transparently.
 *
 * Features:
 * - Attribute-based field marking (#[Encrypted])
 * - YAML-based configuration for entity/field mappings
 * - Per-entity unique key derivation using entity ID
 * - Automatic change set recomputation for Doctrine
 * - Console command for encryption key generation
 *
 * @author Bíró Gábor (biga156)
 */
class FieldEncryptionBundle extends AbstractBundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new FieldEncryptionExtension();
    }
}
