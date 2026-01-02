<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\DependencyInjection;

use Caeligo\FieldEncryptionBundle\Service\BinaryEncryptionService;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Configuration definition for the FieldEncryptionBundle.
 *
 * Example configuration:
 *
 * ```yaml
 * field_encryption:
 *     encryption_key: '%env(FIELD_ENCRYPTION_KEY)%'
 *     key_version: 1
 *     previous_keys:
 *         1: '%env(FIELD_ENCRYPTION_KEY_V1)%'
 *
 *     # File encryption settings
 *     file_encryption:
 *         max_size: 5242880        # 5MB default
 *         chunk_size: 163840       # 160KB default
 *         compression: false       # gzip compression before encryption
 *
 *     # Logging settings
 *     logging:
 *         enabled: false
 *         channel: 'field_encryption'
 *         level: 'info'
 *
 *     entities:
 *         App\Entity\User:
 *             id_property: id              # Optional: property used for key derivation (default: 'id')
 *             fields:
 *                 email:
 *                     encrypted_property: email
 *                     plain_property: plainEmail
 *                     hash_field: true
 *                     hash_property: emailHash
 *         App\Entity\Customer:
 *             id_property: ulid            # Use 'ulid' property instead of 'id' for entities with integer IDs
 *             fields:
 *                 phone:
 *                     encrypted_property: encryptedPhone
 *                     plain_property: plainPhone
 * ```
 *
 * The `id_property` is used to specify which property contains the ULID/UUID
 * used for key derivation during encryption. This is useful when:
 * - The entity uses an integer primary key but has a separate ULID/UUID property
 * - The ID property has a different name (e.g., 'ulid', 'uuid', 'publicId')
 *
 * @author Bíró Gábor (biga156)
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('field_encryption');

        $treeBuilder->getRootNode()
            ->children()
                ->scalarNode('encryption_key')
                    ->isRequired()
                    ->cannotBeEmpty()
                    ->info('The encryption key. Should be set from an environment variable, e.g., %env(FIELD_ENCRYPTION_KEY)%')
                ->end()
                ->scalarNode('hash_pepper')
                    ->defaultNull()
                    ->info('Optional separate key for hashing operations. If not set, encryption_key is used. Use %env(FIELD_ENCRYPTION_HASH_PEPPER)% for better key separation.')
                ->end()
                ->integerNode('key_version')
                    ->defaultValue(1)
                    ->min(1)
                    ->info('The version number of the current encryption key. Increment when rotating keys.')
                ->end()
                ->arrayNode('previous_keys')
                    ->info('Previous encryption keys indexed by version number, for key rotation support.')
                    ->useAttributeAsKey('version')
                    ->scalarPrototype()->end()
                ->end()
                ->arrayNode('file_encryption')
                    ->addDefaultsIfNotSet()
                    ->info('Configuration for binary file encryption')
                    ->children()
                        ->integerNode('max_size')
                            ->defaultValue(BinaryEncryptionService::DEFAULT_MAX_SIZE)
                            ->min(1024)
                            ->max(BinaryEncryptionService::MAX_ALLOWED_SIZE)
                            ->info('Maximum file size in bytes (default: 5MB, max: 50MB)')
                        ->end()
                        ->integerNode('chunk_size')
                            ->defaultValue(BinaryEncryptionService::DEFAULT_CHUNK_SIZE)
                            ->min(16384)
                            ->info('Chunk size for processing large files (default: 160KB)')
                        ->end()
                        ->booleanNode('compression')
                            ->defaultFalse()
                            ->info('Whether to gzip compress files before encryption')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('logging')
                    ->addDefaultsIfNotSet()
                    ->info('Logging configuration for encryption operations')
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultFalse()
                            ->info('Enable logging of encryption/decryption operations')
                        ->end()
                        ->scalarNode('channel')
                            ->defaultValue('field_encryption')
                            ->info('Monolog channel name for encryption logs')
                        ->end()
                        ->enumNode('level')
                            ->values(['debug', 'info', 'notice', 'warning', 'error'])
                            ->defaultValue('info')
                            ->info('Minimum log level')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('entities')
                    ->info('Entity field encryption configuration')
                    ->useAttributeAsKey('class')
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode('id_property')
                                ->defaultValue('id')
                                ->info('The property name containing the ULID/UUID used for key derivation. Defaults to "id".')
                            ->end()
                            ->arrayNode('fields')
                                ->info('Fields to encrypt for this entity')
                                ->useAttributeAsKey('property')
                                ->arrayPrototype()
                                    ->children()
                                        ->scalarNode('encrypted_property')
                                            ->defaultNull()
                                            ->info('The property name that stores the encrypted value. Defaults to "encrypted" + PropertyName.')
                                        ->end()
                                        ->scalarNode('plain_property')
                                            ->defaultNull()
                                            ->info('The property name that stores the decrypted value. Defaults to "plain" + PropertyName.')
                                        ->end()
                                        ->booleanNode('hash_field')
                                            ->defaultFalse()
                                            ->info('Whether to create a searchable hash of the value.')
                                        ->end()
                                        ->scalarNode('hash_property')
                                            ->defaultNull()
                                            ->info('The property name for the hash. Defaults to PropertyName + "Hash" if hash_field is true.')
                                        ->end()
                                    ->end()
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}

