<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\DependencyInjection;

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
