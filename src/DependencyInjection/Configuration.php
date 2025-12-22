<?php

declare(strict_types=1);

namespace Biga\FieldEncryptionBundle\DependencyInjection;

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
 *             email:
 *                 encrypted_property: encryptedEmail
 *                 plain_property: plainEmail
 *                 hash_field: true
 *                 hash_property: emailHash
 *         App\Entity\Customer:
 *             phone:
 *                 encrypted_property: encryptedPhone
 *                 plain_property: plainPhone
 *             address:
 *                 encrypted_property: encryptedAddress
 * ```
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
            ->end();

        return $treeBuilder;
    }
}
