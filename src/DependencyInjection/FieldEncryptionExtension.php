<?php

declare(strict_types=1);

namespace Biga\FieldEncryptionBundle\DependencyInjection;

use Biga\FieldEncryptionBundle\Command\GenerateEncryptionKeyCommand;
use Biga\FieldEncryptionBundle\EventListener\FieldEncryptionListener;
use Biga\FieldEncryptionBundle\Service\FieldEncryptionService;
use Biga\FieldEncryptionBundle\Service\FieldMappingResolver;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Dependency injection extension for the FieldEncryptionBundle.
 *
 * Registers the bundle's services with the Symfony container.
 *
 * @author Bíró Gábor (biga156)
 */
class FieldEncryptionExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config        = $this->processConfiguration($configuration, $configs);

        // Store the encryption key as a container parameter
        $container->setParameter('field_encryption.encryption_key', $config['encryption_key']);

        // Register FieldEncryptionService
        $encryptionServiceDef = new Definition(FieldEncryptionService::class);
        $encryptionServiceDef->setArgument('$encryptionKey', '%field_encryption.encryption_key%');
        $encryptionServiceDef->setPublic(false);
        $container->setDefinition(FieldEncryptionService::class, $encryptionServiceDef);
        $container->setAlias('field_encryption.encryption_service', FieldEncryptionService::class);

        // Register FieldMappingResolver
        $mappingResolverDef = new Definition(FieldMappingResolver::class);
        $mappingResolverDef->setArgument(0, $config['entities'] ?? []);
        $mappingResolverDef->setPublic(false);
        $container->setDefinition(FieldMappingResolver::class, $mappingResolverDef);
        $container->setAlias('field_encryption.mapping_resolver', FieldMappingResolver::class);

        // Register FieldEncryptionListener
        $listenerDef = new Definition(FieldEncryptionListener::class);
        $listenerDef->setArgument(0, new Reference(FieldEncryptionService::class));
        $listenerDef->setArgument(1, new Reference(FieldMappingResolver::class));
        $listenerDef->addTag('doctrine.event_listener', ['event' => 'prePersist']);
        $listenerDef->addTag('doctrine.event_listener', ['event' => 'preUpdate']);
        $listenerDef->addTag('doctrine.event_listener', ['event' => 'postLoad']);
        $listenerDef->setPublic(false);
        $container->setDefinition(FieldEncryptionListener::class, $listenerDef);

        // Register GenerateEncryptionKeyCommand
        $commandDef = new Definition(GenerateEncryptionKeyCommand::class);
        $commandDef->addTag('console.command');
        $commandDef->setPublic(false);
        $container->setDefinition(GenerateEncryptionKeyCommand::class, $commandDef);
    }

    public function getAlias(): string
    {
        return 'field_encryption';
    }
}
