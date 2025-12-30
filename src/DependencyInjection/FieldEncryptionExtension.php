<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\DependencyInjection;

use Caeligo\FieldEncryptionBundle\Command\EncryptExistingDataCommand;
use Caeligo\FieldEncryptionBundle\Command\GenerateEncryptionKeyCommand;
use Caeligo\FieldEncryptionBundle\Command\RotateEncryptionKeyCommand;
use Caeligo\FieldEncryptionBundle\EventListener\FieldEncryptionListener;
use Caeligo\FieldEncryptionBundle\Service\BinaryEncryptionService;
use Caeligo\FieldEncryptionBundle\Service\FieldEncryptionService;
use Caeligo\FieldEncryptionBundle\Service\FieldMappingResolver;
use Caeligo\FieldEncryptionBundle\Service\KeyRotationService;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
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

        // Store configuration as container parameters
        $container->setParameter('field_encryption.encryption_key', $config['encryption_key']);
        $container->setParameter('field_encryption.key_version', $config['key_version']);
        $container->setParameter('field_encryption.previous_keys', $config['previous_keys'] ?? []);
        $container->setParameter('field_encryption.file_encryption.max_size', $config['file_encryption']['max_size']);
        $container->setParameter('field_encryption.file_encryption.chunk_size', $config['file_encryption']['chunk_size']);
        $container->setParameter('field_encryption.file_encryption.compression', $config['file_encryption']['compression']);
        $container->setParameter('field_encryption.logging.enabled', $config['logging']['enabled']);
        $container->setParameter('field_encryption.logging.channel', $config['logging']['channel']);
        $container->setParameter('field_encryption.logging.level', $config['logging']['level']);

        // Register FieldEncryptionService (for string fields)
        $encryptionServiceDef = new Definition(FieldEncryptionService::class);
        $encryptionServiceDef->setArgument('$encryptionKey', '%field_encryption.encryption_key%');
        $encryptionServiceDef->setPublic(false);
        $container->setDefinition(FieldEncryptionService::class, $encryptionServiceDef);
        $container->setAlias('field_encryption.encryption_service', FieldEncryptionService::class);

        // Register BinaryEncryptionService (for file/blob fields)
        $binaryEncryptionServiceDef = new Definition(BinaryEncryptionService::class);
        $binaryEncryptionServiceDef->setArgument('$encryptionKey', '%field_encryption.encryption_key%');
        $binaryEncryptionServiceDef->setArgument('$keyVersion', '%field_encryption.key_version%');
        $binaryEncryptionServiceDef->setArgument('$previousKeys', '%field_encryption.previous_keys%');
        $binaryEncryptionServiceDef->setArgument('$defaultChunkSize', '%field_encryption.file_encryption.chunk_size%');
        $binaryEncryptionServiceDef->setArgument('$defaultMaxSize', '%field_encryption.file_encryption.max_size%');
        $binaryEncryptionServiceDef->setArgument('$defaultCompress', '%field_encryption.file_encryption.compression%');
        $binaryEncryptionServiceDef->setPublic(false);
        $container->setDefinition(BinaryEncryptionService::class, $binaryEncryptionServiceDef);
        $container->setAlias('field_encryption.binary_encryption_service', BinaryEncryptionService::class);

        // Register FieldMappingResolver
        $mappingResolverDef = new Definition(FieldMappingResolver::class);
        $mappingResolverDef->setArgument(0, $config['entities'] ?? []);
        $mappingResolverDef->setPublic(false);
        $container->setDefinition(FieldMappingResolver::class, $mappingResolverDef);
        $container->setAlias('field_encryption.mapping_resolver', FieldMappingResolver::class);

        // Configure logger
        $loggerRef = $config['logging']['enabled']
            ? new Reference(LoggerInterface::class)
            : new Reference('field_encryption.null_logger');

        // Register NullLogger as fallback
        $nullLoggerDef = new Definition(NullLogger::class);
        $nullLoggerDef->setPublic(false);
        $container->setDefinition('field_encryption.null_logger', $nullLoggerDef);

        // Register FieldEncryptionListener
        $listenerDef = new Definition(FieldEncryptionListener::class);
        $listenerDef->setArgument(0, new Reference(FieldEncryptionService::class));
        $listenerDef->setArgument(1, new Reference(FieldMappingResolver::class));
        $listenerDef->setArgument(2, new Reference(BinaryEncryptionService::class));
        $listenerDef->setArgument(3, $loggerRef);
        $listenerDef->addTag('doctrine.event_listener', ['event' => 'prePersist']);
        $listenerDef->addTag('doctrine.event_listener', ['event' => 'preUpdate']);
        $listenerDef->addTag('doctrine.event_listener', ['event' => 'postLoad']);
        $listenerDef->setPublic(false);
        $container->setDefinition(FieldEncryptionListener::class, $listenerDef);

        // Register KeyRotationService
        $keyRotationServiceDef = new Definition(KeyRotationService::class);
        $keyRotationServiceDef->setArgument(0, new Reference(FieldEncryptionService::class));
        $keyRotationServiceDef->setArgument(1, new Reference(BinaryEncryptionService::class));
        $keyRotationServiceDef->setArgument(2, new Reference(FieldMappingResolver::class));
        $keyRotationServiceDef->setArgument(3, $loggerRef);
        $keyRotationServiceDef->setPublic(false);
        $container->setDefinition(KeyRotationService::class, $keyRotationServiceDef);
        $container->setAlias('field_encryption.key_rotation_service', KeyRotationService::class);

        // Register GenerateEncryptionKeyCommand
        $generateKeyCommandDef = new Definition(GenerateEncryptionKeyCommand::class);
        $generateKeyCommandDef->addTag('console.command');
        $generateKeyCommandDef->setPublic(false);
        $container->setDefinition(GenerateEncryptionKeyCommand::class, $generateKeyCommandDef);

        // Register RotateEncryptionKeyCommand
        $rotateKeyCommandDef = new Definition(RotateEncryptionKeyCommand::class);
        $rotateKeyCommandDef->setArgument(0, new Reference(KeyRotationService::class));
        $rotateKeyCommandDef->setArgument(1, new Reference('doctrine.orm.entity_manager'));
        $rotateKeyCommandDef->addTag('console.command');
        $rotateKeyCommandDef->setPublic(false);
        $container->setDefinition(RotateEncryptionKeyCommand::class, $rotateKeyCommandDef);

        // Register EncryptExistingDataCommand
        $encryptExistingCommandDef = new Definition(EncryptExistingDataCommand::class);
        $encryptExistingCommandDef->setArgument(0, new Reference(KeyRotationService::class));
        $encryptExistingCommandDef->setArgument(1, new Reference('doctrine.orm.entity_manager'));
        $encryptExistingCommandDef->addTag('console.command');
        $encryptExistingCommandDef->setPublic(false);
        $container->setDefinition(EncryptExistingDataCommand::class, $encryptExistingCommandDef);
    }

    public function getAlias(): string
    {
        return 'field_encryption';
    }
}
