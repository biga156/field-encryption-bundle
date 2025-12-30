<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Exception;

use LogicException;

/**
 * Exception thrown when a configured property does not exist on an entity.
 *
 * This is a LogicException because it indicates a configuration error
 * that should be fixed during development, not at runtime.
 *
 * @author Bíró Gábor (biga156)
 */
class PropertyNotFoundException extends LogicException
{
    private string $propertyName;
    private string $entityClass;

    public function __construct(string $propertyName, string $entityClass)
    {
        $this->propertyName = $propertyName;
        $this->entityClass = $entityClass;

        parent::__construct(sprintf(
            'Property "%s" does not exist on entity "%s". ' .
            'Please check your #[EncryptedFile] or #[Encrypted] attribute configuration.',
            $propertyName,
            $entityClass
        ));
    }

    public function getPropertyName(): string
    {
        return $this->propertyName;
    }

    public function getEntityClass(): string
    {
        return $this->entityClass;
    }

    /**
     * Create an exception for a missing metadata property.
     */
    public static function metadataProperty(string $propertyName, string $entityClass, string $attributeParam): self
    {
        $exception = new self($propertyName, $entityClass);
        $exception->message = sprintf(
            'Metadata property "%s" (configured via "%s") does not exist on entity "%s". ' .
            'Either create the property or remove the configuration from the #[EncryptedFile] attribute.',
            $propertyName,
            $attributeParam,
            $entityClass
        );

        return $exception;
    }
}
