<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Tests\Unit\Model;

use Caeligo\FieldEncryptionBundle\Model\EncryptedFileData;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for EncryptedFileData DTO.
 */
class EncryptedFileDataTest extends TestCase
{
    public function testConstructorWithAllParameters(): void
    {
        $content = 'test content';
        $mimeType = 'text/plain';
        $originalName = 'test.txt';
        $size = 12;

        $fileData = new EncryptedFileData($content, $mimeType, $originalName, $size);

        $this->assertEquals($content, $fileData->getContent());
        $this->assertEquals($mimeType, $fileData->getMimeType());
        $this->assertEquals($originalName, $fileData->getOriginalName());
        $this->assertEquals($size, $fileData->getSize());
    }

    public function testConstructorAutoCalculatesSize(): void
    {
        $content = 'test content'; // 12 bytes

        $fileData = new EncryptedFileData($content);

        $this->assertEquals(12, $fileData->getSize());
    }

    public function testConstructorWithBinaryContent(): void
    {
        $content = random_bytes(1024);

        $fileData = new EncryptedFileData($content, 'application/octet-stream');

        $this->assertEquals($content, $fileData->getContent());
        $this->assertEquals(1024, $fileData->getSize());
    }

    public function testToBase64(): void
    {
        $content = 'Hello, World!';
        $fileData = new EncryptedFileData($content);

        $base64 = $fileData->toBase64();

        $this->assertEquals(base64_encode($content), $base64);
        $this->assertEquals($content, base64_decode($base64));
    }

    public function testToDataUri(): void
    {
        $content = 'Test content';
        $mimeType = 'text/plain';
        $fileData = new EncryptedFileData($content, $mimeType);

        $dataUri = $fileData->toDataUri();

        $this->assertStringStartsWith('data:text/plain;base64,', $dataUri);
        $this->assertEquals('data:text/plain;base64,' . base64_encode($content), $dataUri);
    }

    public function testToDataUriWithFallbackMimeType(): void
    {
        $content = 'Test content';
        $fileData = new EncryptedFileData($content); // No MIME type

        $dataUri = $fileData->toDataUri();

        $this->assertStringStartsWith('data:application/octet-stream;base64,', $dataUri);
    }

    public function testFromBase64(): void
    {
        $content = 'Hello, World!';
        $base64 = base64_encode($content);

        $fileData = EncryptedFileData::fromBase64($base64, 'text/plain', 'hello.txt');

        $this->assertEquals($content, $fileData->getContent());
        $this->assertEquals('text/plain', $fileData->getMimeType());
        $this->assertEquals('hello.txt', $fileData->getOriginalName());
    }

    public function testFromBase64WithInvalidDataThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        EncryptedFileData::fromBase64('not-valid-base64!!!');
    }

    public function testFromDataUri(): void
    {
        $content = 'Test content';
        $dataUri = 'data:text/plain;base64,' . base64_encode($content);

        $fileData = EncryptedFileData::fromDataUri($dataUri, 'test.txt');

        $this->assertEquals($content, $fileData->getContent());
        $this->assertEquals('text/plain', $fileData->getMimeType());
        $this->assertEquals('test.txt', $fileData->getOriginalName());
    }

    public function testFromDataUriWithInvalidFormatThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        EncryptedFileData::fromDataUri('not-a-data-uri');
    }

    public function testGetExtension(): void
    {
        $testCases = [
            'application/pdf' => 'pdf',
            'image/jpeg' => 'jpg',
            'image/png' => 'png',
            'text/plain' => 'txt',
            'application/json' => 'json',
            'unknown/type' => null,
        ];

        foreach ($testCases as $mimeType => $expectedExtension) {
            $fileData = new EncryptedFileData('content', $mimeType);
            $this->assertEquals($expectedExtension, $fileData->getExtension(), "Failed for MIME type: $mimeType");
        }
    }

    public function testGetExtensionWithNoMimeType(): void
    {
        $fileData = new EncryptedFileData('content');

        $this->assertNull($fileData->getExtension());
    }

    public function testIsImage(): void
    {
        $imageTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        $nonImageTypes = ['text/plain', 'application/pdf', 'video/mp4'];

        foreach ($imageTypes as $mimeType) {
            $fileData = new EncryptedFileData('content', $mimeType);
            $this->assertTrue($fileData->isImage(), "Should be image: $mimeType");
        }

        foreach ($nonImageTypes as $mimeType) {
            $fileData = new EncryptedFileData('content', $mimeType);
            $this->assertFalse($fileData->isImage(), "Should not be image: $mimeType");
        }
    }

    public function testIsImageWithNoMimeType(): void
    {
        $fileData = new EncryptedFileData('content');

        $this->assertFalse($fileData->isImage());
    }

    public function testGetHash(): void
    {
        $content = 'test content';
        $fileData = new EncryptedFileData($content);

        $hash = $fileData->getHash();

        $this->assertEquals(64, strlen($hash)); // SHA-256 produces 64 hex chars
        $this->assertEquals(hash('sha256', $content), $hash);
    }

    public function testGetHashWithDifferentAlgorithm(): void
    {
        $content = 'test content';
        $fileData = new EncryptedFileData($content);

        $md5Hash = $fileData->getHash('md5');

        $this->assertEquals(32, strlen($md5Hash)); // MD5 produces 32 hex chars
        $this->assertEquals(hash('md5', $content), $md5Hash);
    }

    public function testWithMetadata(): void
    {
        $fileData = new EncryptedFileData('content', 'text/plain', 'original.txt');

        $newFileData = $fileData->withMetadata('application/pdf', 'new.pdf');

        $this->assertEquals('content', $newFileData->getContent());
        $this->assertEquals('application/pdf', $newFileData->getMimeType());
        $this->assertEquals('new.pdf', $newFileData->getOriginalName());

        // Original should be unchanged
        $this->assertEquals('text/plain', $fileData->getMimeType());
        $this->assertEquals('original.txt', $fileData->getOriginalName());
    }

    public function testWithMetadataPreservesOriginalWhenNull(): void
    {
        $fileData = new EncryptedFileData('content', 'text/plain', 'original.txt');

        $newFileData = $fileData->withMetadata(null, null);

        $this->assertEquals('text/plain', $newFileData->getMimeType());
        $this->assertEquals('original.txt', $newFileData->getOriginalName());
    }

    public function testGetFormattedSize(): void
    {
        $testCases = [
            100 => '100.00 B',
            1024 => '1.00 KB',
            1536 => '1.50 KB',
            1048576 => '1.00 MB',
            1073741824 => '1.00 GB',
        ];

        foreach ($testCases as $size => $expected) {
            $fileData = new EncryptedFileData('', null, null, $size);
            $this->assertEquals($expected, $fileData->getFormattedSize(), "Failed for size: $size");
        }
    }

    public function testSaveTo(): void
    {
        $content = 'Test file content';
        $fileData = new EncryptedFileData($content);

        $tempFile = sys_get_temp_dir() . '/test_' . uniqid() . '.txt';

        try {
            $bytesWritten = $fileData->saveTo($tempFile);

            $this->assertEquals(strlen($content), $bytesWritten);
            $this->assertFileExists($tempFile);
            $this->assertEquals($content, file_get_contents($tempFile));
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    public function testSaveToCreatesDirectory(): void
    {
        $content = 'Test file content';
        $fileData = new EncryptedFileData($content);

        $tempDir = sys_get_temp_dir() . '/test_dir_' . uniqid();
        $tempFile = $tempDir . '/nested/file.txt';

        try {
            $fileData->saveTo($tempFile);

            $this->assertFileExists($tempFile);
            $this->assertEquals($content, file_get_contents($tempFile));
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
            if (is_dir($tempDir . '/nested')) {
                rmdir($tempDir . '/nested');
            }
            if (is_dir($tempDir)) {
                rmdir($tempDir);
            }
        }
    }

    public function testFromPathCreatesValidInstance(): void
    {
        $content = 'Test file content for path test';
        $tempFile = sys_get_temp_dir() . '/test_' . uniqid() . '.txt';

        try {
            file_put_contents($tempFile, $content);

            $fileData = EncryptedFileData::fromPath($tempFile);

            $this->assertEquals($content, $fileData->getContent());
            $this->assertEquals(basename($tempFile), $fileData->getOriginalName());
            $this->assertEquals(strlen($content), $fileData->getSize());
            $this->assertEquals('text/plain', $fileData->getMimeType());
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    public function testFromPathWithNonexistentFileThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);

        EncryptedFileData::fromPath('/nonexistent/file.txt');
    }
}
