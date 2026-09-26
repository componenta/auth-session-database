<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use PHPUnit\Framework\TestCase;

final class ArchitectureTest extends TestCase
{
    public function testPersistencePackageDoesNotOwnHttpOrLegacySessions(): void
    {
        $composer = json_decode(
            file_get_contents(dirname(__DIR__) . '/composer.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        self::assertIsArray($composer);
        $requires = $composer['require'] ?? [];

        foreach ([
            'componenta/auth-http',
            'componenta/auth-session-http',
            'componenta/session',
            'psr/http-message',
        ] as $forbidden) {
            self::assertArrayNotHasKey($forbidden, $requires);
        }
    }

    public function testSchemaStoresHashesButNoRawBearerColumns(): void
    {
        $schema = file_get_contents(
            dirname(__DIR__) . '/resources/schema/sqlite.sql',
        );

        self::assertIsString($schema);
        self::assertStringContainsString('credential_hash', $schema);
        self::assertStringContainsString('request_token_hash', $schema);
        self::assertDoesNotMatchRegularExpression(
            '/\bcredential\s+(?:TEXT|VARCHAR|CHAR)/i',
            $schema,
        );
        self::assertDoesNotMatchRegularExpression(
            '/\brequest_token\s+(?:TEXT|VARCHAR|CHAR)/i',
            $schema,
        );
    }
}
