<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\Database\DatabasePreAuthenticationManager;
use Componenta\Auth\Session\Database\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use PHPUnit\Framework\TestCase;

final class DatabasePreAuthenticationManagerTest extends TestCase
{
    public function testVerifyDoesNotConsumeButConsumeIsSingleWinner(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = new DatabasePreAuthenticationManager(
            $database,
            new UuidFactory(),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            new CredentialKeyring('k1', ['k1' => str_repeat('k', 32)]),
        );
        $grant = $manager->create();

        self::assertNotNull($manager->verify(
            $grant->credential,
            $grant->requestToken,
        ));
        self::assertSame(
            1,
            $database->select()
                ->from('auth_pre_authentication_transactions')
                ->count(),
        );

        self::assertNotNull($manager->consume(
            $grant->credential,
            $grant->requestToken,
        ));
        self::assertNull($manager->consume(
            $grant->credential,
            $grant->requestToken,
        ));
        self::assertNull($manager->verify(
            $grant->credential,
            $grant->requestToken,
        ));
    }

    public function testMismatchedRequestTokenDoesNotConsumeTransaction(): void
    {
        self::requireSqlite();
        $manager = new DatabasePreAuthenticationManager(
            SqliteDatabaseFixture::create(),
            new UuidFactory(),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            new CredentialKeyring('k1', ['k1' => str_repeat('k', 32)]),
        );
        $grant = $manager->create();
        $other = $manager->create();

        self::assertNull($manager->verify(
            $grant->credential,
            $other->requestToken,
        ));
        self::assertNotNull($manager->verify(
            $grant->credential,
            $grant->requestToken,
        ));
        self::assertNotNull($manager->consume(
            $grant->credential,
            $grant->requestToken,
        ));
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
