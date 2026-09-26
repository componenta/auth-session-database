<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\Database\DatabaseAuthSessionManager;
use Componenta\Auth\Session\Database\DatabasePreAuthenticationManager;
use Componenta\Auth\Session\Database\Tests\Support\MySqlDatabaseFixture;
use Componenta\Auth\Session\Database\Tests\Support\PostgresDatabaseFixture;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\RotationReason;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class VendorDatabaseIntegrationTest extends TestCase
{
    #[DataProvider('databases')]
    public function testAuthenticationSessionLifecycle(
        string $driver,
    ): void {
        $database = self::database($driver);
        self::reset($database, $driver);
        self::schema($database, $driver);

        $manager = new DatabaseAuthSessionManager(
            $database,
            new UuidFactory(),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            self::keyring(),
        );
        $subject = (new UuidFactory())->generate();
        $policy = new AuthSessionPolicy(1800, 28800);
        $grant = $manager->create(
            $subject,
            new AuthenticationEvidence(['otp.email']),
            $policy,
        );

        self::assertNotNull($manager->resume($grant->credential));

        $oldCredential = $grant->credential;
        $rotated = $manager->rotate(
            $grant->session,
            new AuthenticationEvidence(
                ['webauthn'],
                ['user_verified', 'phishing_resistant'],
            ),
            RotationReason::Reauthentication,
            $policy,
        );

        self::assertTrue(
            $rotated->session->uuid->equals($grant->session->uuid),
        );
        self::assertNull($manager->resume($oldCredential));
        self::assertNotNull($manager->resume($rotated->credential));

        $manager->revokePresentedCredential(
            $oldCredential,
            RevocationReason::Logout,
        );

        self::assertNull($manager->resume($rotated->credential));
    }

    #[DataProvider('databases')]
    public function testPreAuthenticationIsOneTime(
        string $driver,
    ): void {
        $database = self::database($driver);
        self::reset($database, $driver);
        self::schema($database, $driver);

        $manager = new DatabasePreAuthenticationManager(
            $database,
            new UuidFactory(),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            self::keyring(),
        );
        $grant = $manager->create();

        self::assertNotNull($manager->consume(
            $grant->credential,
            $grant->requestToken,
        ));
        self::assertNull($manager->consume(
            $grant->credential,
            $grant->requestToken,
        ));
    }

    /** @return iterable<string, array{string}> */
    public static function databases(): iterable
    {
        yield 'mysql-8.4' => ['mysql'];
        yield 'postgresql' => ['pgsql'];
    }

    private static function database(string $driver): DatabaseInterface
    {
        if ($driver === 'mysql') {
            if (!MySqlDatabaseFixture::available()) {
                self::markTestSkipped('MySQL test service is unavailable.');
            }

            return MySqlDatabaseFixture::create();
        }

        if (!PostgresDatabaseFixture::available()) {
            self::markTestSkipped('PostgreSQL test service is unavailable.');
        }

        return PostgresDatabaseFixture::create();
    }

    private static function schema(
        DatabaseInterface $database,
        string $driver,
    ): void {
        $file = $driver === 'mysql'
            ? 'mysql-8.4.sql'
            : 'postgresql.sql';
        $sql = file_get_contents(
            dirname(__DIR__) . '/resources/schema/' . $file,
        );

        if (!is_string($sql)) {
            throw new \RuntimeException('Database schema is unavailable.');
        }

        foreach (array_filter(array_map('trim', explode(';', $sql))) as $query) {
            $database->execute($query);
        }
    }

    private static function reset(
        DatabaseInterface $database,
        string $driver,
    ): void {
        $tables = [
            'auth_pre_authentication_transactions',
            'auth_session_credential_tombstones',
            'auth_sessions',
            'auth_session_subject_locks',
        ];

        if ($driver === 'mysql') {
            $database->execute('SET FOREIGN_KEY_CHECKS = 0');

            foreach ($tables as $table) {
                $database->execute('DROP TABLE IF EXISTS ' . $table);
            }

            $database->execute('SET FOREIGN_KEY_CHECKS = 1');

            return;
        }

        foreach ($tables as $table) {
            $database->execute(
                'DROP TABLE IF EXISTS ' . $table . ' CASCADE',
            );
        }
    }

    private static function keyring(): CredentialKeyring
    {
        return new CredentialKeyring(
            'k1',
            ['k1' => str_repeat('k', 32)],
        );
    }
}
