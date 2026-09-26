<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\Database\DatabaseAuthSessionManager;
use Componenta\Auth\Session\Database\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\RotationReason;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use PHPUnit\Framework\TestCase;

final class DatabaseAuthSessionManagerTest extends TestCase
{
    public function testRawCredentialIsNeverPersistedAndCanResume(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = self::manager($database);
        $grant = $manager->create(
            (new UuidFactory())->generate(),
            new AuthenticationEvidence(['otp.email']),
            new AuthSessionPolicy(1800, 28800),
            ['device' => 'Browser'],
        );
        $row = $database->select()
            ->from('auth_sessions')
            ->where('uuid', $grant->session->uuid->toString())
            ->run()
            ->fetch();

        self::assertIsArray($row);
        self::assertNotSame(
            $grant->credential->toString(),
            $row['credential_hash'] ?? null,
        );
        self::assertSame(64, strlen((string) ($row['credential_hash'] ?? '')));

        $resumed = $manager->resume($grant->credential);
        self::assertNotNull($resumed);
        self::assertTrue($resumed->uuid->equals($grant->session->uuid));
    }

    public function testRotationKeepsStableUuidAndTombstoneCanRevokeSuccessor(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = self::manager($database);
        $grant = $manager->create(
            (new UuidFactory())->generate(),
            new AuthenticationEvidence(['otp.email']),
            new AuthSessionPolicy(1800, 28800),
        );
        $oldCredential = $grant->credential;
        $rotated = $manager->rotate(
            $grant->session,
            new AuthenticationEvidence(['webauthn'], ['user_verified']),
            RotationReason::Reauthentication,
        );

        self::assertTrue($rotated->session->uuid->equals($grant->session->uuid));
        self::assertSame(2, $rotated->session->credentialGeneration);
        self::assertSame(
            ['otp.email', 'webauthn'],
            $rotated->session->evidence->methods,
        );
        self::assertSame(
            ['webauthn'],
            $rotated->session->reauthenticationEvidence?->methods,
        );
        self::assertNull($manager->resume($oldCredential));
        self::assertNotNull($manager->resume($rotated->credential));

        $manager->revokePresentedCredential(
            $oldCredential,
            RevocationReason::Logout,
        );

        self::assertNull($manager->resume($rotated->credential));
    }

    public function testReauthenticationResetsIdleAndOverallTimeouts(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $manager = new DatabaseAuthSessionManager(
            $database,
            new UuidFactory(),
            $clock,
            new CredentialKeyring(
                'k1',
                ['k1' => str_repeat('k', 32)],
            ),
        );
        $policy = new AuthSessionPolicy(1800, 28800);
        $grant = $manager->create(
            (new UuidFactory())->generate(),
            new AuthenticationEvidence(['password'], ['knowledge']),
            $policy,
        );

        $clock->advance('+10 minutes');

        $rotated = $manager->rotate(
            $grant->session,
            new AuthenticationEvidence(
                ['webauthn'],
                ['phishing_resistant', 'user_verified'],
            ),
            RotationReason::Reauthentication,
            $policy,
        );

        self::assertSame(
            '2030-01-01T00:40:00+00:00',
            $rotated->session->idleExpiresAt->format(DATE_ATOM),
        );
        self::assertSame(
            '2030-01-01T08:10:00+00:00',
            $rotated->session->absoluteExpiresAt->format(DATE_ATOM),
        );

        $clock->advance('+10 minutes');

        $rotatedAgain = $manager->rotate(
            $rotated->session,
            new AuthenticationEvidence(['totp'], ['possession']),
            RotationReason::Reauthentication,
            $policy,
        );

        self::assertSame(
            '2030-01-01T08:20:00+00:00',
            $rotatedAgain->session->absoluteExpiresAt->format(DATE_ATOM),
        );
    }

    public function testBulkRevocationPersistsExplicitReason(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = self::manager($database);
        $subject = (new UuidFactory())->generate();

        $manager->create(
            $subject,
            new AuthenticationEvidence(['session']),
            new AuthSessionPolicy(1800, 28800),
        );
        $manager->create(
            $subject,
            new AuthenticationEvidence(['session']),
            new AuthSessionPolicy(1800, 28800),
        );

        $manager->revokeAll(
            $subject,
            reason: RevocationReason::AccountDisabled,
        );

        $rows = $database->select('revocation_reason')
            ->from('auth_sessions')
            ->where('subject_uuid', $subject->toString())
            ->run()
            ->fetchAll();

        self::assertCount(2, $rows);
        foreach ($rows as $row) {
            self::assertIsArray($row);
            self::assertSame(
                RevocationReason::AccountDisabled->value,
                $row['revocation_reason'] ?? null,
            );
        }
    }

    public function testRegistryUsesPublicUuidWithoutExposingCredential(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = self::manager($database);
        $subject = (new UuidFactory())->generate();
        $grant = $manager->create(
            $subject,
            new AuthenticationEvidence(['session']),
            new AuthSessionPolicy(1800, 28800),
        );

        $sessions = $manager->all($subject);

        self::assertCount(1, $sessions);
        self::assertTrue($sessions[0]->uuid->equals($grant->session->uuid));
        self::assertObjectNotHasProperty('credential', $sessions[0]);
    }

    private static function manager(
        \Cycle\Database\DatabaseInterface $database,
    ): DatabaseAuthSessionManager {
        return new DatabaseAuthSessionManager(
            $database,
            new UuidFactory(),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            new CredentialKeyring('k1', ['k1' => str_repeat('k', 32)]),
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
