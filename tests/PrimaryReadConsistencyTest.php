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
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class PrimaryReadConsistencyTest extends TestCase
{
    public function testRevokedSessionCannotResumeFromLaggingReplica(): void
    {
        [$primary, $replica, $split] = $this->databases();
        $issuer = $this->manager($primary);
        $grant = $issuer->create((new UuidFactory())->generate(), new AuthenticationEvidence(['password']), new AuthSessionPolicy(1800, 28800));
        $this->replicateSessions($primary, $replica);
        $issuer->revoke($grant->session->uuid, RevocationReason::Logout);

        $reader = $this->manager($split);
        self::assertNull($reader->resume($grant->credential));
        self::assertNull($reader->find($grant->session->uuid));
        self::assertFalse($reader->isGrantCurrent($grant));
        self::assertSame([], $reader->all($grant->session->subjectId));
    }

    public function testRotationInvalidatesPredecessorEvenWhileReplicaLags(): void
    {
        [$primary, $replica, $split] = $this->databases();
        $issuer = $this->manager($primary);
        $policy = new AuthSessionPolicy(1800, 28800);
        $grant = $issuer->create((new UuidFactory())->generate(), new AuthenticationEvidence(['password']), $policy);
        $this->replicateSessions($primary, $replica);
        $rotated = $issuer->rotate($grant->session, new AuthenticationEvidence(['totp']), RotationReason::Reauthentication, $policy);

        $reader = $this->manager($split);
        self::assertNull($reader->resume($grant->credential));
        self::assertNotNull($reader->resume($rotated->credential));
        self::assertTrue($reader->isGrantCurrent($rotated));
        self::assertFalse($reader->isGrantCurrent($grant));
    }

    public function testNewGrantCanBePublishedBeforeReplication(): void
    {
        [$primary, , $split] = $this->databases();
        $grant = $this->manager($primary)->create((new UuidFactory())->generate(), new AuthenticationEvidence(['password']), new AuthSessionPolicy(1800, 28800));
        self::assertTrue($this->manager($split)->isGrantCurrent($grant));
    }

    public function testSubjectSerializationRespectsDatabaseTablePrefix(): void
    {
        [$database] = $this->databases();
        $schema = file_get_contents(dirname(__DIR__) . '/resources/schema/sqlite.sql');
        self::assertIsString($schema);
        foreach (array_filter(array_map('trim', explode(';', str_replace('auth_', 'tenant_auth_', $schema)))) as $sql) {
            $database->execute($sql);
        }
        $manager = $this->manager($database->withPrefix('tenant_'));
        $grant = $manager->create((new UuidFactory())->generate(), new AuthenticationEvidence(['password']), new AuthSessionPolicy(1800, 28800));
        self::assertTrue($manager->isGrantCurrent($grant));
        $manager->revokeAll($grant->session->subjectId);
        self::assertNull($manager->resume($grant->credential));
    }

    /** @return array{DatabaseInterface, DatabaseInterface, DatabaseInterface} */
    private function databases(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $primary = SqliteDatabaseFixture::create();
        $replica = SqliteDatabaseFixture::create();
        return [$primary, $replica, new Database('split', '', $primary->getDriver(DatabaseInterface::WRITE), $replica->getDriver(DatabaseInterface::READ))];
    }

    private function manager(DatabaseInterface $database): DatabaseAuthSessionManager
    {
        return new DatabaseAuthSessionManager($database, new UuidFactory(), new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'), new CredentialKeyring('test', ['test' => str_repeat('k', 32)]));
    }

    private function replicateSessions(DatabaseInterface $primary, DatabaseInterface $replica): void
    {
        foreach ($primary->select()->from('auth_sessions')->run()->fetchAll() as $row) {
            $replica->insert('auth_sessions')->values($row)->run();
        }
    }
}
