<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\Database\DatabaseAuthSessionHousekeeper;
use Componenta\Auth\Session\Database\DatabaseAuthSessionManager;
use Componenta\Auth\Session\Database\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class HousekeeperConsistencyTest extends TestCase
{
    public function testNonUtcClockDoesNotDeleteLiveSessions(): void
    {
        $database = $this->database();
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $manager = $this->manager($database, $clock);
        $grant = $manager->create((new UuidFactory())->generate(), new AuthenticationEvidence(['password']), new AuthSessionPolicy(1800, 28800));
        $localClock = new FrozenClock('2030-01-01T03:00:00+03:00', '+03:00');
        self::assertSame(0, (new DatabaseAuthSessionHousekeeper($database, $localClock))->cleanup());
        self::assertNotNull($manager->resume($grant->credential));
        $clock->advance('+1800 seconds');
        self::assertSame(1, (new DatabaseAuthSessionHousekeeper($database, $clock))->cleanup());
    }

    public function testStaleReplicaCannotDeleteRenewedSession(): void
    {
        $primary = $this->database();
        $replica = $this->database();
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $manager = $this->manager($primary, $clock);
        $grant = $manager->create((new UuidFactory())->generate(), new AuthenticationEvidence(['password']), new AuthSessionPolicy(1800, 28800));
        foreach ($primary->select()->from('auth_sessions')->run()->fetchAll() as $row) {
            $replica->insert('auth_sessions')->values($row)->run();
        }
        $clock->advance('+1700 seconds');
        $manager->touch($grant->session);
        $clock->advance('+200 seconds');
        $split = new Database('split', '', $primary->getDriver(DatabaseInterface::WRITE), $replica->getDriver(DatabaseInterface::READ));
        self::assertSame(0, (new DatabaseAuthSessionHousekeeper($split, $clock))->cleanup());
        self::assertNotNull($manager->resume($grant->credential));
    }

    private function database(): DatabaseInterface
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        return SqliteDatabaseFixture::create();
    }

    private function manager(DatabaseInterface $database, FrozenClock $clock): DatabaseAuthSessionManager
    {
        return new DatabaseAuthSessionManager($database, new UuidFactory(), $clock, new CredentialKeyring('test', ['test' => str_repeat('k', 32)]));
    }
}
