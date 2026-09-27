<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Database\Tests;

use Componenta\Auth\Session\Database\CredentialKeyring;
use Componenta\Auth\Session\Database\DatabasePreAuthenticationManager;
use Componenta\Auth\Session\Database\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class PreAuthenticationPrimaryReadTest extends TestCase
{
    public function testFreshPreAuthenticationCanBeVerifiedAndConsumedBeforeReplication(): void
    {
        [$primary, , $split] = $this->databases();
        $grant = $this->manager($primary)->create();
        $manager = $this->manager($split);
        self::assertNotNull($manager->verify($grant->credential, $grant->requestToken));
        self::assertNotNull($manager->consume($grant->credential, $grant->requestToken));
        self::assertNull($manager->consume($grant->credential, $grant->requestToken));
    }

    public function testConsumedPreAuthenticationCannotBeReverifiedFromAStaleReplica(): void
    {
        [$primary, $replica, $split] = $this->databases();
        $writer = $this->manager($primary);
        $grant = $writer->create();
        foreach ($primary->select()->from('auth_pre_authentication_transactions')->run()->fetchAll() as $row) {
            $replica->insert('auth_pre_authentication_transactions')->values($row)->run();
        }
        self::assertNotNull($writer->consume($grant->credential, $grant->requestToken));
        self::assertNull($this->manager($split)->verify($grant->credential, $grant->requestToken));
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

    private function manager(DatabaseInterface $database): DatabasePreAuthenticationManager
    {
        return new DatabasePreAuthenticationManager($database, new UuidFactory(), new FrozenClock('2030-01-01T00:00:00Z', 'UTC'), new CredentialKeyring('test', ['test' => str_repeat('k', 32)]));
    }
}
